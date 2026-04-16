package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"strings"
	"sync"
	"time"
)

// TLSAuth implements tls-auth (HMAC-only authentication for control channel).
//
// Wire format (after wrapping):
//
//	[opcode+keyid: 1B][session_id: 8B][HMAC: N bytes][packet_id: 4B][timestamp: 4B][rest of packet...]
//
// HMAC is computed over (in this order):
//
//	packet_id(4) + timestamp(4) + opcode+keyid(1) + session_id(8) + rest_of_packet(...)
type TLSAuth struct {
	hmacSize   int
	encHMACKey []byte
	decHMACKey []byte
	sequence   uint32
	mutex      sync.Mutex
	macPoolEnc sync.Pool
	macPoolDec sync.Pool
}

// NewTLSAuth creates a TLSAuth from an OpenVPN Static key V1, key-direction, and auth algorithm.
//
// auth: "SHA1" (default), "SHA256", or "SHA512".
// keyDirection: 1 or 0 for directional, -1 for bidirectional.
func NewTLSAuth(keyData string, keyDirection int, auth string) (*TLSAuth, error) {
	data, err := ParseStaticKey(keyData)
	if err != nil {
		return nil, err
	}

	// Determine hash function and key/digest size.
	// OpenVPN uses md_kt_size(digest) bytes from each 64-byte HMAC key slot.
	var newHash func() hash.Hash
	var digestSize int
	switch strings.ToUpper(auth) {
	case "SHA256":
		newHash = sha256.New
		digestSize = sha256.Size // 32
	case "SHA512":
		newHash = sha512.New
		digestSize = sha512.Size // 64
	default: // "SHA1" or empty
		newHash = sha1.New
		digestSize = sha1.Size // 20
	}

	// Extract HMAC keys: first digestSize bytes from each 64-byte key slot.
	// key[0].hmac = data[64:128], key[1].hmac = data[192:256]
	var encHMACKey, decHMACKey []byte
	switch keyDirection {
	case 1:
		encHMACKey = make([]byte, digestSize)
		decHMACKey = make([]byte, digestSize)
		copy(encHMACKey, data[192:192+digestSize])
		copy(decHMACKey, data[64:64+digestSize])
	case 0:
		encHMACKey = make([]byte, digestSize)
		decHMACKey = make([]byte, digestSize)
		copy(encHMACKey, data[64:64+digestSize])
		copy(decHMACKey, data[192:192+digestSize])
	default:
		// Bidirectional: same key for both directions
		encHMACKey = make([]byte, digestSize)
		copy(encHMACKey, data[64:64+digestSize])
		decHMACKey = encHMACKey
	}

	return &TLSAuth{
		hmacSize:   digestSize,
		encHMACKey: encHMACKey,
		decHMACKey: decHMACKey,
		macPoolEnc: sync.Pool{New: func() any { return hmac.New(newHash, encHMACKey) }},
		macPoolDec: sync.Pool{New: func() any { return hmac.New(newHash, decHMACKey) }},
	}, nil
}

// Wrap adds tls-auth HMAC + replay protection to a control packet.
func (ta *TLSAuth) Wrap(data []byte) ([]byte, error) {
	if len(data) < 9 {
		return nil, errors.New("packet too short to wrap")
	}

	clearHeader := data[0:9] // opcode + session_id
	restOfPacket := data[9:] // ack_count + acks + packet_id + payload

	ta.mutex.Lock()
	ta.sequence++
	seq := ta.sequence
	ta.mutex.Unlock()

	// Build replay protection fields: packet_id(4) + timestamp(4)
	var pidBuf [8]byte
	binary.BigEndian.PutUint32(pidBuf[0:4], seq)
	binary.BigEndian.PutUint32(pidBuf[4:8], uint32(time.Now().Unix()))

	// HMAC over: pid(4) + timestamp(4) + opcode+keyid(1) + session_id(8) + rest
	h := ta.macPoolEnc.Get().(hash.Hash)
	h.Reset()
	h.Write(pidBuf[:])
	h.Write(clearHeader)
	h.Write(restOfPacket)
	authTag := h.Sum(nil)
	ta.macPoolEnc.Put(h)

	// Wire: clearHeader(9) + HMAC(N) + pid(4) + timestamp(4) + rest(...)
	result := make([]byte, 0, 9+ta.hmacSize+8+len(restOfPacket))
	result = append(result, clearHeader...)
	result = append(result, authTag...)
	result = append(result, pidBuf[:]...)
	result = append(result, restOfPacket...)

	return result, nil
}

// Unwrap verifies and strips tls-auth HMAC + replay protection from a control packet.
func (ta *TLSAuth) Unwrap(data []byte) ([]byte, error) {
	minLen := 9 + ta.hmacSize + 8
	if len(data) < minLen {
		return nil, errors.New("tls-auth data too short")
	}

	clearHeader := data[0:9]
	authTag := data[9 : 9+ta.hmacSize]
	pidBuf := data[9+ta.hmacSize : 9+ta.hmacSize+8]
	restOfPacket := data[9+ta.hmacSize+8:]

	h := ta.macPoolDec.Get().(hash.Hash)
	h.Reset()
	h.Write(pidBuf)
	h.Write(clearHeader)
	h.Write(restOfPacket)
	expectedTag := h.Sum(nil)
	ta.macPoolDec.Put(h)

	if !hmac.Equal(authTag, expectedTag) {
		return nil, errors.New("tls-auth HMAC verification failed")
	}

	result := make([]byte, 9+len(restOfPacket))
	copy(result[0:9], clearHeader)
	copy(result[9:], restOfPacket)

	return result, nil
}

// Overhead returns the number of extra bytes added by tls-auth wrapping.
func (ta *TLSAuth) Overhead() int {
	return ta.hmacSize + 8 // HMAC(N) + pid(4) + timestamp(4)
}
