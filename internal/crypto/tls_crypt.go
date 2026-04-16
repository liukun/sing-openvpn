package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"sync"
	"time"
)

type TLSCrypt struct {
	encBlock   cipher.Block
	decBlock   cipher.Block
	encHMACKey []byte
	decHMACKey []byte
	sequence   uint32
	mutex      sync.Mutex
	macPoolEnc sync.Pool
	macPoolDec sync.Pool
}

func NewTLSCrypt(keyData string) (*TLSCrypt, error) {
	data, err := ParseStaticKey(keyData)
	if err != nil {
		return nil, err
	}

	encBlock, err := aes.NewCipher(data[128:160])
	if err != nil {
		return nil, err
	}
	decBlock, err := aes.NewCipher(data[0:32])
	if err != nil {
		return nil, err
	}

	encHMACKey := data[192:224]
	decHMACKey := data[64:96]

	return &TLSCrypt{
		encBlock:   encBlock,
		decBlock:   decBlock,
		encHMACKey: encHMACKey,
		decHMACKey: decHMACKey,
		macPoolEnc: sync.Pool{New: func() any { return hmac.New(sha256.New, encHMACKey) }},
		macPoolDec: sync.Pool{New: func() any { return hmac.New(sha256.New, decHMACKey) }},
	}, nil
}

func (tc *TLSCrypt) Wrap(data []byte) ([]byte, error) {
	if len(data) < 9 {
		return nil, errors.New("packet too short to wrap")
	}

	clearHeader := data[0:9]
	plaintextPayload := data[9:]

	tc.mutex.Lock()
	tc.sequence++
	seq := tc.sequence
	tc.mutex.Unlock()

	var pidBuf [8]byte
	binary.BigEndian.PutUint32(pidBuf[0:4], seq)
	binary.BigEndian.PutUint32(pidBuf[4:8], uint32(time.Now().Unix()))

	h := tc.macPoolEnc.Get().(hash.Hash)
	h.Reset()
	h.Write(clearHeader)
	h.Write(pidBuf[:])
	h.Write(plaintextPayload)
	authTag := h.Sum(nil)
	tc.macPoolEnc.Put(h)

	iv := authTag[0:16]

	ciphertext := make([]byte, len(plaintextPayload))
	stream := cipher.NewCTR(tc.encBlock, iv)
	stream.XORKeyStream(ciphertext, plaintextPayload)

	result := make([]byte, 0, 9+8+32+len(ciphertext))
	result = append(result, clearHeader...)
	result = append(result, pidBuf[:]...)
	result = append(result, authTag...)
	result = append(result, ciphertext...)

	return result, nil
}

func (tc *TLSCrypt) Unwrap(data []byte) ([]byte, error) {
	minLen := 9 + 8 + 32
	if len(data) < minLen {
		return nil, errors.New("tls-crypt data too short")
	}

	clearHeader := data[0:9]
	pidBuf := data[9:17]
	authTag := data[17:49]
	ciphertext := data[49:]

	iv := authTag[0:16]

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(tc.decBlock, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	h := tc.macPoolDec.Get().(hash.Hash)
	h.Reset()
	h.Write(clearHeader)
	h.Write(pidBuf)
	h.Write(plaintext)
	expectedTag := h.Sum(nil)
	tc.macPoolDec.Put(h)

	if !hmac.Equal(authTag, expectedTag) {
		return nil, errors.New("tls-crypt HMAC verification failed")
	}

	result := make([]byte, 9+len(plaintext))
	copy(result[0:9], clearHeader)
	copy(result[9:], plaintext)

	return result, nil
}

// Overhead returns the number of extra bytes added by tls-crypt wrapping.
func (tc *TLSCrypt) Overhead() int {
	return 8 + 32 // pid(4) + timestamp(4) + auth_tag(32) = 40
}
