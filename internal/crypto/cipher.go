package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"sync"

	"github.com/airofm/sing-openvpn/internal/log"
)

type DataCipher interface {
	// ad is the AEAD additional data prefix (opcode+peer-id header for DATA_V2).
	// GCM appends the packet_id to form the full AAD. CBC ignores it.
	Encrypt(plaintext []byte, ad []byte) ([]byte, error)
	Decrypt(ciphertext []byte, ad []byte) ([]byte, error)
}

type CBCCipher struct {
	encBlock     cipher.Block
	decBlock     cipher.Block
	encHMACKey   []byte
	decHMACKey   []byte
	txPacketID   uint32
	macPoolEnc   sync.Pool
	macPoolDec   sync.Pool
	mutex        sync.Mutex
	replayWindow *ReplayWindow
}

func NewCBCCipher(encKey, decKey, encHMACKey, decHMACKey []byte) (*CBCCipher, error) {
	encBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	decBlock, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, err
	}
	return &CBCCipher{
		encBlock:     encBlock,
		decBlock:     decBlock,
		encHMACKey:   encHMACKey,
		decHMACKey:   decHMACKey,
		macPoolEnc:   sync.Pool{New: func() any { return hmac.New(sha1.New, encHMACKey) }},
		macPoolDec:   sync.Pool{New: func() any { return hmac.New(sha1.New, decHMACKey) }},
		replayWindow: NewReplayWindow(64),
	}, nil
}

func (c *CBCCipher) Encrypt(plaintext []byte, _ []byte) ([]byte, error) {
	c.mutex.Lock()
	pid := c.txPacketID
	c.txPacketID++
	c.mutex.Unlock()

	bs := c.encBlock.BlockSize()
	padding := bs - (4+len(plaintext))%bs
	paddedLen := 4 + len(plaintext) + padding

	// Single allocation for MAC(20) + IV(bs) + Ciphertext(paddedLen)
	result := make([]byte, 20+bs+paddedLen)
	mac := result[0:20]
	iv := result[20 : 20+bs]
	ciphertext := result[20+bs:]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	binary.BigEndian.PutUint32(ciphertext[0:4], pid)
	copy(ciphertext[4:], plaintext)
	for i := 4 + len(plaintext); i < paddedLen; i++ {
		ciphertext[i] = byte(padding)
	}

	mode := cipher.NewCBCEncrypter(c.encBlock, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	h := c.macPoolEnc.Get().(hash.Hash)
	h.Reset()
	h.Write(iv)
	h.Write(ciphertext)
	calculatedMAC := h.Sum(nil)
	copy(mac, calculatedMAC)
	c.macPoolEnc.Put(h)

	log.Debugln("[OpenVPN] CBC Encrypt: pid=%d, plaintext_len=%d, padded_len=%d, result_len=%d", pid, len(plaintext), paddedLen, len(result))
	if len(ciphertext) <= 64 {
		log.Debugln("[OpenVPN] CBC Encrypt: ciphertext=%s", hex.EncodeToString(ciphertext))
	}

	return result, nil
}

func (c *CBCCipher) Decrypt(data []byte, _ []byte) ([]byte, error) {
	if len(data) < 20+16 {
		return nil, errors.New("CBC data too short")
	}

	mac := data[0:20]
	iv := data[20:36]
	ciphertext := data[36:]

	h := c.macPoolDec.Get().(hash.Hash)
	h.Reset()
	h.Write(iv)
	h.Write(ciphertext)
	expectedMAC := h.Sum(nil)
	c.macPoolDec.Put(h)

	if !hmac.Equal(mac, expectedMAC) {
		return nil, errors.New("CBC HMAC verification failed")
	}

	if len(ciphertext)%c.decBlock.BlockSize() != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	// In-place decryption to avoid allocations
	mode := cipher.NewCBCDecrypter(c.decBlock, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	if len(ciphertext) == 0 {
		return nil, errors.New("plaintext is empty")
	}
	padding := int(ciphertext[len(ciphertext)-1])
	if padding > c.decBlock.BlockSize() || padding > len(ciphertext) || padding == 0 {
		return nil, errors.New("invalid padding")
	}
	plaintext := ciphertext[:len(ciphertext)-padding]

	if len(plaintext) < 4 {
		return nil, errors.New("decrypted data too short for packet_id")
	}

	packetID := binary.BigEndian.Uint32(plaintext[0:4])
	if !c.replayWindow.Check(packetID) {
		return nil, errors.New("replayed or stale packet")
	}
	c.replayWindow.Update(packetID)

	return plaintext[4:], nil
}

type GCMCipher struct {
	encAEAD      cipher.AEAD
	decAEAD      cipher.AEAD
	encryptIV    []byte
	decryptIV    []byte
	packetID     uint32
	mutex        sync.Mutex
	replayWindow *ReplayWindow
}

func NewGCMCipher(encKey, decKey, encIV, decIV []byte) (*GCMCipher, error) {
	encBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	encAEAD, err := cipher.NewGCM(encBlock)
	if err != nil {
		return nil, err
	}

	decBlock, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, err
	}
	decAEAD, err := cipher.NewGCM(decBlock)
	if err != nil {
		return nil, err
	}

	return &GCMCipher{
		encAEAD:      encAEAD,
		decAEAD:      decAEAD,
		encryptIV:    encIV,
		decryptIV:    decIV,
		replayWindow: NewReplayWindow(64),
	}, nil
}

func (c *GCMCipher) Encrypt(plaintext []byte, ad []byte) ([]byte, error) {
	c.mutex.Lock()
	c.packetID++
	pid := c.packetID
	c.mutex.Unlock()

	// OpenVPN AEAD nonce: [packet_id(4)] [implicit_iv(8)]
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[0:4], pid)
	copy(nonce[4:12], c.encryptIV)

	// AAD = [ad_prefix (opcode+peerid for V2)] [packet_id(4)]
	var fullAD [8]byte
	n := copy(fullAD[:], ad)
	binary.BigEndian.PutUint32(fullAD[n:n+4], pid)

	// Wire format: [packet_id(4)] [tag(16)] [ciphertext]
	// Seal into result after pid+tag gap, then rearrange tag to front.
	tagSize := c.encAEAD.Overhead()
	result := make([]byte, 4+tagSize+len(plaintext))
	binary.BigEndian.PutUint32(result[0:4], pid)
	sealed := c.encAEAD.Seal(result[4:4], nonce[:], plaintext, fullAD[:n+4])
	// sealed layout in result[4:]: [ciphertext][tag] → rearrange to [tag][ciphertext]
	ctLen := len(sealed) - tagSize
	var tagBuf [16]byte
	copy(tagBuf[:], sealed[ctLen:])
	copy(result[4+tagSize:], sealed[:ctLen])
	copy(result[4:4+tagSize], tagBuf[:])

	return result, nil
}

func (c *GCMCipher) Decrypt(data []byte, ad []byte) ([]byte, error) {
	tagSize := c.decAEAD.Overhead()
	if len(data) < 4+tagSize {
		return nil, errors.New("data too short for GCM")
	}

	packetID := binary.BigEndian.Uint32(data[0:4])

	if !c.replayWindow.Check(packetID) {
		return nil, errors.New("replayed or stale packet")
	}

	// Wire: [packet_id(4)] [tag(16)] [ciphertext]
	// Go AEAD.Open expects: [ciphertext] [tag]
	ctLen := len(data) - 4 - tagSize
	sealed := make([]byte, ctLen+tagSize)
	copy(sealed, data[4+tagSize:])
	copy(sealed[ctLen:], data[4:4+tagSize])

	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[0:4], packetID)
	copy(nonce[4:12], c.decryptIV)

	var fullAD [8]byte
	n := copy(fullAD[:], ad)
	copy(fullAD[n:n+4], data[0:4])

	plaintext, err := c.decAEAD.Open(sealed[:0], nonce[:], sealed, fullAD[:n+4])
	if err != nil {
		return nil, err
	}

	c.replayWindow.Update(packetID)
	return plaintext, nil
}
