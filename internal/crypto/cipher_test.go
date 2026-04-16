package crypto

import (
	"bytes"
	"crypto/aes"
	gocipher "crypto/cipher"
	"encoding/binary"
	"fmt"
	"testing"
)

var (
	testEncKey = [32]byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	}
	testEncIV   = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	testHMACKey = [20]byte{
		100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
		110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
	}
)

// dataV2AD returns a DATA_V2 AD prefix: opcode=9, keyID=0, peerID=7.
func dataV2AD() []byte {
	return []byte{0x48, 0x00, 0x00, 0x07}
}

func newTestGCM(t *testing.T) *GCMCipher {
	t.Helper()
	c, err := NewGCMCipher(testEncKey[:], testEncKey[:], testEncIV, testEncIV)
	if err != nil {
		t.Fatalf("NewGCMCipher: %v", err)
	}
	return c
}

func newTestCBC(t *testing.T) *CBCCipher {
	t.Helper()
	c, err := NewCBCCipher(testEncKey[:], testEncKey[:], testHMACKey[:], testHMACKey[:])
	if err != nil {
		t.Fatalf("NewCBCCipher: %v", err)
	}
	return c
}

// parseGCMWire splits an OpenVPN AEAD wire packet into its components.
func parseGCMWire(wire []byte) (pid uint32, tag, ct []byte) {
	pid = binary.BigEndian.Uint32(wire[0:4])
	tag = wire[4:20]
	ct = wire[20:]
	return
}

// manualGCMDecrypt decrypts using raw Go crypto, bypassing GCMCipher.
// This verifies that the nonce, AAD, and wire layout are correct.
func manualGCMDecrypt(t *testing.T, key, implicitIV, ad, wire []byte) []byte {
	t.Helper()
	pid, tag, ct := parseGCMWire(wire)

	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[0:4], pid)
	copy(nonce[4:12], implicitIV)

	var fullAD [8]byte
	n := copy(fullAD[:], ad)
	binary.BigEndian.PutUint32(fullAD[n:n+4], pid)

	sealed := make([]byte, len(ct)+len(tag))
	copy(sealed, ct)
	copy(sealed[len(ct):], tag)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := gocipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	decrypted, err := aead.Open(nil, nonce[:], sealed, fullAD[:n+4])
	if err != nil {
		t.Fatalf("manual GCM decrypt failed: %v", err)
	}
	return decrypted
}

// TestGCMNonceConstruction verifies the nonce matches OpenVPN spec:
//
//	nonce = [packet_id(4)] [implicit_iv(8)]
//
// Reference: openvpn/src/openvpn/crypto.c key_ctx_update_implicit_iv + encrypt loop.
func TestGCMNonceConstruction(t *testing.T) {
	c := newTestGCM(t)
	ad := dataV2AD()

	wire, err := c.Encrypt([]byte("hello"), ad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	pid, _, _ := parseGCMWire(wire)
	if pid != 1 {
		t.Fatalf("first packet_id = %d, want 1", pid)
	}

	// If the nonce were wrong, manual decrypt with the spec nonce would fail
	decrypted := manualGCMDecrypt(t, testEncKey[:], testEncIV, ad, wire)
	if string(decrypted) != "hello" {
		t.Fatalf("decrypted = %q, want %q", decrypted, "hello")
	}
}

// TestGCMWireFormat verifies the output byte layout matches OpenVPN:
//
//	wire = [packet_id(4)] [tag(16)] [ciphertext(N)]
//
// Reference: openvpn/src/openvpn/crypto.c openvpn_encrypt_aead
func TestGCMWireFormat(t *testing.T) {
	c := newTestGCM(t)
	plaintext := []byte("test data for wire format")
	ad := dataV2AD()

	wire, err := c.Encrypt(plaintext, ad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	expectedLen := 4 + 16 + len(plaintext)
	if len(wire) != expectedLen {
		t.Fatalf("wire length = %d, want %d", len(wire), expectedLen)
	}

	_, tag, ct := parseGCMWire(wire)
	if len(ct) != len(plaintext) {
		t.Fatalf("ciphertext length = %d, want %d", len(ct), len(plaintext))
	}
	if bytes.Equal(tag, make([]byte, 16)) {
		t.Fatal("tag is all zeros — likely not placed correctly")
	}

	decrypted := manualGCMDecrypt(t, testEncKey[:], testEncIV, ad, wire)
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

// TestGCMAADWithDataV2 verifies the AAD includes opcode+peerid for DATA_V2:
//
//	AAD = [opcode_byte(1)] [peer_id(3)] [packet_id(4)]
//
// Reference: openvpn/src/openvpn/crypto.c — cipher_ctx_update_ad covers
// the work buffer [opcode+peerid][packet_id].
func TestGCMAADWithDataV2(t *testing.T) {
	c := newTestGCM(t)
	plaintext := []byte("aad test")
	ad := dataV2AD()

	wire, err := c.Encrypt(plaintext, ad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	c2 := newTestGCM(t)
	decrypted, err := c2.Decrypt(wire, ad)
	if err != nil {
		t.Fatalf("Decrypt with correct AD: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}

	// Wrong AD must fail (proves AAD is authenticated)
	c3 := newTestGCM(t)
	_, err = c3.Decrypt(wire, []byte{0x48, 0x00, 0x00, 0x99})
	if err == nil {
		t.Fatal("Decrypt with wrong AD should fail")
	}
}

// TestGCMAADWithDataV1 verifies DATA_V1 (nil AD) uses only packet_id as AAD.
func TestGCMAADWithDataV1(t *testing.T) {
	c := newTestGCM(t)
	plaintext := []byte("v1 test")

	wire, err := c.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	c2 := newTestGCM(t)
	decrypted, err := c2.Decrypt(wire, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

// TestGCMAADCrossMismatch verifies that encrypting with nil AD and
// decrypting with non-nil AD (or vice versa) fails.
func TestGCMAADCrossMismatch(t *testing.T) {
	c := newTestGCM(t)
	wire, err := c.Encrypt([]byte("cross"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	c2 := newTestGCM(t)
	_, err = c2.Decrypt(wire, dataV2AD())
	if err == nil {
		t.Fatal("Decrypt with V2 AD on V1-encrypted packet should fail")
	}
}

// TestGCMPacketIDStartsAt1 verifies packet IDs start at 1 (0 is reserved in OpenVPN AEAD).
func TestGCMPacketIDStartsAt1(t *testing.T) {
	c := newTestGCM(t)

	wire1, err := c.Encrypt([]byte("a"), nil)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}
	wire2, err := c.Encrypt([]byte("b"), nil)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}

	pid1, _, _ := parseGCMWire(wire1)
	pid2, _, _ := parseGCMWire(wire2)

	if pid1 != 1 {
		t.Errorf("first packet_id = %d, want 1", pid1)
	}
	if pid2 != 2 {
		t.Errorf("second packet_id = %d, want 2", pid2)
	}
}

// TestGCMRoundTrip verifies encrypt→decrypt for various payload sizes.
func TestGCMRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 15, 16, 17, 100, 1400, 1500}
	ad := dataV2AD()

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			c := newTestGCM(t)
			plaintext := make([]byte, size)
			for i := range plaintext {
				plaintext[i] = byte(i % 256)
			}

			wire, err := c.Encrypt(plaintext, ad)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			c2 := newTestGCM(t)
			decrypted, err := c2.Decrypt(wire, ad)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("decrypted mismatch: got %d bytes, want %d", len(decrypted), len(plaintext))
			}
		})
	}
}

// TestGCMReplayRejection verifies the replay window rejects duplicate packets.
func TestGCMReplayRejection(t *testing.T) {
	c := newTestGCM(t)
	ad := dataV2AD()

	wire, err := c.Encrypt([]byte("replay test"), ad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	c2 := newTestGCM(t)
	if _, err := c2.Decrypt(wire, ad); err != nil {
		t.Fatalf("first Decrypt: %v", err)
	}
	if _, err := c2.Decrypt(wire, ad); err == nil {
		t.Fatal("replayed packet should be rejected")
	}
}

// TestCBCRoundTrip verifies CBC encrypt→decrypt is unaffected by the ad parameter.
func TestCBCRoundTrip(t *testing.T) {
	c := newTestCBC(t)
	plaintext := []byte("cbc round trip test data")

	// CBC txPacketID starts at 0, but replay window rejects 0.
	// Burn pid=0 so pid=1 is valid. See TestCBCPacketIDZeroBug.
	c.Encrypt([]byte("burn"), nil)

	wire, err := c.Encrypt(plaintext, dataV2AD())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	c2 := newTestCBC(t)
	decrypted, err := c2.Decrypt(wire, dataV2AD())
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

// TestCBCPacketIDZeroBug documents that CBC starts packet_id at 0
// but the replay window rejects 0. This is a known inconsistency
// (GCM was fixed to start at 1, CBC was not yet updated).
func TestCBCPacketIDZeroBug(t *testing.T) {
	c := newTestCBC(t)
	wire, err := c.Encrypt([]byte("test"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	c2 := newTestCBC(t)
	_, err = c2.Decrypt(wire, nil)
	if err == nil {
		t.Fatal("expected replay rejection for pid=0, but decrypt succeeded")
	}
}
