package openvpn

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"strings"
	"time"

	"github.com/airofm/sing-openvpn/internal/crypto"
	"github.com/airofm/sing-openvpn/internal/log"
	"github.com/metacubex/tls"
)

func (s *session) performHandshake(ctx context.Context) error {
	hsStart := time.Now()

	// 1. Send Hard Reset
	log.Debugln("[OpenVPN] Phase 1: Sending Hard Reset")
	if err := s.sendReset(); err != nil {
		return err
	}

	// 2. Wait for Server Hard Reset
	select {
	case <-time.After(10 * time.Second):
		return fmt.Errorf("timeout waiting for server response")
	case <-ctx.Done():
		return ctx.Err()
	case err := <-s.errChan:
		return err
	case <-s.handshakeStarted:
		// Server responded with Hard Reset, continue to TLS
	}
	log.Infoln("[OpenVPN] Phase 1: Hard Reset exchange took %s", time.Since(hsStart))

	// 3. TLS Handshake (tlsConfig was built in NewClient)
	s.tlsConn = tls.Client(s.controlConn, s.client.tlsConfig)

	tlsStart := time.Now()
	log.Debugln("[OpenVPN] Phase 2: Starting TLS handshake")
	if err := s.tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}
	{
		cs := s.tlsConn.ConnectionState()
		log.Infoln("[OpenVPN] Phase 2: TLS Handshake completed in %s: version=0x%04X cipherSuite=0x%04X", time.Since(tlsStart), cs.Version, cs.CipherSuite)
	}

	// 4. key_method_2 exchange + PUSH_REPLY
	negoStart := time.Now()
	log.Debugln("[OpenVPN] Phase 3: Starting config negotiation (key exchange + PUSH)")
	if err := s.negotiateConfig(ctx); err != nil {
		return fmt.Errorf("config negotiation failed: %w", err)
	}
	log.Infoln("[OpenVPN] Phase 3: Config negotiation took %s", time.Since(negoStart))
	log.Infoln("[OpenVPN] Total handshake time: %s", time.Since(hsStart))
	return nil
}

func (s *session) negotiateConfig(ctx context.Context) error {
	if err := s.sendKeyMethod2(); err != nil {
		return fmt.Errorf("key_method_2 send failed: %w", err)
	}

	// We use a single accumulated buffer to cope with TLS Read returning
	// partial records or multiple messages in one call.
	var accumBuf []byte
	keyMethod2Done := false
	pushReplyDone := false
	var pushReply string

	deadline := time.Now().Add(30 * time.Second)
	readBuf := make([]byte, 8192)

	for !pushReplyDone {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for server negotiation")
		}
		s.tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := s.tlsConn.Read(readBuf)
		s.tlsConn.SetReadDeadline(time.Time{})
		if err != nil {
			if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
				if keyMethod2Done {
					return fmt.Errorf("timeout waiting for PUSH_REPLY")
				}
				return fmt.Errorf("timeout waiting for key_method_2 response")
			}
			return fmt.Errorf("TLS read error: %w", err)
		}
		accumBuf = append(accumBuf, readBuf[:n]...)
		log.Debugln("[OpenVPN] TLS negotiation read: %d bytes, total=%d", n, len(accumBuf))

		if !keyMethod2Done {
			if len(accumBuf) >= 69 {
				if err := s.parseKeyMethod2Response(accumBuf); err != nil {
					return fmt.Errorf("key_method_2 response failed: %w", err)
				}
				keyMethod2Done = true
				log.Infoln("[OpenVPN] Key exchange completed, sending PUSH_REQUEST")

				if _, err := s.tlsConn.Write([]byte("PUSH_REQUEST\x00")); err != nil {
					return fmt.Errorf("failed to send PUSH_REQUEST: %w", err)
				}

				consumed := s.keyMethod2ResponseSize(accumBuf)
				accumBuf = accumBuf[consumed:]
				log.Debugln("[OpenVPN] key_method_2 consumed %d bytes, %d bytes remaining", consumed, len(accumBuf))
			}
		}

		if keyMethod2Done {
			t := string(accumBuf)
			if strings.Contains(t, "AUTH_FAILED") {
				return fmt.Errorf("authentication failed: %s", t)
			}
			if strings.Contains(t, "PUSH_REPLY") {
				idx := strings.Index(t, "PUSH_REPLY")
				end := strings.IndexByte(t[idx:], 0)
				if end >= 0 {
					pushReply = t[idx : idx+end]
				} else {
					pushReply = t[idx:]
				}
				pushReplyDone = true
				log.Debugln("[OpenVPN] PUSH_REPLY found in accumulated buffer")
			} else if strings.Contains(t, "AUTH_TOKEN") || strings.Contains(t, "auth-token") {
				log.Debugln("[OpenVPN] Received auth-token, ignoring and continuing to read")
				if nullIdx := strings.IndexByte(t, 0); nullIdx >= 0 {
					accumBuf = accumBuf[nullIdx+1:]
				}
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	log.Infoln("[OpenVPN] Received config: %s", pushReply)

	// Drain any remaining TLS data after PUSH_REPLY to prevent state
	// corruption on subsequent reads.
	s.tlsConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	drainBuf := make([]byte, 4096)
	for {
		n, err := s.tlsConn.Read(drainBuf)
		if n > 0 {
			log.Debugln("[OpenVPN] Drained %d post-PUSH_REPLY TLS bytes: %s", n, string(drainBuf[:n]))
		}
		if err != nil {
			break
		}
	}
	s.tlsConn.SetReadDeadline(time.Time{})

	if err := s.parsePushReply(pushReply); err != nil {
		return err
	}

	// 5. Derive data-channel keys via OpenVPN PRF (key_method 2).
	keyLen := 256 // key2 = 2 * struct key (each: cipher[64] + hmac[64])
	log.Infoln("[OpenVPN] Using traditional PRF for key derivation")
	log.Debugln("[OpenVPN] PRF inputs: pre_master=%s", hex.EncodeToString(s.clientPreMaster[:8]))
	log.Debugln("[OpenVPN] PRF inputs: client_r1=%s, server_r1=%s", hex.EncodeToString(s.clientRandom1[:8]), hex.EncodeToString(s.serverRandom1[:8]))
	log.Debugln("[OpenVPN] PRF inputs: client_r2=%s, server_r2=%s", hex.EncodeToString(s.clientRandom2[:8]), hex.EncodeToString(s.serverRandom2[:8]))
	log.Debugln("[OpenVPN] PRF inputs: localSID=%x, remoteSID=%x", s.localSID, s.remoteSID)

	master := crypto.OpenVPNPRF(s.clientPreMaster,
		"OpenVPN master secret",
		s.clientRandom1, s.serverRandom1,
		nil, nil, 48)
	log.Debugln("[OpenVPN] PRF master=%s", hex.EncodeToString(master[:16]))

	keyMaterial := crypto.OpenVPNPRF(master,
		"OpenVPN key expansion",
		s.clientRandom2, s.serverRandom2,
		&s.localSID, &s.remoteSID, keyLen)
	log.Debugln("[OpenVPN] PRF key_block[0:32]=%s", hex.EncodeToString(keyMaterial[:32]))
	log.Debugln("[OpenVPN] PRF key_block[64:96]=%s", hex.EncodeToString(keyMaterial[64:96]))
	log.Debugln("[OpenVPN] PRF key_block[128:160]=%s", hex.EncodeToString(keyMaterial[128:160]))
	log.Debugln("[OpenVPN] PRF key_block[192:224]=%s", hex.EncodeToString(keyMaterial[192:224]))

	log.Infoln("[OpenVPN] Using cipher: %s for data channel", s.cipherName)
	var err error
	if strings.Contains(s.cipherName, "GCM") {
		encKey := keyMaterial[0:32]
		decKey := keyMaterial[128 : 128+32]
		encIV := keyMaterial[64 : 64+8]
		decIV := keyMaterial[128+64 : 128+64+8]
		s.cipher, err = crypto.NewGCMCipher(encKey, decKey, encIV, decIV)
		if err != nil {
			return fmt.Errorf("failed to create GCM cipher: %w", err)
		}
		log.Infoln("[OpenVPN] Negotiated AES-GCM data channel keys")
	} else {
		encCipherKey := keyMaterial[0:32]
		decCipherKey := keyMaterial[128 : 128+32]
		encHMACKey := keyMaterial[64 : 64+20]
		decHMACKey := keyMaterial[192 : 192+20]
		s.cipher, err = crypto.NewCBCCipher(encCipherKey, decCipherKey, encHMACKey, decHMACKey)
		if err != nil {
			return fmt.Errorf("failed to create CBC cipher: %w", err)
		}
		log.Infoln("[OpenVPN] Negotiated AES-CBC data channel keys")
	}

	s.initDataHeader()
	return nil
}

func writeString(buf *bytes.Buffer, str string) {
	data := str + "\x00"
	binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.WriteString(data)
}

func (s *session) sendKeyMethod2() error {
	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, uint32(0))
	buf.WriteByte(2)

	random := make([]byte, 48+32+32)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return err
	}
	buf.Write(random)

	s.clientPreMaster = random[0:48]
	s.clientRandom1 = random[48:80]
	s.clientRandom2 = random[80:112]

	proto := "UDPv4"
	if !s.isUDP() {
		proto = "TCPv4_CLIENT"
	}
	cipher := s.cipherName
	if cipher == "" {
		cipher = "AES-256-GCM"
	}
	auth := s.client.cfg.Auth
	if auth == "" {
		auth = "SHA1"
	}
	options := fmt.Sprintf("V4,dev-type tun,link-mtu 1557,tun-mtu 1500,proto %s,cipher %s,auth %s,keysize 256,key-method 2,tls-client", proto, cipher, auth)
	writeString(&buf, options)

	if s.client.cfg.Username != "" {
		writeString(&buf, s.client.cfg.Username)
		writeString(&buf, s.client.cfg.Password)
	}

	peerInfo := "IV_VER=3.11.3\nIV_PLAT=linux\nIV_NCP=2\nIV_TCPNL=1\nIV_PROTO=6\nIV_MTU=1600\nIV_CIPHERS=AES-128-CBC:AES-192-CBC:AES-256-CBC:AES-128-GCM:AES-192-GCM:AES-256-GCM:CHACHA20-POLY1305\nIV_SSL=OpenSSL 3.0.0 7 Sep 2021\nIV_IPv6=0\n"
	writeString(&buf, peerInfo)

	if _, err := s.tlsConn.Write(buf.Bytes()); err != nil {
		return err
	}
	log.Infoln("[OpenVPN] Sent key_method_2 exchange (auth=%v)", s.client.cfg.Username != "")
	return nil
}

func (s *session) parseKeyMethod2Response(data []byte) error {
	if len(data) < 4+1+64 {
		return fmt.Errorf("key_method_2 response too short: %d bytes", len(data))
	}

	dumpLen := 80
	if len(data) < dumpLen {
		dumpLen = len(data)
	}
	log.Debugln("[OpenVPN] key_method_2 response: len=%d, hex=%s", len(data), hex.EncodeToString(data[:dumpLen]))
	log.Debugln("[OpenVPN] key_method_2: literal_zero=%s, key_method=%d", hex.EncodeToString(data[0:4]), data[4])

	s.serverRandom1 = make([]byte, 32)
	s.serverRandom2 = make([]byte, 32)
	copy(s.serverRandom1, data[5:37])
	copy(s.serverRandom2, data[37:69])
	log.Debugln("[OpenVPN] Server random1=%s", hex.EncodeToString(s.serverRandom1))
	log.Debugln("[OpenVPN] Server random2=%s", hex.EncodeToString(s.serverRandom2))

	offset := 4 + 1 + 64
	if len(data) >= offset+2 {
		optLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if len(data) >= offset+optLen && optLen > 0 {
			serverOpts := string(data[offset : offset+optLen-1])
			log.Infoln("[OpenVPN] Server options: %s", serverOpts)
		}
	}
	return nil
}

func (s *session) keyMethod2ResponseSize(data []byte) int {
	base := 4 + 1 + 64
	if len(data) < base+2 {
		return len(data)
	}
	optLen := int(binary.BigEndian.Uint16(data[base:]))
	total := base + 2 + optLen
	if total > len(data) {
		return len(data)
	}
	return total
}

// parsePushReply writes pushed values into the session. It does NOT mutate
// the Client's Config; publishing happens once in Dial on the winning session.
func (s *session) parsePushReply(reply string) error {
	log.Infoln("[OpenVPN] PUSH_REPLY raw: %s", reply)
	parts := strings.Split(reply, ",")

	topology := "net30"
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "topology ") {
			topology = strings.TrimSpace(strings.TrimPrefix(part, "topology "))
			log.Infoln("[OpenVPN] Pushed topology: %s", topology)
		}
	}

	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "ifconfig "):
			args := strings.Fields(part)
			if len(args) < 3 {
				continue
			}
			addr, err := netip.ParseAddr(args[1])
			if err != nil {
				continue
			}
			s.ifconfigIP = addr
			var prefix netip.Prefix
			if topology == "subnet" {
				maskIP, maskErr := netip.ParseAddr(args[2])
				if maskErr == nil && maskIP.Is4() {
					m4 := maskIP.As4()
					prefixLen := 0
					for _, b := range m4 {
						prefixLen += bits.OnesCount8(b)
					}
					prefix = netip.PrefixFrom(addr, prefixLen)
				} else {
					prefix = netip.PrefixFrom(addr, 24)
				}
			} else {
				prefixLen := 30
				if topology == "p2p" {
					prefixLen = 32
				}
				prefix = netip.PrefixFrom(addr, prefixLen)
			}
			s.ifconfigMask = prefix
			log.Infoln("[OpenVPN] Pushed IP: %s (arg2: %s), topology=%s, TUN prefix: %s", args[1], args[2], topology, prefix)
		case strings.HasPrefix(part, "mtu "):
			fmt.Sscanf(part, "mtu %d", &s.mtu)
			log.Infoln("[OpenVPN] Pushed MTU: %d", s.mtu)
		case strings.HasPrefix(part, "cipher "):
			s.cipherName = strings.TrimPrefix(part, "cipher ")
			log.Infoln("[OpenVPN] Pushed cipher: %s", s.cipherName)
		case strings.HasPrefix(part, "peer-id "):
			fmt.Sscanf(part, "peer-id %d", &s.peerID)
			log.Infoln("[OpenVPN] Pushed peer-id: %d", s.peerID)
		case strings.HasPrefix(part, "dhcp-option DNS "):
			dns := strings.TrimSpace(strings.TrimPrefix(part, "dhcp-option DNS "))
			s.dns = append(s.dns, dns)
			log.Infoln("[OpenVPN] Pushed DNS server: %s", dns)
		case strings.HasPrefix(part, "route "):
			log.Infoln("[OpenVPN] Pushed route: %s", strings.TrimPrefix(part, "route "))
		case strings.HasPrefix(part, "route-delay "):
			args := strings.Fields(part)
			if len(args) >= 2 {
				delay := 0
				fmt.Sscanf(args[1], "%d", &delay)
				if delay > 0 && delay < 30 {
					s.routeDelay = delay
				}
			}
			log.Infoln("[OpenVPN] Pushed route-delay: %s", strings.TrimPrefix(part, "route-delay "))
		case strings.HasPrefix(part, "ping "):
			log.Debugln("[OpenVPN] Pushed ping: %s (ignored, using ping-restart/2)", strings.TrimPrefix(part, "ping "))
		case strings.HasPrefix(part, "ping-restart "):
			var val int
			fmt.Sscanf(part, "ping-restart %d", &val)
			if val > 0 {
				s.pingTimeout = val
				s.pingInterval = max(val/2, 1)
			}
			log.Infoln("[OpenVPN] Pushed ping-restart: %d, ping interval: %d", s.pingTimeout, s.pingInterval)
		}
	}
	return nil
}
