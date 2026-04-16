package openvpn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/airofm/sing-openvpn/internal/crypto"
	"github.com/airofm/sing-openvpn/internal/log"
	"github.com/metacubex/tls"
)

func (c *Client) performHandshake(ctx context.Context) error {
	hsStart := time.Now()

	// 1. Send Hard Reset
	log.Debugln("[OpenVPN] Phase 1: Sending Hard Reset")
	if err := c.sendReset(); err != nil {
		return err
	}

	// 2. Wait for Server Hard Reset
	select {
	case <-time.After(10 * time.Second):
		return fmt.Errorf("timeout waiting for server response")
	case <-ctx.Done():
		return ctx.Err()
	case err := <-c.errChan:
		return err
	case <-c.handshakeStarted:
		// Server responded with Hard Reset, continue to TLS
	}
	log.Infoln("[OpenVPN] Phase 1: Hard Reset exchange took %s", time.Since(hsStart))

	// 3. TLS Handshake
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	if c.cfg.CACert != "" {
		pool := x509.NewCertPool()
		ok := pool.AppendCertsFromPEM([]byte(c.cfg.CACert))
		if ok {
			tlsConfig.RootCAs = pool
			// OpenVPN uses its own CA, server cert CN doesn't match the hostname.
			// Verify the chain but skip hostname check.
			tlsConfig.InsecureSkipVerify = true
			tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				certs := make([]*x509.Certificate, len(rawCerts))
				for i, raw := range rawCerts {
					cert, err := x509.ParseCertificate(raw)
					if err != nil {
						return err
					}
					certs[i] = cert
				}
				opts := x509.VerifyOptions{
					Roots:         pool,
					Intermediates: x509.NewCertPool(),
				}
				for _, cert := range certs[1:] {
					opts.Intermediates.AddCert(cert)
				}
				_, err := certs[0].Verify(opts)
				return err
			}
		} else {
			log.Warnln("[OpenVPN] Failed to load CA certificate")
		}
	}

	if c.cfg.TLSCert != "" && c.cfg.TLSKey != "" {
		cert, err := tls.X509KeyPair([]byte(c.cfg.TLSCert), []byte(c.cfg.TLSKey))
		if err == nil {
			tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return &cert, nil
			}
		} else {
			log.Warnln("[OpenVPN] Failed to load client certificate: %v", err)
		}
	}

	c.tlsConn = tls.Client(c.controlConn, tlsConfig)

	// 4. Perform TLS Handshake and Post-Handshake Negotiation
	tlsStart := time.Now()
	log.Debugln("[OpenVPN] Phase 2: Starting TLS handshake")
	if err := c.tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}
	{
		cs := c.tlsConn.ConnectionState()
		log.Infoln("[OpenVPN] Phase 2: TLS Handshake completed in %s: version=0x%04X cipherSuite=0x%04X", time.Since(tlsStart), cs.Version, cs.CipherSuite)
	}

	// 5. Send PUSH_REQUEST and wait for PUSH_REPLY
	negoStart := time.Now()
	log.Debugln("[OpenVPN] Phase 3: Starting config negotiation (key exchange + PUSH)")
	if err := c.negotiateConfig(ctx); err != nil {
		return fmt.Errorf("config negotiation failed: %w", err)
	}
	log.Infoln("[OpenVPN] Phase 3: Config negotiation took %s", time.Since(negoStart))
	log.Infoln("[OpenVPN] Total handshake time: %s", time.Since(hsStart))

	return nil
}

func (c *Client) negotiateConfig(ctx context.Context) error {
	// Send key_method_2 exchange (required before PUSH_REQUEST)
	if err := c.sendKeyMethod2(); err != nil {
		return fmt.Errorf("key_method_2 send failed: %w", err)
	}

	// Read all TLS messages in a streaming loop until we have both
	// the server key_method_2 response AND the PUSH_REPLY.
	// We use a single accumulated buffer to avoid issues with TLS Read
	// returning partial records or multiple messages in one call.
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
		c.tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := c.tlsConn.Read(readBuf)
		c.tlsConn.SetReadDeadline(time.Time{})
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

		// Process key_method_2 response first
		if !keyMethod2Done {
			// key_method_2 response minimum size: 4+1+64 = 69 bytes
			// After parsing, send PUSH_REQUEST
			if len(accumBuf) >= 69 {
				if err := c.parseKeyMethod2Response(accumBuf); err != nil {
					return fmt.Errorf("key_method_2 response failed: %w", err)
				}
				keyMethod2Done = true
				log.Infoln("[OpenVPN] Key exchange completed, sending PUSH_REQUEST")

				// Send PUSH_REQUEST
				if _, err := c.tlsConn.Write([]byte("PUSH_REQUEST\x00")); err != nil {
					return fmt.Errorf("failed to send PUSH_REQUEST: %w", err)
				}

				// Remaining bytes after key_method_2 may contain PUSH_REPLY
				// We need to figure out how many bytes key_method_2 consumed.
				// key_method_2: [zero(4)][key_method(1)][random1(32)][random2(32)][options(2+len)]
				consumed := c.keyMethod2ResponseSize(accumBuf)
				accumBuf = accumBuf[consumed:]
				log.Debugln("[OpenVPN] key_method_2 consumed %d bytes, %d bytes remaining", consumed, len(accumBuf))
			}
		}

		// Check for PUSH_REPLY in accumulated buffer (may arrive in same or next read)
		if keyMethod2Done {
			s := string(accumBuf)
			if strings.Contains(s, "AUTH_FAILED") {
				return fmt.Errorf("authentication failed: %s", s)
			}
			if strings.Contains(s, "PUSH_REPLY") {
				// Extract the PUSH_REPLY message (null-terminated or to end of buffer)
				idx := strings.Index(s, "PUSH_REPLY")
				end := strings.IndexByte(s[idx:], 0)
				if end >= 0 {
					pushReply = s[idx : idx+end]
				} else {
					pushReply = s[idx:]
				}
				pushReplyDone = true
				log.Debugln("[OpenVPN] PUSH_REPLY found in accumulated buffer")
			} else if strings.Contains(s, "AUTH_TOKEN") || strings.Contains(s, "auth-token") {
				log.Debugln("[OpenVPN] Received auth-token, ignoring and continuing to read")
				// Consume everything up to (and including) the null terminator
				if nullIdx := strings.IndexByte(s, 0); nullIdx >= 0 {
					accumBuf = accumBuf[nullIdx+1:]
				}
			}
		}
	}

	log.Infoln("[OpenVPN] Received config: %s", pushReply)

	// Drain any remaining TLS data after PUSH_REPLY (e.g. NCP, auth-token)
	// to prevent TLS state corruption on subsequent reads.
	c.tlsConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	drainBuf := make([]byte, 4096)
	for {
		n, err := c.tlsConn.Read(drainBuf)
		if n > 0 {
			log.Debugln("[OpenVPN] Drained %d post-PUSH_REPLY TLS bytes: %s", n, string(drainBuf[:n]))
		}
		if err != nil {
			break
		}
	}
	c.tlsConn.SetReadDeadline(time.Time{})

	// Parse PUSH_REPLY and update config
	if err := c.parsePushReply(pushReply); err != nil {
		return err
	}

	// 6. Derive data channel keys using OpenVPN PRF (key_method 2)
	keyLen := 256 // key2 = 2 * struct key (each: cipher[64] + hmac[64])

	log.Infoln("[OpenVPN] Using traditional PRF for key derivation")
	log.Debugln("[OpenVPN] PRF inputs: pre_master=%s", hex.EncodeToString(c.clientPreMaster[:8]))
	log.Debugln("[OpenVPN] PRF inputs: client_r1=%s, server_r1=%s", hex.EncodeToString(c.clientRandom1[:8]), hex.EncodeToString(c.serverRandom1[:8]))
	log.Debugln("[OpenVPN] PRF inputs: client_r2=%s, server_r2=%s", hex.EncodeToString(c.clientRandom2[:8]), hex.EncodeToString(c.serverRandom2[:8]))
	log.Debugln("[OpenVPN] PRF inputs: localSID=%x, remoteSID=%x", c.localSID, c.remoteSID)

	master := crypto.OpenVPNPRF(c.clientPreMaster,
		"OpenVPN master secret",
		c.clientRandom1, c.serverRandom1,
		nil, nil, 48)
	log.Debugln("[OpenVPN] PRF master=%s", hex.EncodeToString(master[:16]))

	keyMaterial := crypto.OpenVPNPRF(master,
		"OpenVPN key expansion",
		c.clientRandom2, c.serverRandom2,
		&c.localSID, &c.remoteSID, keyLen)
	log.Debugln("[OpenVPN] PRF key_block[0:32]=%s", hex.EncodeToString(keyMaterial[:32]))
	log.Debugln("[OpenVPN] PRF key_block[64:96]=%s", hex.EncodeToString(keyMaterial[64:96]))
	log.Debugln("[OpenVPN] PRF key_block[128:160]=%s", hex.EncodeToString(keyMaterial[128:160]))
	log.Debugln("[OpenVPN] PRF key_block[192:224]=%s", hex.EncodeToString(keyMaterial[192:224]))

	// key_block layout: key[0]{cipher[64],hmac[64]} + key[1]{cipher[64],hmac[64]}
	// TLS client (NORMAL): encrypt=key[0], decrypt=key[1]
	log.Infoln("[OpenVPN] Using cipher: %s for data channel", c.cfg.Cipher)
	var err error
	if strings.Contains(c.cfg.Cipher, "GCM") {
		encKey := keyMaterial[0:32]
		decKey := keyMaterial[128 : 128+32]
		encIV := keyMaterial[64 : 64+8]         // implicit IV, 8 bytes
		decIV := keyMaterial[128+64 : 128+64+8] // implicit IV, 8 bytes
		c.cipher, err = crypto.NewGCMCipher(encKey, decKey, encIV, decIV)
		if err != nil {
			return fmt.Errorf("failed to create GCM cipher: %w", err)
		}
		log.Infoln("[OpenVPN] Negotiated AES-GCM data channel keys")
	} else {
		encCipherKey := keyMaterial[0:32]
		decCipherKey := keyMaterial[128 : 128+32]
		encHMACKey := keyMaterial[64 : 64+20]
		decHMACKey := keyMaterial[192 : 192+20]
		c.cipher, err = crypto.NewCBCCipher(encCipherKey, decCipherKey, encHMACKey, decHMACKey)
		if err != nil {
			return fmt.Errorf("failed to create CBC cipher: %w", err)
		}
		log.Infoln("[OpenVPN] Negotiated AES-CBC data channel keys")
	}

	c.initDataHeader()

	return nil
}

func writeString(buf *bytes.Buffer, s string) {
	data := s + "\x00"
	binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.WriteString(data)
}

func (c *Client) sendKeyMethod2() error {
	var buf bytes.Buffer

	// Literal zero (uint32)
	binary.Write(&buf, binary.BigEndian, uint32(0))

	// Key method byte (KEY_METHOD_2 = 2)
	buf.WriteByte(2)

	// Key source material: pre_master(48) + random1(32) + random2(32) = 112 bytes
	random := make([]byte, 48+32+32)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return err
	}
	buf.Write(random)

	// Save for PRF key derivation
	c.clientPreMaster = random[0:48]
	c.clientRandom1 = random[48:80]
	c.clientRandom2 = random[80:112]

	// Options string
	proto := "UDPv4"
	if !c.isUDP() {
		proto = "TCPv4_CLIENT"
	}
	cipher := c.cfg.Cipher
	if cipher == "" {
		cipher = "AES-256-GCM"
	}
	auth := c.cfg.Auth
	if auth == "" {
		auth = "SHA1"
	}
	options := fmt.Sprintf("V4,dev-type tun,link-mtu 1557,tun-mtu 1500,proto %s,cipher %s,auth %s,keysize 256,key-method 2,tls-client", proto, cipher, auth)
	writeString(&buf, options)

	// Username/password (if auth-user-pass)
	if c.cfg.Username != "" {
		writeString(&buf, c.cfg.Username)
		writeString(&buf, c.cfg.Password)
	}

	// Peer-info: must be part of key_method_2 message for NCP cipher negotiation.
	// IV_CIPHERS triggers the server to negotiate data channel cipher via NCP.
	peerInfo := "IV_VER=3.11.3\nIV_PLAT=linux\nIV_NCP=2\nIV_TCPNL=1\nIV_PROTO=6\nIV_MTU=1600\nIV_CIPHERS=AES-128-CBC:AES-192-CBC:AES-256-CBC:AES-128-GCM:AES-192-GCM:AES-256-GCM:CHACHA20-POLY1305\nIV_SSL=OpenSSL 3.0.0 7 Sep 2021\nIV_IPv6=0\n"
	writeString(&buf, peerInfo)

	_, err := c.tlsConn.Write(buf.Bytes())
	if err != nil {
		return err
	}
	log.Infoln("[OpenVPN] Sent key_method_2 exchange (auth=%v)", c.cfg.Username != "")
	return nil
}

func (c *Client) parseKeyMethod2Response(data []byte) error {
	if len(data) < 4+1+64 {
		return fmt.Errorf("key_method_2 response too short: %d bytes", len(data))
	}

	dumpLen := 80
	if len(data) < dumpLen {
		dumpLen = len(data)
	}
	log.Debugln("[OpenVPN] key_method_2 response: len=%d, hex=%s", len(data), hex.EncodeToString(data[:dumpLen]))
	log.Debugln("[OpenVPN] key_method_2: literal_zero=%s, key_method=%d", hex.EncodeToString(data[0:4]), data[4])

	c.serverRandom1 = make([]byte, 32)
	c.serverRandom2 = make([]byte, 32)
	copy(c.serverRandom1, data[5:37])
	copy(c.serverRandom2, data[37:69])
	log.Debugln("[OpenVPN] Server random1=%s", hex.EncodeToString(c.serverRandom1))
	log.Debugln("[OpenVPN] Server random2=%s", hex.EncodeToString(c.serverRandom2))

	offset := 4 + 1 + 64
	if len(data) >= offset+2 {
		optLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if len(data) >= offset+optLen && optLen > 0 {
			serverOpts := string(data[offset : offset+optLen-1]) // exclude null terminator
			log.Infoln("[OpenVPN] Server options: %s", serverOpts)
		}
	}
	return nil
}

func (c *Client) keyMethod2ResponseSize(data []byte) int {
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

func (c *Client) parsePushReply(reply string) error {
	// Example: PUSH_REPLY,topology subnet,ifconfig 172.27.233.148 255.255.254.0,...
	log.Infoln("[OpenVPN] PUSH_REPLY raw: %s", reply)
	parts := strings.Split(reply, ",")

	// First pass: collect topology (needed to interpret ifconfig correctly)
	topology := "net30" // default
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "topology ") {
			topology = strings.TrimPrefix(part, "topology ")
			topology = strings.TrimSpace(topology)
			log.Infoln("[OpenVPN] Pushed topology: %s", topology)
		}
	}

	// Second pass: process all fields
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "ifconfig ") {
			// topology subnet: "ifconfig <client_ip> <netmask>"  → prefix = ip/bits(mask)
			// topology net30:  "ifconfig <client_ip> <peer_ip>"  → prefix = ip/30
			// topology p2p:    "ifconfig <client_ip> <peer_ip>"  → prefix = ip/32
			args := strings.Fields(part)
			if len(args) >= 3 {
				addr, err := netip.ParseAddr(args[1])
				if err != nil {
					continue
				}
				c.cfg.IP = addr

				var prefix netip.Prefix
				if topology == "subnet" {
					// args[2] is a dotted netmask, convert to CIDR bits
					maskIP, maskErr := netip.ParseAddr(args[2])
					if maskErr == nil && maskIP.Is4() {
						m4 := maskIP.As4()
						bits := 0
						for _, b := range m4 {
							for b != 0 {
								bits += int(b & 1)
								b >>= 1
							}
						}
						prefix = netip.PrefixFrom(addr, bits)
					} else {
						prefix = netip.PrefixFrom(addr, 24) // fallback
					}
				} else {
					// net30 or p2p: use /30 or /32 respectively
					prefixLen := 30
					if topology == "p2p" {
						prefixLen = 32
					}
					prefix = netip.PrefixFrom(addr, prefixLen)
				}
				c.cfg.Mask = prefix
				log.Infoln("[OpenVPN] Pushed IP: %s (arg2: %s), topology=%s, TUN prefix: %s", args[1], args[2], topology, prefix)
			}
		} else if strings.HasPrefix(part, "topology ") {
			// already handled in first pass
		} else if strings.HasPrefix(part, "mtu ") {
			fmt.Sscanf(part, "mtu %d", &c.cfg.MTU)
			log.Infoln("[OpenVPN] Pushed MTU: %d", c.cfg.MTU)
		} else if strings.HasPrefix(part, "cipher ") {
			c.cfg.Cipher = strings.TrimPrefix(part, "cipher ")
			log.Infoln("[OpenVPN] Pushed cipher: %s", c.cfg.Cipher)
		} else if strings.HasPrefix(part, "peer-id ") {
			fmt.Sscanf(part, "peer-id %d", &c.peerID)
			log.Infoln("[OpenVPN] Pushed peer-id: %d", c.peerID)
		} else if strings.HasPrefix(part, "dhcp-option DNS ") {
			dns := strings.TrimPrefix(part, "dhcp-option DNS ")
			dns = strings.TrimSpace(dns)
			c.cfg.DNS = append(c.cfg.DNS, dns)
			log.Infoln("[OpenVPN] Pushed DNS server: %s", dns)
		} else if strings.HasPrefix(part, "route ") {
			log.Infoln("[OpenVPN] Pushed route: %s", strings.TrimPrefix(part, "route "))
		} else if strings.HasPrefix(part, "route-delay ") {
			// "route-delay <wait_secs> [<timeout_secs>]"
			// Wait wait_secs before data channel is usable
			args := strings.Fields(part)
			if len(args) >= 2 {
				delay := 0
				fmt.Sscanf(args[1], "%d", &delay)
				if delay > 0 && delay < 30 {
					c.routeDelay = delay
				}
			}
			log.Infoln("[OpenVPN] Pushed route-delay: %s", strings.TrimPrefix(part, "route-delay "))
		} else if strings.HasPrefix(part, "ping ") || strings.HasPrefix(part, "ping-restart ") {
			log.Debugln("[OpenVPN] Pushed keepalive: %s", part)
		}
	}
	return nil
}
