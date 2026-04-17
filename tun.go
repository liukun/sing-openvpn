package openvpn

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sync/atomic"

	"github.com/airofm/sing-openvpn/internal/log"
	"github.com/airofm/sing-openvpn/internal/packet"
)

func (s *session) tunReadLoop() {
	log.Infoln("[OpenVPN] tunReadLoop started")

	const batchSize = 32
	bufPtrs := make([]*[]byte, batchSize)
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufPtrs {
		bufPtrs[i] = bufPool.Get().(*[]byte)
		bufs[i] = *bufPtrs[i]
	}
	defer func() {
		for _, p := range bufPtrs {
			bufPool.Put(p)
		}
	}()

	for {
		n, err := s.tunDevice.Read(bufs, sizes, 0)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Errorln("[OpenVPN] TUN Read error: %v", err)
				return
			}
		}

		for i := 0; i < n; i++ {
			plaintext := bufs[i][:sizes[i]]
			var ciphertext []byte
			var errEnc error

			if s.cipher != nil {
				ciphertext, errEnc = s.cipher.Encrypt(plaintext, s.dataAD)
			} else {
				ciphertext = plaintext
			}
			if errEnc != nil {
				log.Warnln("[OpenVPN] TUN encrypt error: %v (len=%d)", errEnc, len(plaintext))
				continue
			}

			atomic.AddUint64(&s.bytesSent, uint64(sizes[i]))
			log.Traceln("[OpenVPN] TUN read %d bytes, encrypted to %d bytes", sizes[i], len(ciphertext))
			p := &packet.Packet{
				Opcode:  s.dataOpcode,
				PeerID:  s.peerID,
				Payload: ciphertext,
			}
			if err := s.writePacket(p); err != nil {
				// Surface so errorMonitor tears the session down.
				select {
				case <-s.ctx.Done():
				case s.errChan <- fmt.Errorf("tun->peer write: %w", err):
				}
				return
			}
		}
	}
}

func (s *session) processIncomingData(data []byte) {
	var plaintext []byte
	var errDec error

	if s.cipher != nil {
		plaintext, errDec = s.cipher.Decrypt(data, s.dataAD)
	} else {
		plaintext = data
	}
	if errDec != nil {
		dumpLen := 40
		if len(data) < dumpLen {
			dumpLen = len(data)
		}
		log.Warnln("[OpenVPN] Data decrypt error: %v (len=%d, hex=%s)", errDec, len(data), hex.EncodeToString(data[:dumpLen]))
		return
	}

	log.Traceln("[OpenVPN] TUN write: %d bytes plaintext", len(plaintext))

	if len(plaintext) == 16 && bytes.Equal(plaintext, pingMagic) {
		atomic.AddUint64(&s.pingsReceived, 1)
		log.Traceln("[OpenVPN] Received OpenVPN ping")
		return
	}
	if len(plaintext) == 0 {
		return
	}

	ipVer := plaintext[0] >> 4
	if ipVer != 4 && ipVer != 6 {
		if log.IsTraceEnabled() {
			log.Traceln("[OpenVPN] Dropping non-IP payload (ver=%d, len=%d, hex=%s)",
				ipVer, len(plaintext), hex.EncodeToString(plaintext[:min(len(plaintext), 20)]))
		}
		return
	}
	if s.tunDevice == nil {
		log.Debugln("[OpenVPN] TUN not ready, dropping %d byte packet", len(plaintext))
		return
	}

	if log.IsTraceEnabled() && ipVer == 4 && len(plaintext) >= 20 {
		srcIP := fmt.Sprintf("%d.%d.%d.%d", plaintext[12], plaintext[13], plaintext[14], plaintext[15])
		dstIP := fmt.Sprintf("%d.%d.%d.%d", plaintext[16], plaintext[17], plaintext[18], plaintext[19])
		log.Traceln("[OpenVPN] Decrypted IP in: src=%s dst=%s len=%d", srcIP, dstIP, len(plaintext))
		proto := plaintext[9]
		ipHdrLen := int(plaintext[0]&0x0f) * 4
		if proto == 17 && len(plaintext) >= ipHdrLen+4 {
			srcPort := uint16(plaintext[ipHdrLen])<<8 | uint16(plaintext[ipHdrLen+1])
			if srcPort == 53 {
				log.Traceln("[OpenVPN] DNS response in: src=%s:%d dst=%s len=%d", srcIP, srcPort, dstIP, len(plaintext))
			}
		}
	}

	atomic.AddUint64(&s.bytesReceived, uint64(len(plaintext)))
	if _, err := s.tunDevice.Write([][]byte{plaintext}, 0); err != nil {
		log.Warnln("[OpenVPN] TUN write failed: %v (len=%d)", err, len(plaintext))
		// Surface to errorMonitor so a broken TUN tears the session down
		// instead of silently losing every inbound packet. Non-blocking so a
		// full errChan (fatal error already in flight) or a canceled session
		// can't stall the data plane.
		select {
		case s.errChan <- fmt.Errorf("peer->tun write: %w", err):
		case <-s.ctx.Done():
		default:
		}
	}
}
