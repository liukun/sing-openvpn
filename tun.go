package openvpn

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sync/atomic"

	"github.com/airofm/sing-openvpn/internal/log"
	"github.com/airofm/sing-openvpn/internal/packet"
)

func (c *Client) tunReadLoop() {
	log.Infoln("[OpenVPN] tunReadLoop started")

	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	bufs := [][]byte{buf}
	sizes := []int{0}

	for {
		batchSize := 32
		if len(bufs) < batchSize {
			for i := len(bufs); i < batchSize; i++ {
				b := bufPool.Get().(*[]byte)
				bufs = append(bufs, *b)
				sizes = append(sizes, 0)
			}
		}

		n, err := c.tunDevice.Read(bufs, sizes, 0)
		if err != nil {
			select {
			case <-c.ctx.Done():
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

			if c.cipher != nil {
				ciphertext, errEnc = c.cipher.Encrypt(plaintext, c.dataAD)
			} else {
				ciphertext = plaintext
			}

			if errEnc != nil {
				log.Warnln("[OpenVPN] TUN encrypt error: %v (len=%d)", errEnc, len(plaintext))
				continue
			}

			atomic.AddUint64(&c.bytesSent, uint64(sizes[i]))
			log.Traceln("[OpenVPN] TUN read %d bytes, encrypted to %d bytes", sizes[i], len(ciphertext))
			p := &packet.Packet{
				Opcode:  c.dataOpcode,
				PeerID:  c.peerID,
				Payload: ciphertext,
			}
			c.writePacket(p)
		}
	}
}

func (c *Client) processIncomingData(data []byte) {
	var plaintext []byte
	var errDec error

	if c.cipher != nil {
		plaintext, errDec = c.cipher.Decrypt(data, c.dataAD)
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
		atomic.AddUint64(&c.pingsReceived, 1)
		log.Traceln("[OpenVPN] Received OpenVPN ping")
		return
	}

	if len(plaintext) == 0 {
		return
	}

	// Only inject valid IP packets into the TUN stack.
	ipVer := plaintext[0] >> 4
	if ipVer != 4 && ipVer != 6 {
		if log.IsTraceEnabled() {
			log.Traceln("[OpenVPN] Dropping non-IP payload (ver=%d, len=%d, hex=%s)",
				ipVer, len(plaintext), hex.EncodeToString(plaintext[:min(len(plaintext), 20)]))
		}
		return
	}

	if c.tunDevice == nil {
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

	atomic.AddUint64(&c.bytesReceived, uint64(len(plaintext)))
	c.tunDevice.Write([][]byte{plaintext}, 0)
}
