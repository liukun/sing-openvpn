package openvpn

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/airofm/sing-openvpn/internal/log"
	"github.com/airofm/sing-openvpn/internal/packet"
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65536)
		return &b
	},
}

func (c *Client) sendReset() error {
	p := &packet.Packet{
		Opcode:    packet.OpControlHardResetClientV2,
		SessionID: c.localSID,
		PacketID:  c.getNextPacketID(),
	}
	return c.writePacket(p)
}

func (c *Client) sendAck(packetID uint32) error {
	p := &packet.Packet{
		Opcode:    packet.OpAckV1,
		SessionID: c.localSID,
		RemoteSID: c.remoteSID,
		Acks:      []uint32{packetID},
	}
	return c.writePacket(p)
}

func (c *Client) readLoop() {
	log.Infoln("[OpenVPN] readLoop started")
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	// Pre-allocate the length buffer for TCP to avoid per-packet allocation
	lenBuf := make([]byte, 2)

	for {
		var data []byte
		var err error
		conn := c.conn
		if conn == nil {
			c.errChan <- fmt.Errorf("connection is nil")
			return
		}

		// Clear any previously set deadline
		conn.SetReadDeadline(time.Time{})

		if !c.isUDP() {
			// TCP: 2-byte length header
			_, err = io.ReadFull(conn, lenBuf)
			if err != nil {
				log.Warnln("[OpenVPN] readLoop TCP read error: %v", err)
				c.errChan <- err
				return
			}
			length := binary.BigEndian.Uint16(lenBuf)
			if int(length) > len(buf) {
				// Prevent buffer overflow on invalid large packet length
				log.Warnln("[OpenVPN] TCP packet length %d exceeds max buffer size", length)
				c.errChan <- fmt.Errorf("TCP packet too large")
				return
			}
			data = buf[:length]
			_, err = io.ReadFull(conn, data)
		} else {
			// UDP: full packet
			n, errRead := conn.Read(buf)
			if errRead != nil {
				log.Warnln("[OpenVPN] readLoop UDP read error: %v", errRead)
				c.errChan <- errRead
				return
			}
			data = buf[:n]
		}

		if err != nil {
			c.errChan <- err
			return
		}

		log.Traceln("[OpenVPN] Received raw packet: len=%d, first_byte=%02x opcode=%d", len(data), data[0], data[0]>>3)

		// Control channel protection (tls-auth / tls-crypt)
		if c.controlProtector != nil {
			// Data packets (packet.OpDataV1/V2) are NOT wrapped.
			// Only control packets are wrapped.
			isData := false
			if len(data) > 0 {
				opcode := data[0] >> 3
				if opcode == packet.OpDataV1 || opcode == packet.OpDataV2 {
					isData = true
				}
			}

			if !isData {
				unwrapped, err := c.controlProtector.Unwrap(data)
				if err == nil {
					data = unwrapped
				} else {
					log.Debugln("[OpenVPN] Failed to unwrap control packet: %v", err)
				}
			}
		}

		packet, err := packet.DecodePacket(data)
		if err != nil {
			log.Warnln("[OpenVPN] Decode packet error: %v", err)
			continue
		}

		c.handlePacket(packet)
		packet.PutPacket()
	}
}

func (c *Client) writePacket(p *packet.Packet) error {
	data := p.Encode()
	if log.IsTraceEnabled() {
		log.Traceln("[OpenVPN] Writing packet: %s, session ID: %x, packet ID: %d, len=%d", packet.OpcodeToString(p.Opcode), p.SessionID, p.PacketID, len(data))
		if (p.Opcode == packet.OpDataV1 || p.Opcode == packet.OpDataV2) && len(data) > 0 {
			dumpLen := 40
			if len(data) < dumpLen {
				dumpLen = len(data)
			}
			log.Traceln("[OpenVPN] DATA packet hex: %s", hex.EncodeToString(data[:dumpLen]))
		}
	}

	// Control channel protection (tls-auth / tls-crypt)
	if p.Opcode != packet.OpDataV1 && p.Opcode != packet.OpDataV2 && c.controlProtector != nil {
		var err error
		data, err = c.controlProtector.Wrap(data)
		if err != nil {
			return err
		}
	}

	var err error
	if !c.isUDP() {
		// TCP: prepend 2-byte length
		tcpData := make([]byte, 2+len(data))
		binary.BigEndian.PutUint16(tcpData[0:2], uint16(len(data)))
		copy(tcpData[2:], data)
		_, err = c.conn.Write(tcpData)
	} else {
		_, err = c.conn.Write(data)
	}
	if err == nil {
		atomic.StoreInt64(&c.lastSend, time.Now().Unix())
	}
	return err
}

func (c *Client) handlePacket(p *packet.Packet) {
	c.updateActivity()
	if log.IsTraceEnabled() {
		log.Traceln("[OpenVPN] Received packet: %s, session ID: %x, packet ID: %d", packet.OpcodeToString(p.Opcode), p.SessionID, p.PacketID)
	}

	// Process ACKs for all control packets
	if p.Opcode != packet.OpDataV1 && p.Opcode != packet.OpDataV2 {
		for _, ack := range p.Acks {
			if chI, ok := c.ackWaiters.Load(ack); ok {
				ch := chI.(chan struct{})
				select {
				case <-ch: // already closed
				default:
					close(ch)
				}
				c.ackWaiters.Delete(ack)
			}
		}
	}

	switch p.Opcode {
	case packet.OpControlHardResetServerV1, packet.OpControlHardResetServerV2:
		log.Infoln("[OpenVPN] Received Server Hard Reset (%s), session ID: %x", packet.OpcodeToString(p.Opcode), p.SessionID)
		c.remoteSID = p.SessionID
		select {
		case c.handshakeStarted <- struct{}{}:
		default:
		}
		c.sendAck(p.PacketID)
	case packet.OpControlV1:
		// TLS data, feed into ControlConn
		// We MUST send an ACK for control packets
		c.sendAck(p.PacketID)
		c.controlConn.FeedData(p.Payload)
	case packet.OpAckV1:
		log.Traceln("[OpenVPN] Received ACK for packet ID: %v", p.Acks)
	case packet.OpDataV1, packet.OpDataV2:
		// Data channel
		// Pass to dataChan for tunWriteLoop to handle
		log.Traceln("[OpenVPN] Received data packet: opcode=%d len=%d", p.Opcode, len(p.Payload))
		c.processIncomingData(p.Payload)
	}
}
