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

func (s *session) sendReset() error {
	p := &packet.Packet{
		Opcode:    packet.OpControlHardResetClientV2,
		SessionID: s.localSID,
		PacketID:  s.getNextPacketID(),
	}
	return s.writePacket(p)
}

func (s *session) sendAck(packetID uint32) error {
	p := &packet.Packet{
		Opcode:    packet.OpAckV1,
		SessionID: s.localSID,
		RemoteSID: s.remoteSID,
		Acks:      []uint32{packetID},
	}
	return s.writePacket(p)
}

func (s *session) readLoop() {
	log.Infoln("[OpenVPN] readLoop started")
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	lenBuf := make([]byte, 2)

	for {
		var data []byte
		var err error
		conn := s.conn
		if conn == nil {
			s.errChan <- fmt.Errorf("connection is nil")
			return
		}
		conn.SetReadDeadline(time.Time{})

		if !s.isUDP() {
			_, err = io.ReadFull(conn, lenBuf)
			if err != nil {
				log.Warnln("[OpenVPN] readLoop TCP read error: %v", err)
				s.errChan <- err
				return
			}
			length := binary.BigEndian.Uint16(lenBuf)
			if int(length) > len(buf) {
				log.Warnln("[OpenVPN] TCP packet length %d exceeds max buffer size", length)
				s.errChan <- fmt.Errorf("TCP packet too large")
				return
			}
			data = buf[:length]
			_, err = io.ReadFull(conn, data)
		} else {
			n, errRead := conn.Read(buf)
			if errRead != nil {
				log.Warnln("[OpenVPN] readLoop UDP read error: %v", errRead)
				s.errChan <- errRead
				return
			}
			data = buf[:n]
		}

		if err != nil {
			s.errChan <- err
			return
		}

		log.Traceln("[OpenVPN] Received raw packet: len=%d, first_byte=%02x opcode=%d", len(data), data[0], data[0]>>3)

		if s.controlProtector != nil {
			isData := false
			if len(data) > 0 {
				opcode := data[0] >> 3
				if opcode == packet.OpDataV1 || opcode == packet.OpDataV2 {
					isData = true
				}
			}
			if !isData {
				unwrapped, err := s.controlProtector.Unwrap(data)
				if err == nil {
					data = unwrapped
				} else {
					log.Debugln("[OpenVPN] Failed to unwrap control packet: %v", err)
				}
			}
		}

		p, err := packet.DecodePacket(data)
		if err != nil {
			log.Warnln("[OpenVPN] Decode packet error: %v", err)
			continue
		}
		s.handlePacket(p)
		p.PutPacket()
	}
}

func (s *session) writePacket(p *packet.Packet) error {
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

	if p.Opcode != packet.OpDataV1 && p.Opcode != packet.OpDataV2 && s.controlProtector != nil {
		var err error
		data, err = s.controlProtector.Wrap(data)
		if err != nil {
			return err
		}
	}

	var err error
	if !s.isUDP() {
		tcpData := make([]byte, 2+len(data))
		binary.BigEndian.PutUint16(tcpData[0:2], uint16(len(data)))
		copy(tcpData[2:], data)
		_, err = s.conn.Write(tcpData)
	} else {
		_, err = s.conn.Write(data)
	}
	if err == nil {
		atomic.StoreInt64(&s.lastSend, time.Now().Unix())
	}
	return err
}

func (s *session) handlePacket(p *packet.Packet) {
	s.updateActivity()
	if log.IsTraceEnabled() {
		log.Traceln("[OpenVPN] Received packet: %s, session ID: %x, packet ID: %d", packet.OpcodeToString(p.Opcode), p.SessionID, p.PacketID)
	}

	if p.Opcode != packet.OpDataV1 && p.Opcode != packet.OpDataV2 {
		for _, ack := range p.Acks {
			if chI, ok := s.ackWaiters.Load(ack); ok {
				ch := chI.(chan struct{})
				select {
				case <-ch:
				default:
					close(ch)
				}
				s.ackWaiters.Delete(ack)
			}
		}
	}

	switch p.Opcode {
	case packet.OpControlHardResetServerV1, packet.OpControlHardResetServerV2:
		log.Infoln("[OpenVPN] Received Server Hard Reset (%s), session ID: %x", packet.OpcodeToString(p.Opcode), p.SessionID)
		s.remoteSID = p.SessionID
		select {
		case s.handshakeStarted <- struct{}{}:
		default:
		}
		s.sendAck(p.PacketID)
	case packet.OpControlV1:
		s.sendAck(p.PacketID)
		s.controlConn.FeedData(p.Payload)
	case packet.OpAckV1:
		log.Traceln("[OpenVPN] Received ACK for packet ID: %v", p.Acks)
	case packet.OpDataV1, packet.OpDataV2:
		log.Traceln("[OpenVPN] Received data packet: opcode=%d len=%d", p.Opcode, len(p.Payload))
		s.processIncomingData(p.Payload)
	}
}
