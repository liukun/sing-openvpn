package openvpn

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/airofm/sing-openvpn/internal/packet"
)

// ControlConn implements net.Conn to provide a reliable stream over OpenVPN control channel
type ControlConn struct {
	client       *Client
	readBuffer   []byte
	readMu       sync.Mutex
	readCond     *sync.Cond
	closed       bool
	readDeadline time.Time // zero = no deadline

	writeMu sync.Mutex
}

func NewControlConn(client *Client) *ControlConn {
	c := &ControlConn{
		client: client,
	}
	c.readCond = sync.NewCond(&c.readMu)
	return c
}

func (c *ControlConn) Read(b []byte) (n int, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuffer) == 0 && !c.closed {
		// Check deadline before waiting
		if !c.readDeadline.IsZero() {
			remaining := time.Until(c.readDeadline)
			if remaining <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			// Use a timer to wake us up when the deadline expires
			timer := time.AfterFunc(remaining, func() {
				c.readCond.Broadcast()
			})
			c.readCond.Wait()
			timer.Stop()
			// Re-check deadline after waking
			if len(c.readBuffer) == 0 && !c.closed && !c.readDeadline.IsZero() && time.Now().After(c.readDeadline) {
				return 0, os.ErrDeadlineExceeded
			}
		} else {
			c.readCond.Wait()
		}
	}

	if c.closed && len(c.readBuffer) == 0 {
		return 0, io.EOF
	}

	n = copy(b, c.readBuffer)
	c.readBuffer = c.readBuffer[n:]
	return n, nil
}

func (c *ControlConn) Write(b []byte) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.closed {
		return 0, errors.New("connection closed")
	}

	// Fragment large TLS messages to avoid IP fragmentation.
	// Each control packet has overhead: opcode(1)+session_id(8)+ack(1)+packet_id(4)=14 bytes
	// plus controlProtector overhead (tls-crypt: 40B, tls-auth: 28B+).
	// Stay under ~1400 bytes UDP payload (safe for most paths).
	protectorOverhead := 0
	if c.client.controlProtector != nil {
		protectorOverhead = c.client.controlProtector.Overhead()
	}
	maxPayload := 1400 - 14 - protectorOverhead

	for offset := 0; offset < len(b); offset += maxPayload {
		end := offset + maxPayload
		if end > len(b) {
			end = len(b)
		}
		fragment := make([]byte, end-offset)
		copy(fragment, b[offset:end])

		p := &packet.Packet{
			Opcode:    packet.OpControlV1,
			SessionID: c.client.localSID,
			PacketID:  c.client.getNextPacketID(),
			Payload:   fragment,
		}

		ackCh := make(chan struct{})
		c.client.ackWaiters.Store(p.PacketID, ackCh)

		sent := false
		for attempt := 0; attempt < 5; attempt++ {
			if err := c.client.writePacket(p); err != nil {
				c.client.ackWaiters.Delete(p.PacketID)
				return offset, err
			}

			// Wait for ACK with exponential backoff: 1s, 2s, 4s, 8s, 8s
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			if backoff > 8*time.Second {
				backoff = 8 * time.Second
			}
			select {
			case <-ackCh:
				sent = true
				goto Acked
			case <-time.After(backoff):
				// Timeout, will retry in next loop iteration
			}
		}
	Acked:
		if !sent {
			c.client.ackWaiters.Delete(p.PacketID)
			return offset, errors.New("control packet reliable send failed: timeout")
		}
	}

	return len(b), nil
}

func (c *ControlConn) Close() error {
	c.readMu.Lock()
	c.closed = true
	c.readCond.Broadcast()
	c.readMu.Unlock()
	return nil
}

func (c *ControlConn) LocalAddr() net.Addr {
	return c.client.conn.LocalAddr()
}

func (c *ControlConn) RemoteAddr() net.Addr {
	return c.client.conn.RemoteAddr()
}

func (c *ControlConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *ControlConn) SetReadDeadline(t time.Time) error {
	c.readMu.Lock()
	c.readDeadline = t
	c.readCond.Broadcast() // wake any waiting Read so it can re-check
	c.readMu.Unlock()
	return nil
}

func (c *ControlConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// FeedData is called by the client's read loop when an packet.OpControlV1 packet is received
func (c *ControlConn) FeedData(data []byte) {
	c.readMu.Lock()
	c.readBuffer = append(c.readBuffer, data...)
	c.readCond.Signal()
	c.readMu.Unlock()
}
