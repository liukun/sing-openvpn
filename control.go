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

// ControlConn implements net.Conn over the OpenVPN reliable control channel,
// bound to a single session. Each session has its own instance.
type ControlConn struct {
	sess *session

	readBuffer   []byte
	readMu       sync.Mutex
	readCond     *sync.Cond
	closed       bool
	readDeadline time.Time

	writeMu sync.Mutex
}

func newControlConn(sess *session) *ControlConn {
	c := &ControlConn{sess: sess}
	c.readCond = sync.NewCond(&c.readMu)
	return c
}

func (c *ControlConn) Read(b []byte) (n int, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuffer) == 0 && !c.closed {
		if !c.readDeadline.IsZero() {
			remaining := time.Until(c.readDeadline)
			if remaining <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer := time.AfterFunc(remaining, func() { c.readCond.Broadcast() })
			c.readCond.Wait()
			timer.Stop()
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
	if c.sess.controlProtector != nil {
		protectorOverhead = c.sess.controlProtector.Overhead()
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
			SessionID: c.sess.localSID,
			PacketID:  c.sess.getNextPacketID(),
			Payload:   fragment,
		}

		ackCh := make(chan struct{})
		c.sess.ackWaiters.Store(p.PacketID, ackCh)

		sent := false
		for attempt := 0; attempt < 5; attempt++ {
			if err := c.sess.writePacket(p); err != nil {
				c.sess.ackWaiters.Delete(p.PacketID)
				return offset, err
			}
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			if backoff > 8*time.Second {
				backoff = 8 * time.Second
			}
			select {
			case <-ackCh:
				sent = true
				goto Acked
			case <-time.After(backoff):
			}
		}
	Acked:
		if !sent {
			c.sess.ackWaiters.Delete(p.PacketID)
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

func (c *ControlConn) LocalAddr() net.Addr  { return c.sess.conn.LocalAddr() }
func (c *ControlConn) RemoteAddr() net.Addr { return c.sess.conn.RemoteAddr() }

func (c *ControlConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *ControlConn) SetReadDeadline(t time.Time) error {
	c.readMu.Lock()
	c.readDeadline = t
	c.readCond.Broadcast()
	c.readMu.Unlock()
	return nil
}

func (c *ControlConn) SetWriteDeadline(t time.Time) error { return nil }

// FeedData is called by the session's read loop when an OpControlV1 packet arrives.
func (c *ControlConn) FeedData(data []byte) {
	c.readMu.Lock()
	c.readBuffer = append(c.readBuffer, data...)
	c.readCond.Signal()
	c.readMu.Unlock()
}
