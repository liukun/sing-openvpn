package openvpn

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// --- helpers ---

// newTestClient creates a minimal Client for unit testing (no real connection).
func newTestClient() *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		cfg: &Config{
			Remotes: []Remote{{Server: "127.0.0.1", Port: 1194, UDP: true}},
		},
		handshakeStarted: make(chan struct{}, 1),
		errChan:          make(chan error, 10),
		ctx:              ctx,
		cancel:           cancel,
	}
	c.controlConn = NewControlConn(c)
	return c
}

// --- IsAlive / Close tests ---

func TestIsAlive_InitiallyDead(t *testing.T) {
	c := newTestClient()
	defer c.cancel()

	if c.IsAlive() {
		t.Fatal("new client should not be alive before Dial")
	}
}

func TestIsAlive_AfterSetAlive(t *testing.T) {
	c := newTestClient()
	defer c.cancel()

	atomic.StoreInt32(&c.alive, 1)
	if !c.IsAlive() {
		t.Fatal("client should be alive after setting alive=1")
	}
}

func TestClose_SetsDeadAndInvokesCallback(t *testing.T) {
	c := newTestClient()
	atomic.StoreInt32(&c.alive, 1)

	callbackCalled := make(chan struct{}, 1)
	c.SetOnClose(func() {
		callbackCalled <- struct{}{}
	})

	err := c.Close()
	if err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}

	if c.IsAlive() {
		t.Fatal("client should be dead after Close()")
	}

	select {
	case <-callbackCalled:
		// ok
	case <-time.After(1 * time.Second):
		t.Fatal("onClose callback was not invoked")
	}
}

func TestClose_Idempotent(t *testing.T) {
	c := newTestClient()
	atomic.StoreInt32(&c.alive, 1)

	callCount := int32(0)
	c.SetOnClose(func() {
		atomic.AddInt32(&callCount, 1)
	})

	// Close twice
	c.Close()
	c.Close()

	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(&callCount) != 1 {
		t.Fatalf("onClose callback should be called exactly once, got %d", callCount)
	}
}

// --- errorMonitor tests ---

func TestErrorMonitor_ClosesOnError(t *testing.T) {
	c := newTestClient()
	atomic.StoreInt32(&c.alive, 1)

	closeCalled := make(chan struct{}, 1)
	c.SetOnClose(func() {
		closeCalled <- struct{}{}
	})

	go c.errorMonitor()

	// Send a fatal error
	c.errChan <- fmt.Errorf("connection reset")

	select {
	case <-closeCalled:
		// errorMonitor detected the error and closed
	case <-time.After(2 * time.Second):
		t.Fatal("errorMonitor did not close the client on error")
	}

	if c.IsAlive() {
		t.Fatal("client should be dead after errorMonitor handles error")
	}
}

func TestErrorMonitor_StopsOnContextCancel(t *testing.T) {
	c := newTestClient()
	atomic.StoreInt32(&c.alive, 1)

	done := make(chan struct{})
	go func() {
		c.errorMonitor()
		close(done)
	}()

	c.cancel()

	select {
	case <-done:
		// errorMonitor exited
	case <-time.After(2 * time.Second):
		t.Fatal("errorMonitor did not exit on context cancellation")
	}
}

// --- pingLoop tests ---

func TestPingLoop_TimeoutDetection(t *testing.T) {
	c := newTestClient()
	c.pingInterval = 1 // 1s tick for fast test
	c.pingTimeout = 3  // 3s timeout
	atomic.StoreInt32(&c.alive, 1)

	done := make(chan struct{})
	go func() {
		c.pingLoop()
		close(done)
	}()

	// Wait for pingLoop to init, then force lastActivity to be stale
	time.Sleep(100 * time.Millisecond)
	atomic.StoreInt64(&c.lastActivity, time.Now().Unix()-5) // 5s stale, exceeds 3s timeout

	select {
	case err := <-c.errChan:
		if err == nil || err.Error() != "ping timeout" {
			t.Fatalf("expected ping timeout error, got: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pingLoop did not detect timeout within expected time")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pingLoop did not exit after timeout")
	}
}

func TestPingLoop_StopsOnContextCancel(t *testing.T) {
	c := newTestClient()
	c.pingInterval = 10
	c.pingTimeout = 60
	c.updateActivity()

	done := make(chan struct{})
	go func() {
		c.pingLoop()
		close(done)
	}()

	// Cancel context
	c.cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pingLoop did not exit on context cancellation")
	}
}

// --- Dial tests ---

func TestDial_NoRemotes(t *testing.T) {
	c := newTestClient()
	c.cfg.Remotes = nil
	defer c.cancel()

	err := c.Dial(context.Background())
	if err == nil {
		t.Fatal("expected error for no remotes")
	}
	if err.Error() != "no remotes configured" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDial_SingleRemote_UnreachableServer(t *testing.T) {
	c := newTestClient()
	c.cfg.Remotes = []Remote{{Server: "192.0.2.1", Port: 9999, UDP: false}} // TEST-NET, unreachable
	defer c.cancel()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := c.Dial(ctx)
	if err == nil {
		t.Fatal("expected error connecting to unreachable server")
	}
}

func TestDial_MultipleRemotes_AllUnreachable(t *testing.T) {
	c := newTestClient()
	c.cfg.Remotes = []Remote{
		{Server: "192.0.2.1", Port: 9999, UDP: false},
		{Server: "192.0.2.2", Port: 9999, UDP: false},
		{Server: "192.0.2.3", Port: 9999, UDP: false},
	}
	defer c.cancel()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	start := time.Now()
	err := c.Dial(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error connecting to all unreachable servers")
	}

	// With parallel connection, all 3 should fail roughly at the same time
	// (within the context timeout), not 3x sequential
	if elapsed > 10*time.Second {
		t.Fatalf("parallel dial took too long: %v (should be < 10s for parallel)", elapsed)
	}
	t.Logf("parallel dial to 3 unreachable remotes took %v", elapsed)
}

// --- SetOnClose tests ---

func TestSetOnClose_NilSafe(t *testing.T) {
	c := newTestClient()
	atomic.StoreInt32(&c.alive, 1)
	// No onClose set - should not panic
	err := c.Close()
	if err != nil {
		t.Fatalf("Close() with nil onClose should not error: %v", err)
	}
}

// --- updateActivity tests ---

func TestUpdateActivity(t *testing.T) {
	c := newTestClient()
	defer c.cancel()

	before := time.Now().Unix()
	c.updateActivity()
	after := time.Now().Unix()

	activity := atomic.LoadInt64(&c.lastActivity)
	if activity < before || activity > after {
		t.Fatalf("lastActivity %d not in range [%d, %d]", activity, before, after)
	}
}

// --- processIncomingData tests ---
// These use cipher=nil (plaintext passthrough) to test the data path logic.

func TestProcessIncomingData_NonIPDropped(t *testing.T) {
	c := newTestClient()
	defer c.cancel()

	// Payload from the real crash: starts with 0x00 (IP version 0), not valid IP
	payload := []byte{
		0x00, 0x00, 0x00, 0x01, 0x5b, 0x68, 0x90, 0xe6,
		0x43, 0x0e, 0x0d, 0xf0, 0xf1, 0x39, 0xdb, 0x1c,
		0xa7, 0xed, 0x08, 0x82, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	// Must not panic (was a nil pointer crash before fix)
	c.processIncomingData(payload)
}

func TestProcessIncomingData_TUNNilSafe(t *testing.T) {
	c := newTestClient()
	defer c.cancel()
	// tunDevice is nil — valid IPv4 packet should be dropped gracefully, not panic

	// Minimal IPv4 packet (20 bytes header, src=10.0.0.1, dst=10.0.0.2)
	ipv4 := make([]byte, 40)
	ipv4[0] = 0x45 // IPv4, IHL=5
	ipv4[12], ipv4[13], ipv4[14], ipv4[15] = 10, 0, 0, 1
	ipv4[16], ipv4[17], ipv4[18], ipv4[19] = 10, 0, 0, 2

	c.processIncomingData(ipv4)
}

func TestProcessIncomingData_EmptyPayload(t *testing.T) {
	c := newTestClient()
	defer c.cancel()

	// Empty plaintext should not panic
	c.processIncomingData([]byte{})
}
