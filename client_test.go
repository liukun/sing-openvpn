package openvpn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/airofm/sing-openvpn/internal/packet"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/wireguard-go/tun"
)

// newTestClient builds a Client with just enough state for unit tests that
// don't touch the network: it has a non-nil cfg with one remote, and a
// cancelable ctx. Tests that need a session go through newTestSession.
func newTestClient() *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		cfg: &Config{
			Remotes: []Remote{{Server: "127.0.0.1", Port: 1194, UDP: true}},
		},
		ctx:    ctx,
		cancel: cancel,
	}
}

// newTestSession builds a session (and its owning client) without dialing
// anything. Used to exercise session-level code paths in isolation.
func newTestSession() *session {
	c := newTestClient()
	return c.newSession(c.cfg.Remotes[0])
}

// attachLiveSession builds a session, marks it alive, and publishes it as
// active — the minimal state setup a fully-connected Client would have.
func (c *Client) attachLiveSession() *session {
	s := c.newSession(c.cfg.Remotes[0])
	atomic.StoreInt32(&s.alive, 1)
	c.active.Store(s)
	return s
}

// --- IsAlive / Close tests ---

func TestIsAlive_InitiallyDead(t *testing.T) {
	c := newTestClient()
	defer c.cancel()

	if c.IsAlive() {
		t.Fatal("new client should not be alive before Dial")
	}
}

func TestIsAlive_AfterSessionAlive(t *testing.T) {
	c := newTestClient()
	defer c.cancel()

	s := c.newSession(c.cfg.Remotes[0])
	atomic.StoreInt32(&s.alive, 1)
	c.active.Store(s)

	if !c.IsAlive() {
		t.Fatal("client should report alive when active session is alive")
	}
}

func TestClose_SetsDeadAndInvokesCallback(t *testing.T) {
	c := newTestClient()
	s := c.newSession(c.cfg.Remotes[0])
	atomic.StoreInt32(&s.alive, 1)
	c.active.Store(s)

	callbackCalled := make(chan struct{}, 1)
	c.SetOnClose(func() { callbackCalled <- struct{}{} })

	if err := c.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
	if c.IsAlive() {
		t.Fatal("client should be dead after Close()")
	}
	select {
	case <-callbackCalled:
	case <-time.After(1 * time.Second):
		t.Fatal("onClose callback was not invoked")
	}
}

func TestClose_Idempotent(t *testing.T) {
	c := newTestClient()
	s := c.newSession(c.cfg.Remotes[0])
	atomic.StoreInt32(&s.alive, 1)
	c.active.Store(s)

	var callCount int32
	c.SetOnClose(func() { atomic.AddInt32(&callCount, 1) })

	c.Close()
	c.Close()

	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&callCount); got != 1 {
		t.Fatalf("onClose callback should fire exactly once, got %d", got)
	}
}

// --- errorMonitor tests ---

func TestErrorMonitor_ClosesOnError(t *testing.T) {
	c := newTestClient()
	s := c.newSession(c.cfg.Remotes[0])
	atomic.StoreInt32(&s.alive, 1)
	c.active.Store(s)

	closeCalled := make(chan struct{}, 1)
	c.SetOnClose(func() { closeCalled <- struct{}{} })

	go s.errorMonitor()

	s.errChan <- fmt.Errorf("connection reset")

	select {
	case <-closeCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("errorMonitor did not close the client on error")
	}
	if c.IsAlive() {
		t.Fatal("client should be dead after errorMonitor handles error")
	}
}

func TestErrorMonitor_StopsOnContextCancel(t *testing.T) {
	c := newTestClient()
	s := c.newSession(c.cfg.Remotes[0])
	atomic.StoreInt32(&s.alive, 1)
	c.active.Store(s)

	done := make(chan struct{})
	go func() { s.errorMonitor(); close(done) }()

	s.cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("errorMonitor did not exit on context cancellation")
	}
}

// --- pingLoop tests ---

func TestPingLoop_TimeoutDetection(t *testing.T) {
	s := newTestSession()
	s.pingInterval = 1
	s.pingTimeout = 3
	atomic.StoreInt32(&s.alive, 1)

	done := make(chan struct{})
	go func() { s.pingLoop(); close(done) }()

	time.Sleep(100 * time.Millisecond)
	atomic.StoreInt64(&s.lastActivity, time.Now().Unix()-5)

	select {
	case err := <-s.errChan:
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
	s := newTestSession()
	s.pingInterval = 10
	s.pingTimeout = 60
	s.updateActivity()

	done := make(chan struct{})
	go func() { s.pingLoop(); close(done) }()

	s.cancel()

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
	c.cfg.Remotes = []Remote{{Server: "192.0.2.1", Port: 9999, UDP: false}}
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
	if elapsed > 10*time.Second {
		t.Fatalf("parallel dial took too long: %v (should be < 10s for parallel)", elapsed)
	}
	t.Logf("parallel dial to 3 unreachable remotes took %v", elapsed)
}

// --- SetOnClose tests ---

func TestSetOnClose_NilSafe(t *testing.T) {
	c := newTestClient()
	s := c.newSession(c.cfg.Remotes[0])
	atomic.StoreInt32(&s.alive, 1)
	c.active.Store(s)
	if err := c.Close(); err != nil {
		t.Fatalf("Close() with nil onClose should not error: %v", err)
	}
}

// --- updateActivity tests ---

func TestUpdateActivity(t *testing.T) {
	s := newTestSession()

	before := time.Now().Unix()
	s.updateActivity()
	after := time.Now().Unix()

	activity := atomic.LoadInt64(&s.lastActivity)
	if activity < before || activity > after {
		t.Fatalf("lastActivity %d not in range [%d, %d]", activity, before, after)
	}
}

// --- processIncomingData tests ---

func TestProcessIncomingData_NonIPDropped(t *testing.T) {
	s := newTestSession()

	payload := []byte{
		0x00, 0x00, 0x00, 0x01, 0x5b, 0x68, 0x90, 0xe6,
		0x43, 0x0e, 0x0d, 0xf0, 0xf1, 0x39, 0xdb, 0x1c,
		0xa7, 0xed, 0x08, 0x82, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	s.processIncomingData(payload)
}

func TestProcessIncomingData_TUNNilSafe(t *testing.T) {
	s := newTestSession()

	ipv4 := make([]byte, 40)
	ipv4[0] = 0x45
	ipv4[12], ipv4[13], ipv4[14], ipv4[15] = 10, 0, 0, 1
	ipv4[16], ipv4[17], ipv4[18], ipv4[19] = 10, 0, 0, 2

	s.processIncomingData(ipv4)
}

func TestProcessIncomingData_EmptyPayload(t *testing.T) {
	s := newTestSession()
	s.processIncomingData([]byte{})
}

// --- session.close / Client.Close plumbing ---

func TestSession_CloseIdempotent(t *testing.T) {
	s := newTestSession()
	atomic.StoreInt32(&s.alive, 1)

	if err := s.close(); err != nil {
		t.Fatalf("first close returned error: %v", err)
	}
	if s.isAlive() {
		t.Fatal("session should be dead after first close")
	}
	// Second close must be a no-op; notably it must not re-cancel or panic.
	if err := s.close(); err != nil {
		t.Fatalf("second close returned error: %v", err)
	}
}

func TestSession_CloseCancelsCtx(t *testing.T) {
	s := newTestSession()
	s.close()

	select {
	case <-s.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("session ctx was not canceled by close")
	}
}

func TestClient_CloseWithoutActive(t *testing.T) {
	c := newTestClient()
	// No active session — Close must still run cleanly and fire onClose once.
	var count int32
	c.SetOnClose(func() { atomic.AddInt32(&count, 1) })
	if err := c.Close(); err != nil {
		t.Fatalf("Close without active session returned error: %v", err)
	}
	if got := atomic.LoadInt32(&count); got != 1 {
		t.Fatalf("onClose should fire exactly once, got %d", got)
	}
}

// --- Stats forwarding ---

func TestClient_StatsNoActiveReturnsZero(t *testing.T) {
	c := newTestClient()
	defer c.cancel()

	s := c.Stats()
	if s != (Stats{}) {
		t.Fatalf("expected zero Stats without active session, got %+v", s)
	}
}

func TestClient_StatsForwardsToSession(t *testing.T) {
	c := newTestClient()
	defer c.cancel()

	sess := c.newSession(c.cfg.Remotes[0])
	connectedAt := time.Now().Add(-5 * time.Minute)
	sess.connectedAt = connectedAt
	atomic.StoreUint64(&sess.pingsSent, 7)
	atomic.StoreUint64(&sess.pingsReceived, 9)
	atomic.StoreUint64(&sess.bytesSent, 1234)
	atomic.StoreUint64(&sess.bytesReceived, 5678)
	c.active.Store(sess)

	got := c.Stats()
	want := Stats{
		ConnectedAt:   connectedAt,
		PingsSent:     7,
		PingsReceived: 9,
		BytesSent:     1234,
		BytesReceived: 5678,
	}
	if got != want {
		t.Fatalf("Stats() = %+v, want %+v", got, want)
	}
}

// --- DialContext / ListenPacket pre-Dial guards ---

func TestClient_DialContextNoActive(t *testing.T) {
	c := newTestClient()
	defer c.cancel()

	_, err := c.DialContext(context.Background(), "tcp", "10.0.0.1:80")
	if err == nil {
		t.Fatal("expected error from DialContext before Dial")
	}
}

func TestClient_ListenPacketNoActive(t *testing.T) {
	c := newTestClient()
	defer c.cancel()

	_, err := c.ListenPacket(context.Background(), "10.0.0.1:53")
	if err == nil {
		t.Fatal("expected error from ListenPacket before Dial")
	}
}

// After Close, DialContext/ListenPacket must error instead of handing back
// a stale, torn-down tunDevice.
func TestClient_DialContextAfterClose(t *testing.T) {
	c := newTestClient()
	c.attachLiveSession()
	_ = c.Close()

	_, err := c.DialContext(context.Background(), "tcp", "10.0.0.1:80")
	if err == nil {
		t.Fatal("DialContext after Close should return an error")
	}
}

func TestClient_ListenPacketAfterClose(t *testing.T) {
	c := newTestClient()
	c.attachLiveSession()
	_ = c.Close()

	_, err := c.ListenPacket(context.Background(), "10.0.0.1:53")
	if err == nil {
		t.Fatal("ListenPacket after Close should return an error")
	}
}

// waitRouteDelay watches s.ctx so that Client.Close() (which cancels the
// Client ctx s.ctx descends from) aborts an in-progress route-delay instead
// of letting the winner be published onto a dead Client.
func TestWaitRouteDelay_SessionCtxCancels(t *testing.T) {
	s := newTestSession()
	s.routeDelay = 60

	done := make(chan error, 1)
	go func() { done <- s.waitRouteDelay(context.Background()) }()

	s.client.cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("waitRouteDelay should return error when s.ctx is canceled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitRouteDelay did not unblock on client ctx cancellation")
	}
}

func TestWaitRouteDelay_CallerCtxStillCancels(t *testing.T) {
	s := newTestSession()
	s.routeDelay = 60

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.waitRouteDelay(ctx) }()

	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("waitRouteDelay should return error when caller ctx is canceled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitRouteDelay did not unblock on caller ctx cancellation")
	}
}

func TestClose_ClearsActive(t *testing.T) {
	c := newTestClient()
	c.attachLiveSession()

	_ = c.Close()

	if got := c.active.Load(); got != nil {
		t.Fatalf("Close should clear active, got %p", got)
	}
}

// simulatePublish exercises the publishMu contract without dialing a real
// socket. It performs the same gating + Store that Dial does inside the
// lock, but skips startLoops — the lock's invariant is about ordering and
// state, and firing the long-lived goroutines requires a live conn / TUN
// device that aren't available in a unit test.
func (c *Client) simulatePublish(winner *session) (published bool) {
	c.publishMu.Lock()
	defer c.publishMu.Unlock()
	if c.closed {
		return false
	}
	c.active.Store(winner)
	atomic.StoreInt32(&winner.alive, 1)
	return true
}

// TestPublishMu_ClosedBlocksPublish: if Close wins, a subsequent publish must
// observe closed=true and refuse to resurrect a winner. Regression for the
// "Close ran between ctx.Err() check and active.Store" window.
func TestPublishMu_ClosedBlocksPublish(t *testing.T) {
	c := newTestClient()
	_ = c.Close()

	winner := c.newSession(c.cfg.Remotes[0])
	defer winner.close()

	if c.simulatePublish(winner) {
		t.Fatal("publish should refuse after Close")
	}
	if c.active.Load() != nil {
		t.Fatal("active must stay nil when publish is refused")
	}
}

// TestPublishMu_CloseSerializesWithPublish: under race, run Close and publish
// concurrently many times. Either ordering is legal, but the end state must
// always be: client dead, active nil. This is the invariant the mutex exists
// to preserve.
func TestPublishMu_CloseSerializesWithPublish(t *testing.T) {
	for i := 0; i < 200; i++ {
		c := newTestClient()
		winner := c.newSession(c.cfg.Remotes[0])

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = c.Close()
		}()
		go func() {
			defer wg.Done()
			if !c.simulatePublish(winner) {
				winner.close()
			}
		}()
		wg.Wait()

		if c.IsAlive() {
			t.Fatalf("iter %d: client alive after Close+publish race", i)
		}
		if c.active.Load() != nil {
			t.Fatalf("iter %d: active not cleared", i)
		}
	}
}

// --- Issue 2 regression: inbound TUN write errors must surface to errChan ---

// failingTunDevice is a wireguard.Device whose Write always fails. All other
// methods are stubs — they're only here to satisfy the interface.
type failingTunDevice struct{ err error }

func (d *failingTunDevice) File() *os.File                         { return nil }
func (d *failingTunDevice) Read([][]byte, []int, int) (int, error) { return 0, d.err }
func (d *failingTunDevice) Write([][]byte, int) (int, error)       { return 0, d.err }
func (d *failingTunDevice) MTU() (int, error)                      { return 1500, nil }
func (d *failingTunDevice) Name() (string, error)                  { return "failing", nil }
func (d *failingTunDevice) Events() <-chan tun.Event               { return nil }
func (d *failingTunDevice) Close() error                           { return nil }
func (d *failingTunDevice) BatchSize() int                         { return 1 }
func (d *failingTunDevice) Start() error                           { return nil }
func (d *failingTunDevice) Inet4Address() netip.Addr               { return netip.Addr{} }
func (d *failingTunDevice) Inet6Address() netip.Addr               { return netip.Addr{} }
func (d *failingTunDevice) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, d.err
}
func (d *failingTunDevice) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, d.err
}

func TestProcessIncomingData_TUNWriteFailureSurfaces(t *testing.T) {
	s := newTestSession()
	s.tunDevice = &failingTunDevice{err: errors.New("tun broken")}

	ipv4 := make([]byte, 40)
	ipv4[0] = 0x45
	ipv4[12], ipv4[13], ipv4[14], ipv4[15] = 10, 0, 0, 1
	ipv4[16], ipv4[17], ipv4[18], ipv4[19] = 10, 0, 0, 2

	s.processIncomingData(ipv4)

	select {
	case err := <-s.errChan:
		if err == nil {
			t.Fatal("expected non-nil error on errChan")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("TUN write failure did not surface on errChan")
	}
}

// --- Issue 3 regression: NewClientFromFile resolves relative cert paths ---

// genSelfSignedCAPEM returns a PEM-encoded self-signed cert that passes
// pool.AppendCertsFromPEM — needed because NewClient validates CA PEM at
// construction time, not at dial time.
func genSelfSignedCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestNewClientFromFile_RelativePaths(t *testing.T) {
	dir := t.TempDir()

	caPEM := genSelfSignedCAPEM(t)
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte(caPEM), 0o600); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	ovpn := []byte("remote example.com 1194\nca ca.crt\n")
	cfgPath := filepath.Join(dir, "client.ovpn")
	if err := os.WriteFile(cfgPath, ovpn, 0o600); err != nil {
		t.Fatalf("write client.ovpn: %v", err)
	}

	client, err := NewClientFromFile(cfgPath, "", "", nil)
	if err != nil {
		t.Fatalf("NewClientFromFile: %v", err)
	}
	defer client.Close()

	if got := client.GetConfig().CACert; got != caPEM {
		t.Fatalf("CA not loaded via NewClientFromFile:\n got: %q\nwant: %q", got, caPEM)
	}
}

// --- decrypt-failure activity gating + burst trigger ---

type failingCipher struct{}

func (failingCipher) Encrypt(_ []byte, _ []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (failingCipher) Decrypt(_ []byte, _ []byte) ([]byte, error) {
	return nil, errors.New("message authentication failed")
}

type passthroughCipher struct{}

func (passthroughCipher) Encrypt(p []byte, _ []byte) ([]byte, error) { return p, nil }
func (passthroughCipher) Decrypt(c []byte, _ []byte) ([]byte, error) { return c, nil }

func TestProcessIncomingData_DecryptFailDoesNotUpdateActivity(t *testing.T) {
	s := newTestSession()
	s.cipher = failingCipher{}

	atomic.StoreInt64(&s.lastActivity, 0)
	s.processIncomingData([]byte{0xde, 0xad, 0xbe, 0xef})

	if got := atomic.LoadInt64(&s.lastActivity); got != 0 {
		t.Fatalf("lastActivity must stay 0 on decrypt failure, got %d", got)
	}
}

func TestProcessIncomingData_DecryptOKUpdatesActivity(t *testing.T) {
	s := newTestSession()
	s.cipher = passthroughCipher{}

	atomic.StoreInt64(&s.lastActivity, 0)
	ipv4 := make([]byte, 40)
	ipv4[0] = 0x45
	s.processIncomingData(ipv4)

	if got := atomic.LoadInt64(&s.lastActivity); got == 0 {
		t.Fatal("lastActivity must be updated after successful decrypt")
	}
}

func TestProcessIncomingData_DecryptFailBurstTriggersErrChan(t *testing.T) {
	s := newTestSession()
	s.cipher = failingCipher{}

	for i := 0; i < decryptFailBurstThreshold-1; i++ {
		s.processIncomingData([]byte{0x00})
		select {
		case err := <-s.errChan:
			t.Fatalf("errChan fired prematurely at iteration %d: %v", i, err)
		default:
		}
	}
	s.processIncomingData([]byte{0x00})

	select {
	case err := <-s.errChan:
		if err == nil {
			t.Fatal("errChan delivered nil error")
		}
	default:
		t.Fatal("burst threshold did not trigger errChan")
	}

	// After firing the counter resets; another full burst must re-trigger so
	// a temporarily-full errChan can't permanently silence the detector.
	for i := 0; i < decryptFailBurstThreshold; i++ {
		s.processIncomingData([]byte{0x00})
	}
	select {
	case <-s.errChan:
	default:
		t.Fatal("counter did not reset after first burst; second burst lost")
	}
}

func TestHandlePacket_DataOpcodeDoesNotUpdateActivityWithoutDecrypt(t *testing.T) {
	s := newTestSession()
	s.cipher = failingCipher{}
	atomic.StoreInt64(&s.lastActivity, 0)

	p := &packet.Packet{
		Opcode:  packet.OpDataV2,
		Payload: []byte{0xde, 0xad, 0xbe, 0xef},
	}
	s.handlePacket(p)

	if got := atomic.LoadInt64(&s.lastActivity); got != 0 {
		t.Fatalf("data packet with failing decrypt must not update activity, got %d", got)
	}
}

func TestHandlePacket_ControlOpcodeUpdatesActivity(t *testing.T) {
	s := newTestSession()
	atomic.StoreInt64(&s.lastActivity, 0)

	p := &packet.Packet{Opcode: packet.OpAckV1}
	s.handlePacket(p)

	if got := atomic.LoadInt64(&s.lastActivity); got == 0 {
		t.Fatal("control packet must update activity on successful parse")
	}
}

// Stats() must keep returning the dead session's counters after Close so a
// reconnect loop can ask "did this connection ever carry traffic?" — the
// signal we use to pick fresh-baseDelay vs exponential-backoff retry.
func TestStats_AfterCloseReturnsLastSessionCounters(t *testing.T) {
	c := newTestClient()
	s := c.attachLiveSession()
	atomic.StoreUint64(&s.bytesReceived, 12345)
	atomic.StoreUint64(&s.bytesSent, 678)

	if err := c.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	got := c.Stats()
	if got.BytesReceived != 12345 {
		t.Fatalf("Stats().BytesReceived after Close = %d, want 12345", got.BytesReceived)
	}
	if got.BytesSent != 678 {
		t.Fatalf("Stats().BytesSent after Close = %d, want 678", got.BytesSent)
	}
}

func TestStats_NoSessionReturnsZero(t *testing.T) {
	c := newTestClient()
	defer c.cancel()

	if got := c.Stats(); got.BytesReceived != 0 || got.BytesSent != 0 {
		t.Fatalf("Stats() with no session must be zero, got %+v", got)
	}
}
