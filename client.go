package openvpn

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/airofm/sing-openvpn/internal/log"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

// Client is the externally-facing handle to an OpenVPN connection. It holds
// only config-level state; all per-connection state lives in the active
// *session. This separation is what makes parallel multi-remote dialing
// correct: each attempt gets its own session, and only the winner is kept.
type Client struct {
	cfg       *Config     // immutable after NewClient
	tlsConfig *tls.Config // prebuilt, shared by every handshake attempt

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	onClose   func() // invoked exactly once when the client dies

	// publishMu serializes Dial's publish step (cfg mutation + active.Store +
	// startLoops) with Close. Without it, Close can interleave between Store
	// and startLoops (or between the pre-publish ctx check and Store),
	// resurrecting a winner onto a client that already fired Close.
	publishMu  sync.Mutex
	closed     bool  // guarded by publishMu
	finalStats Stats // last session's counters, captured in Close (publishMu)

	active atomic.Pointer[session] // set once a winning session is chosen
}

// Stats is a snapshot of the active session's counters. Returned values are
// zero when no session is active.
type Stats struct {
	ConnectedAt   time.Time
	PingsSent     uint64
	PingsReceived uint64
	BytesSent     uint64
	BytesReceived uint64
}

// NewClient parses the .ovpn configuration bytes and validates config-level
// state. Paths referenced by ca/cert/key/tls-auth/tls-crypt must be absolute
// or inline — there is no base directory to resolve relatives against. For
// file-based configs, prefer NewClientFromFile.
func NewClient(ovpnContent []byte, username, password string, dialer Dialer) (*Client, error) {
	cfg, err := ParseOVPN(ovpnContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ovpn content: %w", err)
	}
	return newClientFromConfig(cfg, username, password, dialer)
}

// NewClientFromFile reads and parses an .ovpn file, resolving relative
// ca/cert/key/tls-auth/tls-crypt paths against the config file's directory
// (matching the OpenVPN CLI). It does not touch the network.
func NewClientFromFile(path, username, password string, dialer Dialer) (*Client, error) {
	cfg, err := ParseOVPNFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ovpn file: %w", err)
	}
	return newClientFromConfig(cfg, username, password, dialer)
}

func newClientFromConfig(cfg *Config, username, password string, dialer Dialer) (*Client, error) {
	cfg.Username = username
	cfg.Password = password
	cfg.Dialer = dialer

	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}

	// Fail closed: refuse to construct a client without a usable CA rather
	// than silently connecting with verification disabled.
	if cfg.CACert == "" {
		return nil, fmt.Errorf("CA certificate required (configure <ca> or ca path in .ovpn)")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
		return nil, fmt.Errorf("failed to parse CA certificate PEM")
	}
	c.tlsConfig = &tls.Config{
		RootCAs: pool,
		// OpenVPN uses its own CA; server cert CN doesn't match the hostname.
		// Skip Go's default hostname verification and verify the chain manually.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
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
		},
	}
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.X509KeyPair([]byte(cfg.TLSCert), []byte(cfg.TLSKey))
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		c.tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		}
	}

	return c, nil
}

// Dial races every configured remote in parallel. Each attempt runs
// independently in its own session; the first session that completes dial +
// handshake + TUN setup wins, and all other sessions are torn down. Ctx
// applies to the whole dial; once a winner is chosen, the winner's lifetime
// follows the Client.
func (c *Client) Dial(ctx context.Context) error {
	dialStart := time.Now()
	log.Infoln("[OpenVPN] Dial started at %s", dialStart.Format(time.RFC3339Nano))

	remotes := c.cfg.Remotes
	if len(remotes) == 0 {
		return fmt.Errorf("no remotes configured")
	}

	raceCtx, cancelRace := context.WithCancel(ctx)

	winCh := make(chan *session, len(remotes))
	errCh := make(chan error, len(remotes))
	var wg sync.WaitGroup
	wg.Add(len(remotes))

	for _, r := range remotes {
		go func(r Remote) {
			defer wg.Done()
			s, err := c.attemptRemote(raceCtx, r)
			if err != nil {
				errCh <- err
				return
			}
			select {
			case winCh <- s:
			case <-raceCtx.Done():
				s.close()
			}
		}(r)
	}

	var winner *session
	var lastErr error
	remaining := len(remotes)

selection:
	for remaining > 0 && winner == nil {
		select {
		case s := <-winCh:
			winner = s
		case err := <-errCh:
			lastErr = err
			remaining--
		case <-ctx.Done():
			lastErr = ctx.Err()
			break selection
		}
	}

	cancelRace()

	// Drain late arrivals so losers don't leak and senders don't block. errCh
	// is buffered to len(remotes) and each goroutine writes at most once, so
	// it never needs draining — only winCh carries late winners that must be
	// closed.
	go func() {
		wg.Wait()
		close(winCh)
	}()
	go func() {
		for s := range winCh {
			s.close()
		}
	}()

	if winner == nil {
		if lastErr == nil {
			lastErr = fmt.Errorf("no winner")
		}
		return fmt.Errorf("failed to connect to any remote: %w", lastErr)
	}

	log.Infoln("[OpenVPN] Remote connection + handshake took %s", time.Since(dialStart))

	if err := winner.waitRouteDelay(ctx); err != nil {
		winner.close()
		return err
	}

	// Publish under publishMu so Close cannot interleave between the closed-
	// check, cfg mutation, active.Store, and startLoops. See the publishMu
	// comment on Client for the race this closes.
	c.publishMu.Lock()
	if c.closed {
		c.publishMu.Unlock()
		winner.close()
		return context.Canceled
	}
	c.cfg.IP = winner.ifconfigIP
	if winner.ifconfigMask.IsValid() {
		c.cfg.Mask = winner.ifconfigMask
	}
	if winner.mtu > 0 {
		c.cfg.MTU = winner.mtu
	}
	if winner.cipherName != "" {
		c.cfg.Cipher = winner.cipherName
	}
	if len(winner.dns) > 0 {
		c.cfg.DNS = winner.dns
	}
	c.active.Store(winner)
	winner.startLoops()
	c.publishMu.Unlock()

	log.Infoln("[OpenVPN] Dial completed, total time: %s", time.Since(dialStart))
	return nil
}

// attemptRemote runs the full per-remote connection pipeline: dial, handshake,
// TUN setup. Returns a session that's ready to have its long-lived loops
// started, or an error. Losers of the race are torn down by the caller via
// session.close().
func (c *Client) attemptRemote(ctx context.Context, remote Remote) (*session, error) {
	tryStart := time.Now()
	s := c.newSession(remote)

	if err := s.dial(ctx); err != nil {
		s.close()
		return nil, err
	}

	// While the handshake runs, watch ctx so that a race cancellation from
	// outside (e.g. another remote already won) unblocks the blocking reads
	// inside negotiateConfig. Setting a past deadline on both the raw conn and
	// the TLS conn wakes any in-flight Read. This watcher is scoped to the
	// handshake + TUN setup; once attemptRemote returns successfully the
	// winner is no longer affected by ctx cancellation.
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			pastDeadline := time.Unix(1, 0)
			if s.conn != nil {
				_ = s.conn.SetReadDeadline(pastDeadline)
			}
			if s.tlsConn != nil {
				_ = s.tlsConn.SetReadDeadline(pastDeadline)
			}
		case <-watchDone:
		}
	}()
	defer close(watchDone)

	go s.readLoop()

	hsStart := time.Now()
	if err := s.performHandshake(ctx); err != nil {
		log.Warnln("[OpenVPN] Handshake failed with %s: %v", remote.Server, err)
		s.close()
		return nil, err
	}
	log.Infoln("[OpenVPN] Handshake with %s took %s", remote.Server, time.Since(hsStart))

	if err := s.setupTUN(); err != nil {
		s.close()
		return nil, err
	}
	log.Infoln("[OpenVPN] Successfully assembled session for %s, total time: %s", remote.Server, time.Since(tryStart))
	return s, nil
}

// Close tears down the client and, if one exists, the active session. Safe to
// call multiple times; the registered onClose callback fires exactly once.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.publishMu.Lock()
		c.closed = true
		c.cancel()
		s := c.active.Swap(nil)
		if s != nil {
			c.finalStats = s.snapshotStats()
		}
		c.publishMu.Unlock()
		if s != nil {
			err = s.close()
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

// GetConfig returns the parsed (and, post-Dial, PUSH-augmented) configuration.
// Callers must not mutate the returned struct once Dial has run.
func (c *Client) GetConfig() *Config { return c.cfg }

// SetOnClose registers a callback invoked exactly once when the client dies.
// Must be called before Close / before the session trips its errorMonitor.
func (c *Client) SetOnClose(fn func()) { c.onClose = fn }

// IsAlive reports whether a winning session exists and is still serving
// traffic.
func (c *Client) IsAlive() bool {
	s := c.active.Load()
	return s != nil && s.isAlive()
}

// Stats returns a snapshot of the active session's counters. After Close it
// returns the dead session's last counters so callers (e.g. reconnect loops)
// can decide whether the connection actually carried traffic.
func (c *Client) Stats() Stats {
	if s := c.active.Load(); s != nil {
		return s.snapshotStats()
	}
	c.publishMu.Lock()
	defer c.publishMu.Unlock()
	return c.finalStats
}

// DialContext opens a TCP connection through the VPN tunnel.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	s := c.active.Load()
	if s == nil || !s.isAlive() {
		return nil, fmt.Errorf("openvpn tunnel not available")
	}
	saddr := M.ParseSocksaddr(address)
	if !saddr.IsIP() {
		return nil, fmt.Errorf("address %s must be an IP address", address)
	}
	return s.tunDevice.DialContext(ctx, network, saddr.Unwrap())
}

// ListenPacket opens a UDP socket inside the VPN tunnel.
func (c *Client) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	s := c.active.Load()
	if s == nil || !s.isAlive() {
		return nil, fmt.Errorf("openvpn tunnel not available")
	}
	saddr := M.ParseSocksaddr(address)
	if !saddr.IsIP() {
		return nil, fmt.Errorf("address %s must be an IP address", address)
	}
	return s.tunDevice.ListenPacket(ctx, saddr.Unwrap())
}
