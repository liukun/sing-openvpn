package openvpn

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/airofm/sing-openvpn/internal/crypto"
	"github.com/airofm/sing-openvpn/internal/log"
	"github.com/airofm/sing-openvpn/internal/packet"
	wireguard "github.com/metacubex/sing-wireguard"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

type Client struct {
	cfg        *Config
	conn       net.Conn
	isUDPConn  bool
	localSID   uint64
	remoteSID  uint64
	peerID     uint32
	packetID   uint32
	acks       []uint32
	mutex      sync.Mutex
	ackWaiters sync.Map // uint32 -> chan struct{}

	lastActivity int64 // unix timestamp in seconds, updated on data received
	lastSend     int64 // unix timestamp in seconds, updated on any packet sent
	alive        int32 // 1 = alive, 0 = dead (atomic)

	tlsConn          *tls.Conn
	controlConn      *ControlConn
	handshakeStarted chan struct{}
	controlProtector crypto.ControlProtector
	errChan          chan error

	// Key material from key_method_2 exchange (for PRF key derivation)
	clientPreMaster []byte // 48 bytes
	clientRandom1   []byte // 32 bytes
	clientRandom2   []byte // 32 bytes
	serverRandom1   []byte // 32 bytes
	serverRandom2   []byte // 32 bytes

	routeDelay   int // seconds to wait after connection before routing is ready (from route-delay push)
	pingInterval int // seconds between keepalive pings (from "ping N" push, default 10)
	pingTimeout  int // seconds of inactivity before disconnect (from "ping-restart N" push, default 60)

	tunDevice  wireguard.Device
	cipher     crypto.DataCipher
	dataOpcode byte   // cached after handshake: OpDataV1 or OpDataV2
	dataAD     []byte // cached AEAD AD prefix: [opcode_byte][peer-id(3)] for V2, nil for V1

	ctx    context.Context
	cancel context.CancelFunc

	onClose func() // callback invoked when connection dies
}

// NewClient parses the .ovpn configuration content and initializes a new Client.
func NewClient(ovpnContent []byte, username, password string, dialer Dialer) (*Client, error) {
	cfg, err := ParseOVPN(ovpnContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ovpn content: %w", err)
	}
	cfg.Username = username
	cfg.Password = password
	cfg.Dialer = dialer

	ctx, cancel := context.WithCancel(context.Background())

	// Generate random Session ID
	var sid uint64
	binary.Read(rand.Reader, binary.BigEndian, &sid)

	c := &Client{
		cfg:              cfg,
		localSID:         sid,
		pingInterval:     10,
		pingTimeout:      60,
		handshakeStarted: make(chan struct{}, 1),
		errChan:          make(chan error, 10),
		ctx:              ctx,
		cancel:           cancel,
	}
	c.controlConn = NewControlConn(c)

	if cfg.TLSCrypt != "" {
		tc, err := crypto.NewTLSCrypt(cfg.TLSCrypt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tls-crypt key: %w", err)
		}
		c.controlProtector = tc
	} else if cfg.TLSAuth != "" {
		keyDir := -1
		if cfg.KeyDirection != nil {
			keyDir = *cfg.KeyDirection
		}
		ta, err := crypto.NewTLSAuth(cfg.TLSAuth, keyDir, cfg.Auth)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tls-auth key: %w", err)
		}
		c.controlProtector = ta
		log.Infoln("[OpenVPN] tls-auth enabled, key-direction=%d", keyDir)
	}

	return c, nil
}

func (c *Client) Dial(ctx context.Context) error {
	dialStart := time.Now()
	log.Infoln("[OpenVPN] Dial started at %s", dialStart.Format(time.RFC3339Nano))

	if len(c.cfg.Remotes) == 0 {
		return fmt.Errorf("no remotes configured")
	}

	// For a single remote, connect directly (no goroutine overhead)
	if len(c.cfg.Remotes) == 1 {
		if err := c.tryRemote(ctx, c.cfg.Remotes[0]); err != nil {
			return fmt.Errorf("failed to connect to any remote: %w", err)
		}
	} else {
		// Multiple remotes: try in parallel, first success wins
		type result struct {
			err error
		}
		winCh := make(chan result, len(c.cfg.Remotes))
		raceCtx, raceCancel := context.WithCancel(ctx)
		defer raceCancel()

		for _, remote := range c.cfg.Remotes {
			go func(r Remote) {
				// Each goroutine creates a temporary client state to attempt connection.
				// The winner will apply its state to `c`.
				err := c.tryRemote(raceCtx, r)
				winCh <- result{err: err}
			}(remote)
		}

		var lastErr error
		success := false
		for range c.cfg.Remotes {
			res := <-winCh
			if res.err == nil && !success {
				success = true
				raceCancel() // cancel other attempts
			} else if res.err != nil {
				lastErr = res.err
			}
		}
		if !success {
			return fmt.Errorf("failed to connect to any remote: %w", lastErr)
		}
	}

	log.Infoln("[OpenVPN] Remote connection + handshake took %s", time.Since(dialStart))

	if c.conn == nil {
		return fmt.Errorf("failed to connect: no connection established")
	}

	// 6. Initialize TUN device with negotiated parameters
	tunStart := time.Now()
	mtu := c.cfg.MTU
	if mtu == 0 {
		mtu = 1500
	}

	// Build TUN prefix from pushed IP.
	// parsePushReply sets cfg.Mask to <ip>/32 (point-to-point tun mode).
	// Fall back to /24 if Mask was never set (e.g. server did not push ifconfig).
	var prefixes []netip.Prefix
	if c.cfg.Mask.IsValid() {
		prefixes = []netip.Prefix{c.cfg.Mask}
	} else {
		prefixes = []netip.Prefix{netip.PrefixFrom(c.cfg.IP, 24)}
	}
	log.Infoln("[OpenVPN] TUN prefixes: %v", prefixes)

	var err error
	c.tunDevice, err = wireguard.NewStackDevice(prefixes, uint32(mtu))
	if err != nil {
		return err
	}

	if err := c.tunDevice.Start(); err != nil {
		return err
	}
	log.Infoln("[OpenVPN] TUN device init took %s", time.Since(tunStart))

	// Mark connection as alive
	atomic.StoreInt32(&c.alive, 1)

	// Wait for route-delay: the server needs this time to set up its routing/NAT.
	// Packets sent before this delay expires will be silently dropped by the server.
	if c.routeDelay > 0 {
		log.Infoln("[OpenVPN] Waiting %d seconds for server route-delay before sending data...", c.routeDelay)
		select {
		case <-time.After(time.Duration(c.routeDelay) * time.Second):
			log.Infoln("[OpenVPN] Route-delay wait completed")
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Start TUN loops
	go c.tunReadLoop()
	go c.pingLoop()
	go c.errorMonitor()

	log.Infoln("[OpenVPN] Dial completed, total time: %s", time.Since(dialStart))
	return nil
}

// tryRemote attempts to connect and handshake with a single remote.
// On success, it sets c.conn and related state. The caller must ensure
// that only one successful tryRemote applies its state (via mutex).
func (c *Client) tryRemote(ctx context.Context, remote Remote) error {
	tryStart := time.Now()
	network := "udp"
	if !remote.UDP {
		network = "tcp"
	}

	// Resolve host
	dnsStart := time.Now()
	addrs, lookupErr := net.DefaultResolver.LookupHost(ctx, remote.Server)
	if lookupErr != nil || len(addrs) == 0 {
		log.Warnln("[OpenVPN] Failed to resolve %s: %v", remote.Server, lookupErr)
		return fmt.Errorf("DNS lookup failed for %s: %v", remote.Server, lookupErr)
	}
	ip, err := netip.ParseAddr(addrs[0])
	if err != nil {
		return fmt.Errorf("invalid IP for %s: %v", remote.Server, err)
	}

	log.Infoln("[OpenVPN] DNS resolve for %s took %s -> %s", remote.Server, time.Since(dnsStart), ip.String())

	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", remote.Port))
	log.Infoln("[OpenVPN] Trying to connect to %s (%s, server: %s)", addr, network, remote.Server)
	connStart := time.Now()

	var conn net.Conn
	if c.cfg.Dialer != nil {
		conn, err = c.cfg.Dialer.DialContext(ctx, network, addr)
	} else {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		conn, err = dialer.DialContext(ctx, network, addr)
	}
	if err != nil {
		log.Warnln("[OpenVPN] Failed to connect to %s: %v", addr, err)
		return err
	}

	log.Infoln("[OpenVPN] TCP/UDP connect to %s took %s", addr, time.Since(connStart))

	// Use mutex to prevent race: only first successful handshake wins
	c.mutex.Lock()
	if c.conn != nil {
		// Another goroutine already won
		c.mutex.Unlock()
		conn.Close()
		return fmt.Errorf("another remote already connected")
	}
	c.conn = conn
	c.isUDPConn = remote.UDP
	c.mutex.Unlock()

	// Start read loop
	go c.readLoop()

	// Try handshake
	hsStart := time.Now()
	err = c.performHandshake(ctx)
	if err != nil {
		log.Warnln("[OpenVPN] Handshake failed with %s: %v", addr, err)
		c.mutex.Lock()
		// Only reset if we are still the active connection
		if c.conn == conn {
			c.cancel()
			c.conn.Close()
			c.conn = nil
			c.ctx, c.cancel = context.WithCancel(context.Background())
		}
		c.mutex.Unlock()
		return err
	}

	log.Infoln("[OpenVPN] Handshake with %s took %s", addr, time.Since(hsStart))
	log.Infoln("[OpenVPN] Successfully connected to %s (%s), total tryRemote time: %s", addr, network, time.Since(tryStart))
	return nil
}

func (c *Client) GetConfig() *Config {
	return c.cfg
}

func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if c.tunDevice == nil {
		return nil, fmt.Errorf("openvpn client not fully initialized")
	}
	saddr := M.ParseSocksaddr(address)
	if !saddr.IsIP() {
		return nil, fmt.Errorf("address %s must be an IP address", address)
	}
	return c.tunDevice.DialContext(ctx, network, saddr.Unwrap())
}

func (c *Client) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	if c.tunDevice == nil {
		return nil, fmt.Errorf("openvpn client not fully initialized")
	}
	saddr := M.ParseSocksaddr(address)
	if !saddr.IsIP() {
		return nil, fmt.Errorf("address %s must be an IP address", address)
	}
	return c.tunDevice.ListenPacket(ctx, saddr.Unwrap())
}

func (c *Client) isUDP() bool {
	return c.isUDPConn
}

// initDataHeader caches the data channel opcode and AEAD AD prefix.
// Must be called after peerID is assigned (post-handshake).
func (c *Client) initDataHeader() {
	if c.peerID != 0 {
		c.dataOpcode = packet.OpDataV2
		c.dataAD = []byte{
			packet.OpDataV2 << 3,
			byte(c.peerID >> 16),
			byte(c.peerID >> 8),
			byte(c.peerID),
		}
	} else {
		c.dataOpcode = packet.OpDataV1
		c.dataAD = nil
	}
}

func (c *Client) getNextPacketID() uint32 {
	return atomic.AddUint32(&c.packetID, 1) - 1
}

func (c *Client) updateActivity() {
	atomic.StoreInt64(&c.lastActivity, time.Now().Unix())
}

// IsAlive returns true if the VPN connection is still active.
func (c *Client) IsAlive() bool {
	return atomic.LoadInt32(&c.alive) == 1
}

// SetOnClose registers a callback that is invoked when the connection dies.
func (c *Client) SetOnClose(fn func()) {
	c.onClose = fn
}

// errorMonitor runs after handshake, continuously draining errChan.
// On fatal error it closes the client so that mihomo can detect and reconnect.
func (c *Client) errorMonitor() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case err := <-c.errChan:
			if err != nil {
				log.Warnln("[OpenVPN] errorMonitor: fatal error detected: %v, closing connection", err)
				c.Close()
				return
			}
		}
	}
}

var pingMagic = []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}

func (c *Client) pingLoop() {
	ticker := time.NewTicker(time.Duration(c.pingInterval) * time.Second)
	defer ticker.Stop()
	now := time.Now().Unix()
	c.updateActivity()
	atomic.StoreInt64(&c.lastSend, now)
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			now = time.Now().Unix()
			last := atomic.LoadInt64(&c.lastActivity)
			if now-last > int64(c.pingTimeout) {
				log.Warnln("[OpenVPN] Ping timeout: no data received for %d seconds, closing connection", c.pingTimeout)
				c.errChan <- fmt.Errorf("ping timeout")
				return
			}

			lastSend := atomic.LoadInt64(&c.lastSend)
			if c.cipher != nil && now-lastSend >= int64(c.pingInterval) {
				pingData, err := c.cipher.Encrypt(pingMagic, c.dataAD)
				if err == nil {
					p := &packet.Packet{
						Opcode:  c.dataOpcode,
						PeerID:  c.peerID,
						Payload: pingData,
					}
					if writeErr := c.writePacket(p); writeErr != nil {
						log.Warnln("[OpenVPN] Ping write failed: %v", writeErr)
						c.errChan <- writeErr
						return
					}
				}
			}
		}
	}
}

func (c *Client) Close() error {
	// Only run close logic once via alive flag
	if !atomic.CompareAndSwapInt32(&c.alive, 1, 0) {
		// Already closed or never alive, just cancel context
		c.cancel()
		return nil
	}

	c.cancel()
	var err error
	if c.conn != nil {
		err = c.conn.Close()
	}
	if c.tunDevice != nil {
		if e := c.tunDevice.Close(); e != nil {
			err = e
		}
	}

	// Invoke onClose callback to notify mihomo adapter
	if c.onClose != nil {
		c.onClose()
	}
	return err
}
