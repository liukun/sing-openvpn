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
	"github.com/metacubex/sing/common"
	"github.com/metacubex/tls"
)

// session holds all state tied to a single physical VPN connection:
// one remote, one TCP/UDP conn, one TLS session, one cipher, one TUN device.
// Multiple sessions can run concurrently during a multi-remote dial race,
// and each one is self-contained — losers can be torn down without touching
// the winner or the Client.
type session struct {
	client *Client // back-ref for cfg, tlsConfig, onClose plumbing

	remote    Remote
	conn      net.Conn
	isUDPConn bool

	controlProtector crypto.ControlProtector
	tlsConn          *tls.Conn
	controlConn      *ControlConn
	handshakeStarted chan struct{}
	errChan          chan error

	localSID   uint64
	remoteSID  uint64
	peerID     uint32
	packetID   uint32
	ackWaiters sync.Map // uint32 -> chan struct{}

	// key_method_2 material (saved between sendKeyMethod2 and PRF derivation)
	clientPreMaster []byte
	clientRandom1   []byte
	clientRandom2   []byte
	serverRandom1   []byte
	serverRandom2   []byte

	// Data-channel cipher (derived after key_method_2)
	cipher     crypto.DataCipher
	cipherName string // from cfg.Cipher, overwritten by pushed cipher
	dataOpcode byte
	dataAD     []byte

	// Values extracted from PUSH_REPLY
	ifconfigIP   netip.Addr
	ifconfigMask netip.Prefix
	mtu          int
	dns          []string
	routeDelay   int
	pingInterval int
	pingTimeout  int

	tunDevice wireguard.Device

	connectedAt   time.Time
	pingsSent     uint64
	pingsReceived uint64
	bytesSent     uint64
	bytesReceived uint64
	lastActivity  int64
	lastSend      int64
	alive         int32

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// newSession allocates a session with a context descended from the Client's,
// so Client.Close cancels all live sessions.
func (c *Client) newSession(remote Remote) *session {
	var sid uint64
	_ = binary.Read(rand.Reader, binary.BigEndian, &sid)

	ctx, cancel := context.WithCancel(c.ctx)
	s := &session{
		client:           c,
		remote:           remote,
		localSID:         sid,
		cipherName:       c.cfg.Cipher,
		mtu:              c.cfg.MTU,
		pingInterval:     10,
		pingTimeout:      60,
		handshakeStarted: make(chan struct{}, 1),
		errChan:          make(chan error, 10),
		ctx:              ctx,
		cancel:           cancel,
	}
	s.controlConn = newControlConn(s)
	return s
}

// dial resolves the remote, opens the transport connection, and constructs a
// per-session ControlProtector. It does not perform the OpenVPN handshake.
func (s *session) dial(ctx context.Context) error {
	remote := s.remote
	network := "udp"
	if !remote.UDP {
		network = "tcp"
	}

	dnsStart := time.Now()
	addrs, lookupErr := net.DefaultResolver.LookupHost(ctx, remote.Server)
	if lookupErr != nil || len(addrs) == 0 {
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
	if s.client.cfg.Dialer != nil {
		conn, err = s.client.cfg.Dialer.DialContext(ctx, network, addr)
	} else {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		conn, err = dialer.DialContext(ctx, network, addr)
	}
	if err != nil {
		return fmt.Errorf("dial %s failed: %w", addr, err)
	}
	log.Infoln("[OpenVPN] TCP/UDP connect to %s took %s", addr, time.Since(connStart))

	s.conn = conn
	s.isUDPConn = remote.UDP

	// Each session owns its own ControlProtector instance. tls-auth and
	// tls-crypt keep per-instance replay sequence counters; sharing across
	// parallel sessions would collide.
	if key := s.client.cfg.TLSCrypt; key != "" {
		p, err := crypto.NewTLSCrypt(key)
		if err != nil {
			return fmt.Errorf("parse tls-crypt key: %w", err)
		}
		s.controlProtector = p
	} else if key := s.client.cfg.TLSAuth; key != "" {
		keyDir := -1
		if s.client.cfg.KeyDirection != nil {
			keyDir = *s.client.cfg.KeyDirection
		}
		p, err := crypto.NewTLSAuth(key, keyDir, s.client.cfg.Auth)
		if err != nil {
			return fmt.Errorf("parse tls-auth key: %w", err)
		}
		s.controlProtector = p
	}
	return nil
}

// setupTUN builds the gvisor TUN device from PUSH_REPLY values. Must run
// after performHandshake.
func (s *session) setupTUN() error {
	tunStart := time.Now()
	mtu := s.mtu
	if mtu == 0 {
		mtu = 1500
	}

	var prefixes []netip.Prefix
	switch {
	case s.ifconfigMask.IsValid():
		prefixes = []netip.Prefix{s.ifconfigMask}
	case s.ifconfigIP.IsValid():
		prefixes = []netip.Prefix{netip.PrefixFrom(s.ifconfigIP, 24)}
	default:
		return fmt.Errorf("server did not push ifconfig; cannot build TUN")
	}
	log.Infoln("[OpenVPN] TUN prefixes: %v", prefixes)

	dev, err := wireguard.NewStackDevice(prefixes, uint32(mtu))
	if err != nil {
		return err
	}
	if err := dev.Start(); err != nil {
		dev.Close()
		return err
	}
	s.tunDevice = dev
	log.Infoln("[OpenVPN] TUN device init took %s", time.Since(tunStart))
	return nil
}

// waitRouteDelay sleeps for the pushed route-delay seconds so the server's
// routing/NAT is ready before we send user traffic. Watches both the caller's
// ctx and s.ctx so Client.Close() during route-delay aborts the wait instead
// of letting the winner be published onto a closed Client.
func (s *session) waitRouteDelay(ctx context.Context) error {
	if s.routeDelay <= 0 {
		return nil
	}
	log.Infoln("[OpenVPN] Waiting %d seconds for server route-delay before sending data...", s.routeDelay)
	select {
	case <-time.After(time.Duration(s.routeDelay) * time.Second):
		log.Infoln("[OpenVPN] Route-delay wait completed")
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

// startLoops launches the long-lived session goroutines. Called only on the
// winner.
func (s *session) startLoops() {
	atomic.StoreInt32(&s.alive, 1)
	s.connectedAt = time.Now()
	go s.tunReadLoop()
	go s.pingLoop()
	go s.errorMonitor()
}

// close releases all resources this session owns. Idempotent.
func (s *session) close() error {
	var err error
	s.closeOnce.Do(func() {
		atomic.StoreInt32(&s.alive, 0)
		s.cancel()
		err = common.Close(s.conn, s.tunDevice)
	})
	return err
}

func (s *session) isAlive() bool { return atomic.LoadInt32(&s.alive) == 1 }

func (s *session) snapshotStats() Stats {
	return Stats{
		ConnectedAt:   s.connectedAt,
		PingsSent:     atomic.LoadUint64(&s.pingsSent),
		PingsReceived: atomic.LoadUint64(&s.pingsReceived),
		BytesSent:     atomic.LoadUint64(&s.bytesSent),
		BytesReceived: atomic.LoadUint64(&s.bytesReceived),
	}
}

func (s *session) isUDP() bool { return s.isUDPConn }

func (s *session) getNextPacketID() uint32 {
	return atomic.AddUint32(&s.packetID, 1) - 1
}

func (s *session) updateActivity() {
	atomic.StoreInt64(&s.lastActivity, time.Now().Unix())
}

// initDataHeader caches the data-channel opcode and AEAD AD prefix. Must be
// called after peerID is parsed from PUSH_REPLY.
func (s *session) initDataHeader() {
	if s.peerID != 0 {
		s.dataOpcode = packet.OpDataV2
		s.dataAD = []byte{
			packet.OpDataV2 << 3,
			byte(s.peerID >> 16),
			byte(s.peerID >> 8),
			byte(s.peerID),
		}
	} else {
		s.dataOpcode = packet.OpDataV1
		s.dataAD = nil
	}
}

// errorMonitor drains errChan and tears down the Client on first fatal error.
// Runs on the winning session only (after startLoops).
func (s *session) errorMonitor() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case err := <-s.errChan:
			if err != nil {
				log.Warnln("[OpenVPN] errorMonitor: fatal error detected: %v, closing connection", err)
				// Closing the Client will also close this session.
				s.client.Close()
				return
			}
		}
	}
}

var pingMagic = []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}

func (s *session) pingLoop() {
	ticker := time.NewTicker(time.Duration(s.pingInterval) * time.Second)
	defer ticker.Stop()
	now := time.Now().Unix()
	s.updateActivity()
	atomic.StoreInt64(&s.lastSend, now)
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			now = time.Now().Unix()
			last := atomic.LoadInt64(&s.lastActivity)
			if now-last > int64(s.pingTimeout) {
				log.Warnln("[OpenVPN] Ping timeout: no data received for %d seconds, closing connection", s.pingTimeout)
				s.errChan <- fmt.Errorf("ping timeout")
				return
			}
			lastSend := atomic.LoadInt64(&s.lastSend)
			if s.cipher != nil && now-lastSend >= int64(s.pingInterval) {
				pingData, err := s.cipher.Encrypt(pingMagic, s.dataAD)
				if err != nil {
					continue
				}
				p := &packet.Packet{
					Opcode:  s.dataOpcode,
					PeerID:  s.peerID,
					Payload: pingData,
				}
				if writeErr := s.writePacket(p); writeErr != nil {
					log.Warnln("[OpenVPN] Ping write failed: %v", writeErr)
					s.errChan <- writeErr
					return
				}
				atomic.AddUint64(&s.pingsSent, 1)
			}
		}
	}
}
