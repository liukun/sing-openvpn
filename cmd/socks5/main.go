//go:build with_gvisor

package main

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"os"
	osexec "os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	openvpn "github.com/airofm/sing-openvpn"
	"github.com/armon/go-socks5"
)

type Config struct {
	SOCKS5  SOCKS5Config  `toml:"socks5"`
	OpenVPN OpenVPNConfig `toml:"openvpn"`
}

type SOCKS5Config struct {
	Listen string `toml:"listen"`
}

type OpenVPNConfig struct {
	OVPNFile       string `toml:"ovpn_file"`
	Username       string `toml:"username"`
	Password       string `toml:"password"`
	PasswordScript string `toml:"password_script"`
}

func (c *OpenVPNConfig) resolvePassword() (string, error) {
	if c.PasswordScript != "" {
		out, err := osexec.Command("bash", c.PasswordScript).Output()
		if err != nil {
			return "", fmt.Errorf("password script failed: %w", err)
		}
		return strings.TrimSpace(string(out)), nil
	}
	return c.Password, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <config.toml>\n", os.Args[0])
		os.Exit(1)
	}

	var cfg Config
	if _, err := toml.DecodeFile(os.Args[1], &cfg); err != nil {
		log.Fatalf("failed to parse config: %v", err)
	}
	if cfg.SOCKS5.Listen == "" {
		cfg.SOCKS5.Listen = "127.0.0.1:6080"
	}

	ovpnContent, err := os.ReadFile(cfg.OpenVPN.OVPNFile)
	if err != nil {
		log.Fatalf("failed to read ovpn file: %v", err)
	}

	password, err := cfg.OpenVPN.resolvePassword()
	if err != nil {
		log.Fatalf("failed to resolve password: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	proxy := &vpnProxy{
		ovpnContent: ovpnContent,
		username:    cfg.OpenVPN.Username,
		password:    password,
		listen:      cfg.SOCKS5.Listen,
	}

	proxy.run(ctx)
}

type vpnProxy struct {
	ovpnContent []byte
	username    string
	password    string
	listen      string

	mu      sync.RWMutex
	client  *openvpn.Client
	dns     string
	firstUp chan struct{} // closed on first successful connection
}

func (p *vpnProxy) run(ctx context.Context) {
	p.firstUp = make(chan struct{})
	go p.connectLoop(ctx)

	select {
	case <-p.firstUp:
	case <-ctx.Done():
		return
	}

	server, err := socks5.New(&socks5.Config{
		Dial:     p.dialContext,
		Resolver: &vpnResolver{proxy: p},
	})
	if err != nil {
		log.Fatalf("failed to create socks5 server: %v", err)
	}

	log.Printf("socks5 proxy listening on socks5://%s", p.listen)

	ln, err := net.Listen("tcp", p.listen)
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	if err := server.Serve(ln); err != nil && ctx.Err() == nil {
		log.Fatalf("serve failed: %v", err)
	}
}

func (p *vpnProxy) connectLoop(ctx context.Context) {
	const (
		baseDelay = 1 * time.Second
		maxDelay  = 60 * time.Second
	)
	delay := baseDelay

	for {
		if ctx.Err() != nil {
			return
		}

		client, err := openvpn.NewClient(p.ovpnContent, p.username, p.password, nil)
		if err != nil {
			log.Printf("failed to create openvpn client: %v", err)
			delay = backoff(delay, maxDelay)
			sleepCtx(ctx, delay)
			continue
		}

		dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
		err = client.Dial(dialCtx)
		dialCancel()
		if err != nil {
			log.Printf("openvpn dial failed: %v", err)
			client.Close()
			delay = backoff(delay, maxDelay)
			sleepCtx(ctx, delay)
			continue
		}

		cfg := client.GetConfig()
		var dns string
		if len(cfg.DNS) > 0 {
			dns = cfg.DNS[0] + ":53"
		}

		reconnect := make(chan struct{}, 1)
		client.SetOnClose(func() {
			select {
			case reconnect <- struct{}{}:
			default:
			}
		})

		p.mu.Lock()
		if p.client != nil {
			p.client.Close()
		}
		p.client = client
		p.dns = dns
		p.mu.Unlock()

		delay = baseDelay
		log.Printf("openvpn connected, ip=%s dns=%s", cfg.IP, dns)

		select {
		case <-p.firstUp:
		default:
			close(p.firstUp)
		}

		select {
		case <-reconnect:
			log.Printf("openvpn connection lost, reconnecting...")
		case <-ctx.Done():
			client.Close()
			return
		}
	}
}

func (p *vpnProxy) getClient() (*openvpn.Client, string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.client, p.dns
}

func (p *vpnProxy) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	client, _ := p.getClient()
	if client == nil || !client.IsAlive() {
		return nil, fmt.Errorf("openvpn not connected")
	}
	return client.DialContext(ctx, network, addr)
}

// vpnResolver resolves DNS through the VPN tunnel.
type vpnResolver struct {
	proxy *vpnProxy
}

func (r *vpnResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	client, dnsAddr := r.proxy.getClient()
	if client == nil || !client.IsAlive() {
		return ctx, nil, fmt.Errorf("openvpn not connected")
	}
	if dnsAddr == "" {
		return ctx, nil, fmt.Errorf("no vpn dns server available")
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return client.DialContext(ctx, "udp", dnsAddr)
		},
	}

	addrs, err := resolver.LookupIPAddr(ctx, name)
	if err != nil {
		return ctx, nil, err
	}
	for _, a := range addrs {
		if ip := a.IP.To4(); ip != nil {
			return ctx, ip, nil
		}
	}
	if len(addrs) > 0 {
		return ctx, addrs[0].IP, nil
	}
	return ctx, nil, fmt.Errorf("no address found for %s", name)
}

func backoff(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		next = max
	}
	// Add jitter: 75%-100% of next
	jitter := next/4 + time.Duration(rand.Int64N(int64(next/4+1)))
	return jitter + next*3/4
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
