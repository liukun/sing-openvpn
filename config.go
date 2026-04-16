package openvpn

import (
	"context"
	"net"
	"net/netip"
)

type Remote struct {
	Server        string
	Port          int
	UDP           bool
	ProtoExplicit bool // indicates if UDP/TCP was explicitly set on this remote line
}

type Config struct {
	Remotes      []Remote
	TLSCert      string
	TLSKey       string
	CACert       string
	TLSCrypt     string
	TLSAuth      string
	KeyDirection *int   // nil = bidirectional (default), 0 or 1
	Auth         string // HMAC algorithm for tls-auth: "SHA1", "SHA256", "SHA512"; default "SHA1"
	Cipher       string
	AuthNoCache  bool
	Username     string
	Password     string
	IP           netip.Addr
	Mask         netip.Prefix
	MTU          int
	DNS          []string
	Dialer       Dialer
}

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}
