package crypto

// ControlProtector wraps/unwraps OpenVPN control channel packets
// for pre-TLS authentication (tls-auth) or encryption (tls-crypt).
type ControlProtector interface {
	Wrap(data []byte) ([]byte, error)
	Unwrap(data []byte) ([]byte, error)
	Overhead() int
}
