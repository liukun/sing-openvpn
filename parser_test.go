package openvpn

import (
	"os"
	"path/filepath"
	"testing"
)

// Finding 4: relative ca/cert/key paths should resolve against the config
// file's directory when loaded via ParseOVPNFile.
func TestParseOVPNFile_ResolvesRelativeCAPath(t *testing.T) {
	dir := t.TempDir()

	caPath := filepath.Join(dir, "ca.crt")
	const caPEM = "-----BEGIN CERTIFICATE-----\nMIIBd\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(caPath, []byte(caPEM), 0o600); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}

	ovpn := []byte("remote example.com 1194\nca ca.crt\n")
	if err := os.WriteFile(filepath.Join(dir, "client.ovpn"), ovpn, 0o600); err != nil {
		t.Fatalf("write client.ovpn: %v", err)
	}

	cfg, err := ParseOVPNFile(filepath.Join(dir, "client.ovpn"))
	if err != nil {
		t.Fatalf("ParseOVPNFile: %v", err)
	}
	if cfg.CACert != caPEM {
		t.Fatalf("CACert mismatch:\n got: %q\nwant: %q", cfg.CACert, caPEM)
	}
}

func TestParseOVPNFile_ResolvesNestedRelativePath(t *testing.T) {
	dir := t.TempDir()
	certsDir := filepath.Join(dir, "certs")
	if err := os.Mkdir(certsDir, 0o755); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}

	const caPEM = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(filepath.Join(certsDir, "ca.crt"), []byte(caPEM), 0o600); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}

	ovpn := []byte("remote example.com 1194\nca certs/ca.crt\n")
	cfgPath := filepath.Join(dir, "client.ovpn")
	if err := os.WriteFile(cfgPath, ovpn, 0o600); err != nil {
		t.Fatalf("write client.ovpn: %v", err)
	}

	cfg, err := ParseOVPNFile(cfgPath)
	if err != nil {
		t.Fatalf("ParseOVPNFile: %v", err)
	}
	if cfg.CACert != caPEM {
		t.Fatalf("CACert not loaded from nested path")
	}
}

// Existing ParseOVPN (no baseDir) still treats relative paths as CWD-relative
// and will fail on nonexistent files — documenting current behavior so the
// regression is visible if the public surface changes.
func TestParseOVPN_RelativePathFailsWithoutBaseDir(t *testing.T) {
	ovpn := []byte("remote example.com 1194\nca nonexistent-ca.crt\n")
	if _, err := ParseOVPN(ovpn); err == nil {
		t.Fatal("expected error reading nonexistent ca file via ParseOVPN")
	}
}
