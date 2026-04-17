package openvpn

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ParseOVPN parses the contents of an OpenVPN configuration file.
// It assumes all certificates and keys are embedded inline or paths are absolute.
func ParseOVPN(data []byte) (*Config, error) {
	return parseOVPN(data, "")
}

// ParseOVPNFile reads an OpenVPN configuration from path. Relative filenames
// on ca/cert/key/tls-auth/tls-crypt directives are resolved against the
// config file's directory, matching the OpenVPN CLI.
func ParseOVPNFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseOVPN(data, filepath.Dir(path))
}

func parseOVPN(data []byte, baseDir string) (*Config, error) {
	cfg := &Config{}
	scanner := bufio.NewScanner(bytes.NewReader(data))

	var currentBlock string
	var blockContent strings.Builder

	var globalProto string

	readFile := func(filename string) (string, error) {
		if baseDir != "" && !filepath.IsAbs(filename) {
			filename = filepath.Join(baseDir, filename)
		}
		b, err := os.ReadFile(filename)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] == '#' || line[0] == ';' {
			continue
		}

		// Handle inline blocks
		if currentBlock != "" {
			if string(line) == "</"+currentBlock+">" {
				content := blockContent.String()
				switch currentBlock {
				case "ca":
					cfg.CACert = content
				case "cert":
					cfg.TLSCert = content
				case "key":
					cfg.TLSKey = content
				case "tls-crypt":
					cfg.TLSCrypt = content
				case "tls-auth":
					cfg.TLSAuth = content
				}
				currentBlock = ""
				blockContent.Reset()
			} else {
				blockContent.Write(line)
				blockContent.WriteByte('\n')
			}
			continue
		}

		if line[0] == '<' && line[len(line)-1] == '>' {
			currentBlock = string(line[1 : len(line)-1])
			blockContent.Reset()
			continue
		}

		// Strip inline comments before splitting
		lineStr := string(line)
		if idx := strings.IndexAny(lineStr, "#;"); idx != -1 {
			lineStr = strings.TrimSpace(lineStr[:idx])
		}

		fields := strings.Fields(lineStr)
		if len(fields) == 0 {
			continue
		}

		directive := fields[0]
		switch directive {
		case "remote":
			if len(fields) >= 2 {
				remote := Remote{
					Server: fields[1],
					Port:   1194,
					UDP:    true, // Default if no global proto and no explicit proto
				}
				if len(fields) >= 3 {
					if p, err := strconv.Atoi(fields[2]); err == nil {
						remote.Port = p
					}
				}
				if len(fields) >= 4 {
					remote.UDP = !strings.HasPrefix(strings.ToLower(fields[3]), "tcp")
					remote.ProtoExplicit = true
				}
				cfg.Remotes = append(cfg.Remotes, remote)
			}
		case "proto":
			if len(fields) >= 2 {
				globalProto = strings.ToLower(fields[1])
			}
		case "cipher":
			if len(fields) >= 2 {
				cfg.Cipher = fields[1]
			}
		case "ca":
			if len(fields) >= 2 {
				content, err := readFile(fields[1])
				if err != nil {
					return nil, err
				}
				cfg.CACert = content
			}
		case "cert":
			if len(fields) >= 2 {
				content, err := readFile(fields[1])
				if err != nil {
					return nil, err
				}
				cfg.TLSCert = content
			}
		case "key":
			if len(fields) >= 2 {
				content, err := readFile(fields[1])
				if err != nil {
					return nil, err
				}
				cfg.TLSKey = content
			}
		case "tls-crypt":
			if len(fields) >= 2 {
				content, err := readFile(fields[1])
				if err != nil {
					return nil, err
				}
				cfg.TLSCrypt = content
			}
		case "tls-auth":
			if len(fields) >= 2 {
				content, err := readFile(fields[1])
				if err != nil {
					return nil, err
				}
				cfg.TLSAuth = content
				// tls-auth <file> <direction> — inline key-direction on same line
				if len(fields) >= 3 && cfg.KeyDirection == nil {
					if d, err := strconv.Atoi(fields[2]); err == nil {
						cfg.KeyDirection = &d
					}
				}
			}
		case "auth":
			if len(fields) >= 2 {
				cfg.Auth = strings.ToUpper(fields[1])
			}
		case "key-direction":
			if len(fields) >= 2 {
				if d, err := strconv.Atoi(fields[1]); err == nil {
					cfg.KeyDirection = &d
				}
			}
		case "auth-nocache":
			cfg.AuthNoCache = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Apply global proto to remotes that didn't specify one
	if globalProto != "" {
		isUDP := !strings.HasPrefix(globalProto, "tcp")
		for i := range cfg.Remotes {
			if !cfg.Remotes[i].ProtoExplicit {
				cfg.Remotes[i].UDP = isUDP
			}
		}
	}

	return cfg, nil
}
