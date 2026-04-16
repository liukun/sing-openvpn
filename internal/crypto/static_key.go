package crypto

import (
	"encoding/hex"
	"errors"
	"strings"
)

// ParseStaticKey parses an OpenVPN Static key V1 format and returns 256 raw bytes.
func ParseStaticKey(keyData string) ([]byte, error) {
	lines := strings.Split(keyData, "\n")
	var hexData strings.Builder
	inKey := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "-----BEGIN OpenVPN Static key V1-----") {
			inKey = true
			continue
		}
		if strings.Contains(line, "-----END OpenVPN Static key V1-----") {
			break
		}
		if inKey {
			hexData.WriteString(line)
		}
	}

	data, err := hex.DecodeString(hexData.String())
	if err != nil {
		return nil, err
	}

	if len(data) < 256 {
		return nil, errors.New("static key too short, need 256 bytes")
	}

	return data, nil
}
