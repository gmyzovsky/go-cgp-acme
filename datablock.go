package main

import (
	"encoding/base64"
	"fmt"

	cgpdata "github.com/gmyzovsky/go-cgp-data"
)

// settingBytes extracts binary data from a domain-settings value.
//
// CommuniGate Pro returns certificate settings (PrivateSecureKey,
// SecureCertificate, CAChain) from GETDOMAINSETTINGS as quoted strings
// whose text is a "[base64]" datablock, not as bare datablock tokens
// (verified against a live 6.5.6 server). This helper accepts both a
// real cgpdata.DataBlock and the string form, mirroring le-cgatepro's
// block2der: every non-base64 character is stripped before decoding,
// which also tolerates whitespace-wrapped multi-line values.
func settingBytes(v cgpdata.Value) ([]byte, error) {
	switch t := v.(type) {
	case cgpdata.DataBlock:
		return []byte(t), nil
	case cgpdata.String:
		return base64.StdEncoding.DecodeString(stripNonBase64(string(t)))
	default:
		return nil, fmt.Errorf("unsupported setting value type %T", v)
	}
}

func stripNonBase64(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '+', c == '/', c == '=':
			out = append(out, c)
		}
	}
	return string(out)
}
