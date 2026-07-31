package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cgpapi "github.com/gmyzovsky/go-cgp-api"
)

// writeConfig puts body in a temporary file and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "go-cgp-acme.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const minimalConfig = `
[cgp]
login = "postmaster@localhost"
password = "secret"

[acme]
directory_url = "https://ca.example/directory"
`

func TestLoadConfigVerbose(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"absent", minimalConfig, 0},
		{"per-domain", "verbose = 1\n" + minimalConfig, 1},
		{"with ACME trace", "verbose = 2\n" + minimalConfig, 2},
	}
	for _, tc := range cases {
		cfg, err := LoadConfig(writeConfig(t, tc.body))
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if cfg.Verbose != tc.want {
			t.Errorf("%s: Verbose = %d, want %d", tc.name, cfg.Verbose, tc.want)
		}
	}

	if _, err := LoadConfig(writeConfig(t, "verbose = -1\n"+minimalConfig)); err == nil {
		t.Error("a negative verbose was accepted, want an error")
	}
}

// staging is a testing switch, not a setting: it must not be settable
// from a file, and an old file that still carries it should say so
// rather than quietly do nothing.
func TestLoadConfigRejectsStagingKey(t *testing.T) {
	for _, body := range []string{
		minimalConfig + "staging = true\n",
		minimalConfig + "staging = false\n",
	} {
		_, err := LoadConfig(writeConfig(t, body))
		if err == nil {
			t.Fatal("a file setting acme.staging was accepted, want an error")
		}
		if !strings.Contains(err.Error(), "staging") {
			t.Errorf("error %q does not name the offending key", err)
		}
	}

	// The endpoint it selects stays configurable, of course.
	cfg, err := LoadConfig(writeConfig(t, minimalConfig+"staging_url = \"https://ca.example/staging\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ACME.StagingURL != "https://ca.example/staging" {
		t.Errorf("StagingURL = %q, want the configured one", cfg.ACME.StagingURL)
	}
	if cfg.ACME.Staging {
		t.Error("Staging is set without --staging")
	}
}

// configWithTLS puts a tls setting into the [cgp] table of the
// minimal configuration.
func configWithTLS(mode string) string {
	return strings.Replace(minimalConfig, "[cgp]\n", "[cgp]\ntls = \""+mode+"\"\n", 1)
}

// The transport must never be decided by a typo: an unrecognized
// cgp.tls has to be an error, not a silent fall back to cleartext.
func TestLoadConfigTLS(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    cgpapi.TLSMode
		wantErr bool
	}{
		{"absent", minimalConfig, cgpapi.NoTLS, false},
		{"none", configWithTLS("none"), cgpapi.NoTLS, false},
		{"implicit", configWithTLS("tls"), cgpapi.ImplicitTLS, false},
		{"starttls", configWithTLS("STARTTLS"), cgpapi.StartTLS, false},
		{"unknown", configWithTLS("ssl"), 0, true},
	}
	for _, tc := range cases {
		cfg, err := LoadConfig(writeConfig(t, tc.body))
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: accepted, want an error", tc.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		mode, err := cfg.CGP.TLSMode()
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if mode != tc.want {
			t.Errorf("%s: mode = %v, want %v", tc.name, mode, tc.want)
		}
	}
}

// An unset port follows the transport, and a host and a port sharing
// one string means an IPv6 literal has to come back bracketed.
func TestCGPConfigAddr(t *testing.T) {
	cases := []struct {
		name string
		cgp  CGPConfig
		mode cgpapi.TLSMode
		want string
	}{
		{"default plain", CGPConfig{Host: "localhost"}, cgpapi.NoTLS, "localhost:106"},
		{"default starttls", CGPConfig{Host: "localhost"}, cgpapi.StartTLS, "localhost:106"},
		{"default implicit", CGPConfig{Host: "mail.example.org"}, cgpapi.ImplicitTLS, "mail.example.org:1106"},
		{"explicit wins", CGPConfig{Host: "mail.example.org", Port: 2106}, cgpapi.ImplicitTLS, "mail.example.org:2106"},
		{"ipv4", CGPConfig{Host: "10.0.0.1"}, cgpapi.NoTLS, "10.0.0.1:106"},
		{"ipv6", CGPConfig{Host: "2001:db8::1"}, cgpapi.ImplicitTLS, "[2001:db8::1]:1106"},
	}
	for _, tc := range cases {
		if got := tc.cgp.Addr(tc.mode); got != tc.want {
			t.Errorf("%s: Addr = %q, want %q", tc.name, got, tc.want)
		}
	}
}
