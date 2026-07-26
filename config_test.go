package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
