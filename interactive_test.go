package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseConnString(t *testing.T) {
	tests := []struct {
		in      string
		want    CGPConfig
		wantErr bool
	}{
		{
			in:   "postmaster:secret@h243n44.etc.myzovsky.ru:106",
			want: CGPConfig{Host: "h243n44.etc.myzovsky.ru", Port: 106, Login: "postmaster", Password: "secret"},
		},
		{
			in:   "postmaster:secret@host",
			want: CGPConfig{Host: "host", Port: 106, Login: "postmaster", Password: "secret"},
		},
		{
			in:   "postmaster@host",
			want: CGPConfig{Host: "host", Port: 106, Login: "postmaster"},
		},
		{
			in:   "host",
			want: CGPConfig{Host: "host", Port: 106},
		},
		{
			in:   "host:2106",
			want: CGPConfig{Host: "host", Port: 2106},
		},
		{
			// Only the first ':' in the userinfo splits login/password,
			// so a password may itself contain colons.
			in:   "postmaster:p:s@host:106",
			want: CGPConfig{Host: "host", Port: 106, Login: "postmaster", Password: "p:s"},
		},
		{in: "postmaster:secret@host:abc", wantErr: true},
		{in: "postmaster:secret@host:0", wantErr: true},
		{in: "postmaster:secret@host:70000", wantErr: true},
		{in: "user:pass@", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		got, err := parseConnString(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseConnString(%q) = %+v, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseConnString(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseConnString(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
}

func TestPromptLine(t *testing.T) {
	tests := []struct {
		input string
		def   string
		want  string
	}{
		{input: "\n", def: "localhost", want: "localhost"},
		{input: "value\n", def: "localhost", want: "value"},
		{input: "  spaced  \n", def: "d", want: "spaced"},
		{input: "\n", def: "", want: ""},
		{input: "eofnonewline", def: "d", want: "eofnonewline"},
	}
	for _, tt := range tests {
		in := bufio.NewReader(strings.NewReader(tt.input))
		got, err := promptLine(in, "label", tt.def)
		if err != nil {
			t.Errorf("promptLine(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("promptLine(%q, def=%q) = %q, want %q", tt.input, tt.def, got, tt.want)
		}
	}
}

func TestQualifyLogin(t *testing.T) {
	tests := []struct {
		login, host, want string
	}{
		{"claude", "h243n44.etc.myzovsky.ru", "claude@h243n44.etc.myzovsky.ru"},
		{"claude", "192.168.33.253", "claude@192.168.33.253"},
		{"postmaster", "localhost", "postmaster@localhost"},
		{"claude@example.org", "mail.example.org", "claude@example.org"}, // already qualified
		{"", "host", ""}, // empty left as-is
	}
	for _, tt := range tests {
		if got := qualifyLogin(tt.login, tt.host); got != tt.want {
			t.Errorf("qualifyLogin(%q, %q) = %q, want %q", tt.login, tt.host, got, tt.want)
		}
	}
}

func TestFirstExisting(t *testing.T) {
	dir := t.TempDir()
	exists := filepath.Join(dir, "here.toml")
	if err := os.WriteFile(exists, []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "nope.toml")

	if got := firstExisting([]string{missing, exists}); got != exists {
		t.Errorf("firstExisting([missing, exists]) = %q, want %q", got, exists)
	}
	if got := firstExisting([]string{missing}); got != "" {
		t.Errorf("firstExisting([missing]) = %q, want empty", got)
	}
}

func TestDefaultConfigPaths(t *testing.T) {
	paths := defaultConfigPaths()
	if len(paths) == 0 {
		t.Fatal("defaultConfigPaths returned nothing")
	}
	if last := paths[len(paths)-1]; last != defaultConfigPath {
		t.Errorf("last path = %q, want %q", last, defaultConfigPath)
	}
	// When os.Executable succeeds there is also an exe-adjacent path
	// first, named go-cgp-acme.toml.
	if len(paths) == 2 && filepath.Base(paths[0]) != configBaseName {
		t.Errorf("first path base = %q, want %q", filepath.Base(paths[0]), configBaseName)
	}
}

func TestStandaloneConfigDefaults(t *testing.T) {
	cfg := standaloneConfig()
	if cfg.ACME.DirectoryURL != letsEncryptProduction {
		t.Errorf("DirectoryURL = %q, want %q", cfg.ACME.DirectoryURL, letsEncryptProduction)
	}
	if cfg.ACME.StagingURL != letsEncryptStaging {
		t.Errorf("StagingURL = %q, want %q", cfg.ACME.StagingURL, letsEncryptStaging)
	}
	if cfg.CGP.Port != 106 {
		t.Errorf("Port = %d, want 106", cfg.CGP.Port)
	}
	if cfg.ACME.KeyBits != 2048 {
		t.Errorf("KeyBits = %d, want 2048", cfg.ACME.KeyBits)
	}
	if cfg.ACME.RenewFraction != 1.0/3.0 {
		t.Errorf("RenewFraction = %v, want 1/3", cfg.ACME.RenewFraction)
	}
	if cfg.Storage.Path != "private/letsencrypt" {
		t.Errorf("Storage.Path = %q, want private/letsencrypt", cfg.Storage.Path)
	}
}
