package main

import (
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the go-cgp-acme configuration, loaded from a TOML file.
// Command-line flags override the corresponding fields.
type Config struct {
	CGP     CGPConfig     `toml:"cgp"`
	ACME    ACMEConfig    `toml:"acme"`
	Domains DomainsConfig `toml:"domains"`
	Storage StorageConfig `toml:"storage"`
}

// CGPConfig describes the CommuniGate Pro PWD/CLI connection.
type CGPConfig struct {
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	Login    string `toml:"login"`
	Password string `toml:"password"`
}

// ACMEConfig describes the ACME account and issuance parameters.
type ACMEConfig struct {
	// Email is the ACME registration and recovery contact. Empty
	// defaults to postmaster@<main domain> at run time.
	Email string `toml:"email"`
	// DirectoryURL is the production ACME directory endpoint. Required;
	// point it at any RFC 8555 CA.
	DirectoryURL string `toml:"directory_url"`
	// StagingURL is an optional staging/test ACME directory endpoint,
	// used instead of DirectoryURL when Staging is set. Some CAs offer a
	// separate staging environment; leave empty for CAs that don't.
	StagingURL string `toml:"staging_url"`
	// EABKID and EABKey are the External Account Binding credentials some
	// CAs require to register an account: a key ID and its HMAC key as
	// issued by the CA. EABKey is base64-encoded (URL or standard
	// alphabet, padded or not), as the CA presents it. Both empty means
	// no EAB.
	EABKID string `toml:"eab_kid"`
	EABKey string `toml:"eab_key"`
	// Staging selects StagingURL instead of DirectoryURL (also: --staging).
	Staging bool `toml:"staging"`
	// KeyBits is the RSA key size for newly issued certificates.
	// CommuniGate Pro supports RSA only (PKCS#1). Default 2048.
	KeyBits int `toml:"key_bits"`
	// RenewBefore renews a certificate that expires within this
	// window, as a Go duration string (default "720h", 30 days).
	RenewBefore duration `toml:"renew_before"`
}

// DomainsConfig selects which domains are processed.
type DomainsConfig struct {
	// OnlyLocal restricts the run to this node's local domains: the
	// main domain and any regular non-Shared domains (everything
	// LISTDOMAINS reports except the Shared ones). In a Dynamic Cluster
	// every node runs with this enabled.
	OnlyLocal bool `toml:"only_local"`
	// OnlyShared restricts the run to the cluster's Shared domains.
	// One designated node runs with this enabled. Setting both
	// OnlyLocal and OnlyShared cancels out: both are ignored.
	OnlyShared bool `toml:"only_shared"`
	// Include, when non-empty, lists the only domains processed.
	Include []string `toml:"include"`
	// Exclude lists domains and domain aliases to skip.
	Exclude []string `toml:"exclude"`
}

// StorageConfig describes where go-cgp-acme keeps its state inside
// the CommuniGate Pro Account File Storage of the CLI account.
type StorageConfig struct {
	// Path is the File Storage directory for the ACME account key and
	// certificate archive. Default "private/letsencrypt".
	Path string `toml:"path"`
}

// duration wraps time.Duration for TOML decoding from a string like
// "720h".
type duration struct{ time.Duration }

func (d *duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// LoadConfig reads path and applies defaults.
func LoadConfig(path string) (*Config, error) {
	cfg := &Config{
		CGP:     CGPConfig{Host: "localhost", Port: 106},
		ACME:    ACMEConfig{KeyBits: 2048, RenewBefore: duration{30 * 24 * time.Hour}},
		Storage: StorageConfig{Path: "private/letsencrypt"},
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	meta, err := toml.Decode(string(raw), cfg)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("%s: unknown configuration key %q", path, undecoded[0].String())
	}
	if cfg.CGP.Login == "" || cfg.CGP.Password == "" {
		return nil, fmt.Errorf("%s: cgp.login and cgp.password are required", path)
	}
	if cfg.ACME.DirectoryURL == "" {
		return nil, fmt.Errorf("%s: acme.directory_url is required", path)
	}
	return cfg, nil
}
