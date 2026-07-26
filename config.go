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
	// Verbose is the output level: 0 reports only what changed, 1 adds
	// a line per domain, 2 also traces the ACME exchange. Raised per run
	// by repeating --verbose, which wins over this when given.
	Verbose int `toml:"verbose"`

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
	// Email is the ACME registration and recovery contact. Empty asks
	// the server for the CLI account's own address (accountContact), and
	// registers with no contact if that is not usable as one.
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
	// Staging selects StagingURL instead of DirectoryURL. Set by
	// --staging only, never from the file: a staging run reports its
	// certificate instead of installing it, which is a thing to ask for
	// once while testing, not a state to leave a machine in.
	Staging bool `toml:"-"`
	// KeyBits is the RSA key size for newly issued certificates.
	// CommuniGate Pro supports RSA only (PKCS#1). Default 2048.
	KeyBits int `toml:"key_bits"`
	// RenewFraction renews a certificate once less than this fraction of
	// its lifetime remains, so the window scales with certificate
	// validity (at 1/3 a 90-day cert renews 30 days out, a 6-day cert 2
	// days out). Range [0, 1); default 1/3. Zero disables the fractional
	// trigger, leaving only RenewBefore.
	RenewFraction float64 `toml:"renew_fraction"`
	// RenewBefore is an optional absolute floor on the renewal window: a
	// certificate is also renewed once less than this remains, whichever
	// window is larger. A Go duration string; "0h" (default) disables it,
	// leaving RenewFraction to govern.
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
	// certificate archive. Default "private/acme".
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
		ACME:    ACMEConfig{KeyBits: 2048, RenewFraction: 1.0 / 3.0},
		Storage: StorageConfig{Path: "private/acme"},
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
	if cfg.Verbose < 0 {
		return nil, fmt.Errorf("%s: verbose must not be negative", path)
	}
	if cfg.ACME.RenewFraction < 0 || cfg.ACME.RenewFraction >= 1 {
		return nil, fmt.Errorf("%s: acme.renew_fraction must be in [0, 1)", path)
	}
	if cfg.ACME.RenewBefore.Duration < 0 {
		return nil, fmt.Errorf("%s: acme.renew_before must not be negative", path)
	}
	if cfg.ACME.RenewFraction == 0 && cfg.ACME.RenewBefore.Duration == 0 {
		return nil, fmt.Errorf("%s: acme.renew_fraction and acme.renew_before are both zero; expiry renewal disabled", path)
	}
	return cfg, nil
}
