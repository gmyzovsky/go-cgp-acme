// Command go-cgp-acme is an ACME (Let's Encrypt) client for the
// CommuniGate Pro server: it renews the TLS certificates of CGP
// domains and their aliases, serving http-01 challenges out of each
// domain's unnamed Skin and installing issued certificates via the
// PWD/CLI protocol.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	cgpapi "github.com/gmyzovsky/go-cgp-api"
	"golang.org/x/crypto/acme"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "go-cgp-acme:", err)
		os.Exit(1)
	}
}

const (
	configBaseName    = "go-cgp-acme.toml"
	defaultConfigPath = "/etc/" + configBaseName
)

// version is the release, stamped at build time via
// -ldflags "-X main.version=...". "dev" for a plain go build.
var version = "dev"

// usage documents the flags and the connection-string form.
func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "Usage: %s [flags] [login:password@host:port]\n\n", os.Args[0])
	fmt.Fprintf(out, "Renews CommuniGate Pro TLS certificates via ACME. Without -config it looks\n")
	fmt.Fprintf(out, "for %s next to the executable, then at %s;\n", configBaseName, defaultConfigPath)
	fmt.Fprintf(out, "with neither present it runs a one-off against Let's Encrypt, prompting for\n")
	fmt.Fprintf(out, "any connection field the command line leaves out.\n\n")
	fmt.Fprintf(out, "Flags:\n")
	flag.PrintDefaults()
}

type stringList []string

func (s *stringList) String() string { return fmt.Sprint([]string(*s)) }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// verbosity counts how often a flag was given, so -verbose -verbose is
// level 2. IsBoolFlag keeps it usable without a value, and an explicit
// -verbose=false turns it back off.
type verbosity int

func (v *verbosity) String() string   { return strconv.Itoa(int(*v)) }
func (v *verbosity) IsBoolFlag() bool { return true }
func (v *verbosity) Set(s string) error {
	if s == "false" {
		*v = 0
		return nil
	}
	*v++
	return nil
}

func run(ctx context.Context) error {
	var (
		configPath  = flag.String("config", "", "configuration file (default: next to the binary, then "+defaultConfigPath+")")
		onlyLocal   = flag.Bool("onlylocal", false, "process only this node's local (non-Shared) domains")
		onlyShared  = flag.Bool("onlyshared", false, "process only the cluster's Shared domains")
		staging     = flag.Bool("staging", false, "use the staging ACME endpoint; implies --force and reports the certificate instead of installing it")
		selfTest    = flag.Bool("self-test", false, "report what a run would do and rehearse the http-01 challenge of every name; changes nothing, contacts no CA")
		forceFlag   = flag.Bool("force", false, "renew regardless of certificate state")
		showVersion = flag.Bool("version", false, "print version and exit")
		level       verbosity
		domains     stringList
		exclude     stringList
	)
	flag.Var(&level, "verbose", "verbose output; repeat (-verbose -verbose) to trace the ACME exchange")
	flag.Var(&domains, "domain", "domain to process (repeatable; default all)")
	flag.Var(&exclude, "exclude", "domain or alias to skip (repeatable, adds to config)")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println("go-cgp-acme", version)
		return nil
	}

	var connCGP *CGPConfig
	if args := flag.Args(); len(args) > 0 {
		if len(args) > 1 {
			return fmt.Errorf("unexpected extra argument %q (flags must precede the connection string)", args[1])
		}
		parsed, err := parseConnString(args[0])
		if err != nil {
			return err
		}
		connCGP = &parsed
	}

	// Configuration source: an explicit -config (an error if missing,
	// as before); else the default file when it exists; else a fileless
	// standalone run wired to Let's Encrypt, for a one-off issue/renew.
	var (
		cfg      *Config
		err      error
		fileless bool
	)
	switch {
	case flagPassed("config"):
		cfg, err = LoadConfig(*configPath)
	default:
		if path := firstExisting(defaultConfigPaths()); path != "" {
			cfg, err = LoadConfig(path)
		} else {
			cfg, fileless = standaloneConfig(), true
		}
	}
	if err != nil {
		return err
	}

	// A connection string overrides the CGP connection in any mode.
	if connCGP != nil {
		cfg.CGP.Host, cfg.CGP.Port = connCGP.Host, connCGP.Port
		if connCGP.Login != "" {
			cfg.CGP.Login = connCGP.Login
		}
		if connCGP.Password != "" {
			cfg.CGP.Password = connCGP.Password
		}
	}
	// Fill missing connection fields interactively: a connection string
	// that omitted the password, or a fileless run with no string at all.
	switch {
	case connCGP != nil:
		if err := collectCGP(&cfg.CGP, false); err != nil {
			return err
		}
	case fileless:
		if err := collectCGP(&cfg.CGP, true); err != nil {
			return err
		}
	}

	if *onlyLocal {
		cfg.Domains.OnlyLocal = true
	}
	if *onlyShared {
		cfg.Domains.OnlyShared = true
	}
	if *staging {
		cfg.ACME.Staging = true
	}
	if len(domains) > 0 {
		cfg.Domains.Include = domains
	}
	cfg.Domains.Exclude = append(cfg.Domains.Exclude, exclude...)

	// A staging run installs nothing, so there is no certificate to
	// protect and nothing to gain from waiting for one to age: staging
	// implies --force, or the rehearsal would have nothing to do exactly
	// when everything is in order.
	force := *forceFlag || cfg.ACME.Staging
	// The file sets the standing level; a --verbose on the command line
	// replaces it outright, so -verbose=false can quiet a chatty config
	// for one run.
	if flagPassed("verbose") {
		cfg.Verbose = int(level)
	}
	verbose, trace := cfg.Verbose >= 1, cfg.Verbose >= 2
	if cfg.ACME.Staging {
		fmt.Println("MAIN staging run: renews regardless of certificate state and installs nothing")
	}

	// In a fileless run the ACME endpoint is not written down anywhere,
	// so make the CA it resolves to visible.
	if fileless {
		endpoint := cfg.ACME.DirectoryURL
		if cfg.ACME.Staging {
			endpoint = cfg.ACME.StagingURL
		}
		fmt.Printf("MAIN using ACME endpoint %s\n", endpoint)
	}

	c, err := cgpapi.Dial(ctx, cgpapi.Options{
		Addr:     cfg.CGP.Host + ":" + strconv.Itoa(cfg.CGP.Port),
		Login:    cfg.CGP.Login,
		Password: cfg.CGP.Password,
	})
	if err != nil {
		return err
	}
	defer c.Close(ctx)

	// GETVERSION is the one command the server asks no access right for,
	// which makes it the right greeting.
	ver, err := c.GetVersion(ctx, nil)
	if err != nil {
		return err
	}
	if verbose {
		fmt.Printf("MAIN connected to %s (CGP %s)\n", cfg.CGP.Host, ver.Version)
	}

	list, err := selectDomains(ctx, c, cfg)
	if err != nil {
		return err
	}

	excluded := make(map[string]bool, len(cfg.Domains.Exclude))
	for _, e := range cfg.Domains.Exclude {
		excluded[e] = true
	}

	if *selfTest {
		return runSelfTest(ctx, c, cfg, list, excluded, force, verbose)
	}

	var renewals []*decision
	for _, domain := range list {
		if excluded[domain] {
			if verbose {
				fmt.Printf("MAIN [ %s ] excluded\n", domain)
			}
			continue
		}
		d, err := checkDomain(ctx, c, domain, excluded, cfg.ACME.RenewBefore.Duration, cfg.ACME.RenewFraction, force)
		if err != nil {
			return err
		}
		switch {
		case d.Skipped:
			if verbose {
				fmt.Printf("MAIN [ %s ] skipped: %s\n", domain, d.Reason)
			}
		case d.Renew:
			fmt.Printf("MAIN [ %s ] needs certificate (%s), SANs %v\n", domain, d.Reason, d.SANs)
			renewals = append(renewals, d)
		default:
			if verbose {
				fmt.Printf("MAIN [ %s ] up to date: %s\n", domain, d.Reason)
			}
		}
	}

	if len(renewals) == 0 {
		if verbose {
			fmt.Println("MAIN nothing to do")
		}
		return nil
	}

	// Rehearse http-01 locally before any order exists: a name that
	// cannot answer - typically a domain alias missing from DNS - would
	// only spend an ACME request to fail. Such an alias is excluded and
	// the domain re-checked, which may leave nothing to renew.
	renewals, blocked, err := rehearseRenewals(ctx, c, cfg, renewals, excluded, force, verbose)
	if err != nil {
		return err
	}
	if len(renewals) == 0 {
		if blocked > 0 {
			return fmt.Errorf("%d domain(s) cannot answer http-01; nothing renewed", blocked)
		}
		if verbose {
			fmt.Println("MAIN nothing to do")
		}
		return nil
	}

	email := cfg.ACME.Email
	if email == "" {
		email = accountContact(ctx, c)
	}
	ac, err := newACMEClient(ctx, c, cfg, email, verbose, trace)
	if err != nil {
		return err
	}

	failed, total := blocked, len(renewals)+blocked
	for _, d := range renewals {
		if err := renewDomain(ctx, c, ac, cfg, d, verbose); err != nil {
			fmt.Fprintf(os.Stderr, "ACME [ %s ] FAILED: %v\n", d.Domain, err)
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d renewal(s) failed", failed, total)
	}
	if verbose {
		fmt.Println("MAIN all done")
	}
	return nil
}

// renewDomain issues a certificate for one domain and installs it,
// archiving the previous key and certificates first.
func renewDomain(ctx context.Context, c *cgpapi.Client, ac *acme.Client, cfg *Config, d *decision, verbose bool) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	keyDER, chain, err := issueCertificate(ctx, c, ac, d, cfg.ACME.KeyBits, verbose)
	if err != nil {
		return err
	}
	// A staging run rehearses validation and issuance; it stops short of
	// the domain settings, which a test CA's certificate would only
	// spoil.
	if cfg.ACME.Staging {
		return reportCertificate(d, chain, verbose)
	}
	if err := archiveDomain(ctx, c, cfg.Storage.Path, d.Domain, verbose); err != nil {
		return err
	}
	if err := installCertificate(ctx, c, d.Domain, keyDER, chain); err != nil {
		return err
	}
	fmt.Printf("MAIN [ %s ] certificate installed (%d names)\n", d.Domain, len(d.SANs))
	return nil
}
