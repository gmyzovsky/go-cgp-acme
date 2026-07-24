// Command go-cgp-acme is an ACME (Let's Encrypt) client for the
// CommuniGate Pro server: it renews the TLS certificates of CGP
// domains and their aliases, serving http-01 challenges out of each
// domain's unnamed Skin and installing issued certificates via the
// PWD/CLI protocol.
//
// It is the Go successor of le-cgatepro.pl. Current state: domain
// enumeration and renewal decisions (the read-only half) work; ACME
// issuance is under construction.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"

	cgpapi "github.com/gmyzovsky/go-cgp-api"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "go-cgp-acme:", err)
		os.Exit(1)
	}
}

type stringList []string

func (s *stringList) String() string { return fmt.Sprint([]string(*s)) }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func run(ctx context.Context) error {
	var (
		configPath = flag.String("config", "/etc/go-cgp-acme.toml", "path to the configuration file")
		mainOnly   = flag.Bool("mainonly", false, "process only this node's main domain")
		staging    = flag.Bool("staging", false, "use the Let's Encrypt staging environment")
		selfTest   = flag.Bool("self-test", false, "probe challenge reachability and report, without contacting ACME")
		force      = flag.Bool("force", false, "renew regardless of certificate state")
		dryRun     = flag.Bool("dry-run", false, "decide and report only; change nothing")
		verbose    = flag.Bool("verbose", false, "verbose output")
		domains    stringList
		exclude    stringList
	)
	flag.Var(&domains, "domain", "domain to process (repeatable; default all)")
	flag.Var(&exclude, "exclude", "domain or alias to skip (repeatable, adds to config)")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if *mainOnly {
		cfg.Domains.MainOnly = true
	}
	if *staging {
		cfg.ACME.Staging = true
	}
	if len(domains) > 0 {
		cfg.Domains.Include = domains
	}
	cfg.Domains.Exclude = append(cfg.Domains.Exclude, exclude...)

	if *selfTest {
		return fmt.Errorf("--self-test is not implemented yet")
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

	ver, err := c.GetVersion(ctx, nil)
	if err != nil {
		return err
	}
	main, err := c.MainDomainName(ctx, nil)
	if err != nil {
		return err
	}
	if *verbose {
		fmt.Printf("MAIN connected to %s (CGP %s), main domain %s\n", cfg.CGP.Host, ver.Version, main.Name)
	}

	var list []string
	switch {
	case cfg.Domains.MainOnly:
		list = []string{main.Name}
	case len(cfg.Domains.Include) > 0:
		list = cfg.Domains.Include
	default:
		out, err := c.ListDomains(ctx, nil)
		if err != nil {
			return err
		}
		for _, d := range out.Domains {
			list = append(list, fmt.Sprint(d))
		}
	}

	excluded := make(map[string]bool, len(cfg.Domains.Exclude))
	for _, e := range cfg.Domains.Exclude {
		excluded[e] = true
	}

	var renewals []*decision
	for _, domain := range list {
		if excluded[domain] {
			if *verbose {
				fmt.Printf("MAIN [ %s ] excluded\n", domain)
			}
			continue
		}
		d, err := checkDomain(ctx, c, domain, excluded, cfg.ACME.RenewBefore.Duration, *force)
		if err != nil {
			return err
		}
		switch {
		case d.Skipped:
			if *verbose {
				fmt.Printf("MAIN [ %s ] skipped: %s\n", domain, d.Reason)
			}
		case d.Renew:
			fmt.Printf("MAIN [ %s ] needs certificate (%s), SANs %v\n", domain, d.Reason, d.SANs)
			renewals = append(renewals, d)
		default:
			if *verbose {
				fmt.Printf("MAIN [ %s ] up to date: %s\n", domain, d.Reason)
			}
		}
	}

	if len(renewals) == 0 {
		if *verbose {
			fmt.Println("MAIN nothing to do")
		}
		return nil
	}
	if *dryRun {
		fmt.Printf("MAIN dry run: %d domain(s) would be renewed\n", len(renewals))
		return nil
	}
	return fmt.Errorf("ACME issuance is not implemented yet; re-run with --dry-run")
}
