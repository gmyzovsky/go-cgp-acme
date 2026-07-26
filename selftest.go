package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	cgpapi "github.com/gmyzovsky/go-cgp-api"
)

// challengePath is where a CA fetches an http-01 challenge response,
// and where CommuniGate Pro serves the domain's Skin file of that name
// when started with --HTTPServeAcmeChallenge YES.
const challengePath = "/.well-known/acme-challenge/"

// tokenAlphabet is the base64url alphabet ACME tokens are drawn from.
// Probe tokens use the same shape, mixed case included, so a rehearsal
// exercises exactly what a real challenge would.
const tokenAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// probeTimeout bounds one challenge fetch.
const probeTimeout = 15 * time.Second

// probe is the outcome of one local http-01 rehearsal.
type probe struct {
	Name    string
	Pass    bool
	Status  string // PASS, an HTTP status code, or a short failure kind
	Comment string // what to look at when it is not a PASS
}

// probeClient fetches challenge responses. Redirects are followed, and
// certificates are not verified along the way, because that is what a
// CA does when validating http-01: the answer is the token, not the
// TLS identity of whoever serves it.
var probeClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	},
}

// probeNames rehearses the http-01 challenge locally for every name a
// certificate is to cover. For each name it stores a random token as a
// Skin file of the parent domain (aliases are served by the same site,
// exactly as during issuance), fetches it over plain HTTP from the
// public name, compares, and removes the file again.
//
// The point is to find out before an ACME order exists that a name
// cannot answer - a domain alias that is not in DNS or does not point
// here at all is the common case - so the order is never placed.
func probeNames(ctx context.Context, c *cgpapi.Client, domain string, names []string, verbose bool) ([]probe, error) {
	if err := ensureUnnamedSkin(ctx, c, domain, verbose); err != nil {
		return nil, err
	}
	probes := make([]probe, 0, len(names))
	for _, name := range names {
		p, err := probeName(ctx, c, domain, name, verbose)
		if err != nil {
			return nil, err
		}
		if verbose {
			if p.Pass {
				fmt.Printf("SELF [ %s ] http-01 reachable\n", name)
			} else {
				fmt.Printf("SELF [ %s ] http-01 %s: %s\n", name, p.Status, p.Comment)
			}
		}
		probes = append(probes, p)
	}
	return probes, nil
}

// probeName runs the rehearsal for a single name. A CGP or transport
// error that is not the name's own fault (storing the Skin file) is
// returned as an error; everything the name itself does wrong becomes
// a failed probe.
func probeName(ctx context.Context, c *cgpapi.Client, domain, name string, verbose bool) (probe, error) {
	token, err := randomToken(43)
	if err != nil {
		return probe{}, err
	}
	payload, err := randomToken(43)
	if err != nil {
		return probe{}, err
	}
	// Shaped like a key authorization: <token>.<account key thumbprint>.
	// No account is involved here - the probe compares what it stored.
	body := token + "." + payload

	if _, err := c.StoreDomainSkinFile(ctx, &cgpapi.StoreDomainSkinFileInput{
		DomainName: domain,
		FileName:   token,
		Content:    []byte(body),
	}); err != nil {
		return probe{}, fmt.Errorf("store probe file: %w", err)
	}
	defer func() {
		// CGP stores Skin file names lowercased; delete by that name.
		_, delErr := c.DeleteDomainSkinFile(ctx, &cgpapi.DeleteDomainSkinFileInput{
			DomainName: domain,
			FileName:   strings.ToLower(token),
		})
		if delErr != nil && verbose {
			fmt.Printf("SELF [ %s ] probe file cleanup: %v\n", name, delErr)
		}
	}()

	return fetchChallenge(ctx, name, token, body), nil
}

// fetchChallenge asks name for the token over plain HTTP and turns the
// result into a probe, with a comment pointing at the likely cause.
func fetchChallenge(ctx context.Context, name, token, want string) probe {
	p := probe{Name: name}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	url := "http://" + name + challengePath + token
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		p.Status, p.Comment = "ERROR", err.Error()
		return p
	}
	resp, err := probeClient.Do(req)
	if err != nil {
		p.Status, p.Comment = transportFailure(err)
		return p
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		p.Status, p.Comment = "ERROR", err.Error()
		return p
	}
	switch {
	case resp.StatusCode == http.StatusOK && strings.TrimSpace(string(got)) == want:
		p.Pass, p.Status = true, "PASS"
	case resp.StatusCode == http.StatusOK:
		p.Status, p.Comment = "MISMATCH", "another server answered (redirected?)"
	case resp.StatusCode == http.StatusNotFound:
		p.Status, p.Comment = "404", "challenge not served, try --HTTPServeAcmeChallenge YES"
	default:
		p.Status, p.Comment = fmt.Sprint(resp.StatusCode), strings.ToLower(http.StatusText(resp.StatusCode))
	}
	return p
}

// transportFailure names the way a challenge fetch failed before any
// HTTP status was seen. These are the interesting ones: a name that is
// not in DNS, or one that resolves somewhere without an HTTP listener.
func transportFailure(err error) (status, comment string) {
	if dnsErr, ok := errors.AsType[*net.DNSError](err); ok {
		if dnsErr.IsNotFound {
			return "DNS", "name does not resolve"
		}
		return "DNS", "lookup failed: " + dnsErr.Err
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded), os.IsTimeout(err):
		return "TIMEOUT", "no answer on port 80"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "REFUSED", "nothing listening on port 80"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "UNREACHABLE", "no route to the address this name points at"
	}
	return "ERROR", firstLine(err.Error())
}

// runSelfTest reports what a run would do, and whether it could: for
// every selected domain it prints the same renewal decision a real run
// prints, rehearses http-01 for every name, and ends with a table of
// what answered. It contacts no CA and installs nothing; the only
// change it makes is the challenge file it removes again (and the
// unnamed Skin, if the domain had none).
func runSelfTest(ctx context.Context, c *cgpapi.Client, cfg *Config, list []string, excluded map[string]bool, force, verbose bool) error {
	type row struct {
		name   string
		alias  bool
		status string
		note   string
	}
	var rows []row
	failed, renewals, blocked := 0, 0, 0

	for _, domain := range list {
		if excluded[domain] {
			if verbose {
				fmt.Printf("SELF [ %s ] excluded\n", domain)
			}
			continue
		}
		d, err := checkDomain(ctx, c, domain, excluded, cfg.ACME.RenewBefore.Duration, cfg.ACME.RenewFraction, force)
		if err != nil {
			return err
		}
		if d.Skipped {
			rows = append(rows, row{name: domain, status: "SKIP", note: d.Reason})
			continue
		}
		if d.Renew {
			fmt.Printf("MAIN [ %s ] needs certificate (%s), SANs %v\n", domain, d.Reason, d.SANs)
		} else {
			fmt.Printf("MAIN [ %s ] up to date: %s\n", domain, d.Reason)
		}

		// Every selected domain is probed, not just the ones due for
		// renewal: knowing a name cannot answer is worth more before its
		// certificate is about to expire than after.
		probes, err := probeNames(ctx, c, domain, d.SANs, verbose)
		if err != nil {
			return err
		}
		for _, p := range probes {
			if !p.Pass {
				failed++
			}
			rows = append(rows, row{name: p.Name, alias: p.Name != domain, status: p.Status, note: p.Comment})
		}
		if !d.Renew {
			continue
		}

		// For a domain that would be renewed, follow the decision all the
		// way through, exactly as the run itself would.
		blocker, badAliases := classifyProbes(domain, probes)
		switch {
		case blocker != nil:
			fmt.Fprintf(os.Stderr, "SELF [ %s ] BLOCKED: cannot answer http-01 (%s: %s)\n", domain, blocker.Status, blocker.Comment)
			blocked++
		case len(badAliases) == 0:
			renewals++
		default:
			nd, err := reconsider(ctx, c, cfg, d, badAliases, excluded, force)
			if err != nil {
				return err
			}
			if nd != nil {
				renewals++
			}
		}
	}

	width := 32
	for _, r := range rows {
		if n := len(r.name) + 3; r.alias && n > width {
			width = n
		} else if !r.alias && len(r.name) > width {
			width = len(r.name)
		}
	}
	fmt.Printf("\n%-*s  %-8s %s\n", width, "NAME", "HTTP-01", "COMMENT")
	fmt.Println(strings.Repeat("-", width+11+len("COMMENT")))
	for _, r := range rows {
		name := r.name
		if r.alias {
			name = "-> " + name
		}
		fmt.Println(strings.TrimRight(fmt.Sprintf("%-*s  %-8s %s", width, name, r.status, r.note), " "))
	}

	fmt.Printf("\nMAIN self-test: %d domain(s) would be renewed", renewals)
	if blocked > 0 {
		fmt.Printf(", %d blocked", blocked)
	}
	fmt.Println()

	if failed > 0 {
		return fmt.Errorf("self-test: %d name(s) cannot answer http-01", failed)
	}
	return nil
}

// reconsider drops the names that cannot answer from the run and asks
// checkDomain again: a domain is often marked for renewal precisely
// because an alias is missing from its certificate, and if that alias
// is also missing from DNS there may be nothing left to do. Returns the
// surviving decision, or nil when the domain no longer needs one.
func reconsider(ctx context.Context, c *cgpapi.Client, cfg *Config, d *decision, badAliases []probe, excluded map[string]bool, force bool) (*decision, error) {
	for _, p := range badAliases {
		fmt.Printf("SELF [ %s ] alias %s cannot answer http-01 (%s: %s); excluded for this run\n", d.Domain, p.Name, p.Status, p.Comment)
		fmt.Printf("SELF [ %s ] add %q to domains.exclude to stop reconsidering it\n", d.Domain, p.Name)
		excluded[p.Name] = true
	}

	nd, err := checkDomain(ctx, c, d.Domain, excluded, cfg.ACME.RenewBefore.Duration, cfg.ACME.RenewFraction, force)
	if err != nil {
		return nil, err
	}
	switch {
	case nd.Skipped:
		fmt.Printf("SELF [ %s ] skipped after exclusion: %s\n", d.Domain, nd.Reason)
		return nil, nil
	case nd.Renew:
		fmt.Printf("MAIN [ %s ] still needs certificate (%s), SANs %v\n", d.Domain, nd.Reason, nd.SANs)
		return nd, nil
	default:
		fmt.Printf("MAIN [ %s ] no renewal needed after exclusion: %s\n", d.Domain, nd.Reason)
		return nil, nil
	}
}

// rehearseRenewals runs the same probe over the domains a run is about
// to renew, so a name that cannot answer never costs an ACME request.
//
// A failing alias is excluded for the rest of the run and the domain is
// re-checked: when the missing alias was the only reason to renew, the
// domain drops out of the list entirely. A domain that cannot answer
// for itself is dropped and counted, since its certificate is the one
// thing this tool exists to renew.
func rehearseRenewals(ctx context.Context, c *cgpapi.Client, cfg *Config, renewals []*decision, excluded map[string]bool, force, verbose bool) ([]*decision, int, error) {
	kept := make([]*decision, 0, len(renewals))
	blocked := 0

	for _, d := range renewals {
		probes, err := probeNames(ctx, c, d.Domain, d.SANs, verbose)
		if err != nil {
			return nil, 0, err
		}
		blocker, badAliases := classifyProbes(d.Domain, probes)
		if blocker != nil {
			fmt.Fprintf(os.Stderr, "SELF [ %s ] BLOCKED: cannot answer http-01 (%s: %s)\n", d.Domain, blocker.Status, blocker.Comment)
			blocked++
			continue
		}
		if len(badAliases) == 0 {
			kept = append(kept, d)
			continue
		}

		nd, err := reconsider(ctx, c, cfg, d, badAliases, excluded, force)
		if err != nil {
			return nil, 0, err
		}
		if nd != nil {
			kept = append(kept, nd)
		}
	}
	return kept, blocked, nil
}

// classifyProbes reads a rehearsal: the domain's own failure, if any,
// which blocks the whole renewal, and the failing aliases, which can be
// dropped from the certificate instead. The two are not
// interchangeable - a certificate without its domain is pointless,
// while one without an unreachable alias is exactly what is wanted.
func classifyProbes(domain string, probes []probe) (blocker *probe, badAliases []probe) {
	for i, p := range probes {
		if p.Pass {
			continue
		}
		if p.Name == domain {
			if blocker == nil {
				blocker = &probes[i]
			}
			continue
		}
		badAliases = append(badAliases, p)
	}
	return blocker, badAliases
}

// randomToken returns n characters of the ACME token alphabet. The
// alphabet is exactly 64 long, so the modulo is unbiased.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i, v := range b {
		b[i] = tokenAlphabet[int(v)%len(tokenAlphabet)]
	}
	return string(b), nil
}

// firstLine keeps an error message to one line for the report table.
func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
