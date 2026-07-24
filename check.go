package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	cgpapi "github.com/gmyzovsky/go-cgp-api"
	"golang.org/x/net/idna"
)

// decision is the per-domain outcome of checkDomain: whether a
// certificate should be (re)issued, and why.
type decision struct {
	Domain  string
	Renew   bool
	Reason  string
	SANs    []string // punycode names the new certificate must cover
	Skipped bool     // PKI services disabled or domain excluded
}

// checkDomain inspects a domain's effective settings and current
// certificate and decides whether a new certificate is needed.
// Read-only.
//
// The decision chain, in order:
//  1. PKI Services disabled (CertificateType=NO) -> skip.
//  2. No certificate installed, or CertificateType not YES -> renew.
//  3. A domain alias is missing from the certificate SANs -> renew.
//  4. Certificate expires within renewBefore -> renew.
func checkDomain(ctx context.Context, c *cgpapi.Client, domain string, exclude map[string]bool, renewBefore time.Duration, force bool) (*decision, error) {
	d := &decision{Domain: domain}

	aliases, err := c.GetDomainAliases(ctx, &cgpapi.GetDomainAliasesInput{DomainName: domain})
	if err != nil {
		return nil, fmt.Errorf("GetDomainAliases(%s): %w", domain, err)
	}
	d.SANs = []string{domain}
	for _, a := range aliases.Aliases {
		alias := fmt.Sprint(a)
		punycode, err := idna.Lookup.ToASCII(alias)
		if err != nil {
			return nil, fmt.Errorf("alias %q of %s: %w", alias, domain, err)
		}
		if exclude[alias] || exclude[punycode] {
			continue
		}
		d.SANs = append(d.SANs, punycode)
	}

	eff, err := c.GetDomainEffectiveSettings(ctx, &cgpapi.GetDomainEffectiveSettingsInput{DomainName: domain})
	if err != nil {
		return nil, fmt.Errorf("GetDomainEffectiveSettings(%s): %w", domain, err)
	}
	certType := ""
	if v, ok := eff.Settings.Get("CertificateType"); ok {
		certType = fmt.Sprint(v)
	}
	if certType == "NO" {
		d.Skipped = true
		d.Reason = "PKI Services disabled"
		return d, nil
	}

	if force {
		d.Renew = true
		d.Reason = "forced"
		return d, nil
	}

	certValue, ok := eff.Settings.Get("SecureCertificate")
	if !ok || certType != "YES" {
		d.Renew = true
		d.Reason = "no certificate installed"
		return d, nil
	}
	der, err := settingBytes(certValue)
	if err != nil {
		return nil, fmt.Errorf("SecureCertificate of %s: %w", domain, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("SecureCertificate of %s: %w", domain, err)
	}

	san := make(map[string]bool, len(cert.DNSNames))
	for _, name := range cert.DNSNames {
		san[name] = true
	}
	for _, name := range d.SANs {
		if !san[name] {
			d.Renew = true
			d.Reason = fmt.Sprintf("alias %s not in certificate", name)
			return d, nil
		}
	}

	if left := time.Until(cert.NotAfter); left < renewBefore {
		d.Renew = true
		d.Reason = fmt.Sprintf("expires %s", cert.NotAfter.Format("2006-01-02"))
		return d, nil
	}

	d.Reason = fmt.Sprintf("valid until %s", cert.NotAfter.Format("2006-01-02"))
	return d, nil
}
