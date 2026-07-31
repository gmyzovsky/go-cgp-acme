package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	cgpapi "github.com/gmyzovsky/go-cgp-api"
	cgpdata "github.com/gmyzovsky/go-cgp-data"
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
//  4. Certificate past its renewal window (renewFraction of lifetime,
//     or the renewBefore floor) -> renew.
func checkDomain(ctx context.Context, c *cgpapi.Client, domain string, exclude map[string]bool, renewBefore time.Duration, renewFraction float64, force bool) (*decision, error) {
	d := &decision{Domain: domain}

	aliases, err := c.GetDomainAliases(ctx, &cgpapi.GetDomainAliasesInput{DomainName: domain})
	if err != nil {
		return nil, fmt.Errorf("GetDomainAliases(%s): %w", domain, err)
	}
	d.SANs, err = certificateNames(domain, aliases.Aliases, exclude)
	if err != nil {
		return nil, err
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

	threshold := renewalThreshold(cert.NotBefore, cert.NotAfter, renewFraction, renewBefore)
	if left := time.Until(cert.NotAfter); left < threshold {
		d.Renew = true
		d.Reason = fmt.Sprintf("expires %s", cert.NotAfter.Format("2006-01-02"))
		return d, nil
	}

	d.Reason = fmt.Sprintf("valid until %s", cert.NotAfter.Format("2006-01-02"))
	return d, nil
}

// certificateNames is the list of names a domain's certificate must
// cover: the domain itself, then each alias in punycode.
//
// Exclusion is applied to the alias as the server spells it before the
// name is put through IDNA at all. An alias the operator has already
// ruled out - an internal login alias, a filesystem artifact
// CommuniGate Pro took for a domain - has no business failing the whole
// domain on a conversion of a name that was never going to be in the
// certificate. The punycode form is checked too, so either spelling in
// domains.exclude works.
func certificateNames(domain string, aliases cgpdata.Array, exclude map[string]bool) ([]string, error) {
	names := make([]string, 0, len(aliases)+1)
	names = append(names, domain)
	for _, a := range aliases {
		alias := fmt.Sprint(a)
		if exclude[alias] {
			continue
		}
		punycode, err := idna.Lookup.ToASCII(alias)
		if err != nil {
			return nil, fmt.Errorf("alias %q of %s: %w", alias, domain, err)
		}
		if exclude[punycode] {
			continue
		}
		names = append(names, punycode)
	}
	return names, nil
}

// renewalThreshold is the remaining-lifetime window at or below which a
// certificate is renewed: the larger of fraction x lifetime and the
// absolute floor renewBefore. fraction scales the window with the
// certificate's own validity; renewBefore is an optional minimum.
func renewalThreshold(notBefore, notAfter time.Time, fraction float64, renewBefore time.Duration) time.Duration {
	threshold := time.Duration(fraction * float64(notAfter.Sub(notBefore)))
	if renewBefore > threshold {
		threshold = renewBefore
	}
	return threshold
}
