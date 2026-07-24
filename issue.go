package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"

	cgpapi "github.com/gmyzovsky/go-cgp-api"
	"golang.org/x/crypto/acme"
)

// issueCertificate obtains a certificate for d.SANs from the ACME CA,
// serving http-01 challenges out of the domain's unnamed Skin. It
// returns the new private key (PKCS#1 DER) and the certificate chain
// (leaf first, DER).
func issueCertificate(ctx context.Context, c *cgpapi.Client, ac *acme.Client, d *decision, keyBits int, verbose bool) (keyDER []byte, chain [][]byte, err error) {
	if err := ensureUnnamedSkin(ctx, c, d.Domain, verbose); err != nil {
		return nil, nil, err
	}

	if verbose {
		fmt.Printf("ACME [ %s ] create order\n", d.Domain)
	}
	order, err := ac.AuthorizeOrder(ctx, acme.DomainIDs(d.SANs...))
	if err != nil {
		return nil, nil, fmt.Errorf("create order: %w", err)
	}

	if order.Status == acme.StatusPending {
		for _, authzURL := range order.AuthzURLs {
			if err := solveAuthorization(ctx, c, ac, d.Domain, authzURL, verbose); err != nil {
				return nil, nil, err
			}
		}
	}

	if _, err := ac.WaitOrder(ctx, order.URI); err != nil {
		return nil, nil, fmt.Errorf("wait order: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: d.Domain},
		DNSNames: d.SANs,
	}, key)
	if err != nil {
		return nil, nil, err
	}

	if verbose {
		fmt.Printf("ACME [ %s ] finalize\n", d.Domain)
	}
	chain, _, err = ac.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, nil, fmt.Errorf("finalize: %w", err)
	}
	if len(chain) == 0 {
		return nil, nil, fmt.Errorf("finalize: empty certificate chain")
	}
	if verbose {
		fmt.Printf("ACME [ %s ] certificate chain of %d received\n", d.Domain, len(chain))
	}
	return x509.MarshalPKCS1PrivateKey(key), chain, nil
}

// solveAuthorization completes one http-01 authorization by storing
// the key authorization as a Skin file of the parent domain (aliases
// are served by the same domain site), accepting the challenge, and
// waiting for the CA's validation. The Skin file is removed
// afterwards; note the deliberate lowercasing on deletion - CGP
// stores Skin file names lowercased (le-cgatepro did the same).
func solveAuthorization(ctx context.Context, c *cgpapi.Client, ac *acme.Client, domain, authzURL string, verbose bool) error {
	authz, err := ac.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("get authorization: %w", err)
	}
	target := authz.Identifier.Value
	if authz.Status == acme.StatusValid {
		if verbose {
			fmt.Printf("ACME [ %s ] authorization already valid\n", target)
		}
		return nil
	}
	if authz.Status != acme.StatusPending {
		return fmt.Errorf("authorization for %s is %s", target, authz.Status)
	}

	var chal *acme.Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "http-01" {
			chal = ch
			break
		}
	}
	if chal == nil {
		return fmt.Errorf("no http-01 challenge offered for %s", target)
	}

	keyAuth, err := ac.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return err
	}
	_, err = c.StoreDomainSkinFile(ctx, &cgpapi.StoreDomainSkinFileInput{
		DomainName: domain,
		FileName:   chal.Token,
		Content:    []byte(keyAuth),
	})
	if err != nil {
		return fmt.Errorf("store challenge file: %w", err)
	}
	defer func() {
		_, delErr := c.DeleteDomainSkinFile(ctx, &cgpapi.DeleteDomainSkinFileInput{
			DomainName: domain,
			FileName:   strings.ToLower(chal.Token),
		})
		if delErr != nil && verbose {
			fmt.Printf("ACME [ %s ] challenge file cleanup: %v\n", target, delErr)
		}
	}()

	if verbose {
		fmt.Printf("ACME [ %s ] accept http-01 challenge\n", target)
	}
	if _, err := ac.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept challenge for %s: %w", target, err)
	}
	if _, err := ac.WaitAuthorization(ctx, authz.URI); err != nil {
		return fmt.Errorf("authorization for %s: %w", target, err)
	}
	if verbose {
		fmt.Printf("ACME [ %s ] authorization valid\n", target)
	}
	return nil
}

// ensureUnnamedSkin makes sure the domain has its unnamed Skin -
// without one there is nowhere to store challenge files (and named
// Skins cannot exist without it either).
func ensureUnnamedSkin(ctx context.Context, c *cgpapi.Client, domain string, verbose bool) error {
	skins, err := c.ListDomainSkins(ctx, &cgpapi.ListDomainSkinsInput{DomainName: domain})
	if err != nil {
		return err
	}
	if len(skins.Skins) > 0 {
		return nil
	}
	if _, err := c.CreateDomainSkin(ctx, &cgpapi.CreateDomainSkinInput{DomainName: domain}); err != nil {
		return err
	}
	if verbose {
		fmt.Printf("MAIN [ %s ] unnamed Skin created\n", domain)
	}
	return nil
}
