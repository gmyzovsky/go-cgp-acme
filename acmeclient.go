package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	cgpapi "github.com/gmyzovsky/go-cgp-api"
	"golang.org/x/crypto/acme"
)

const accountKeyBits = 4096

// newACMEClient assembles an ACME client whose RSA account key lives
// in the CLI account's File Storage, one key per CA (separate CAs mean
// separate accounts - see acmeEndpoint for the file names). A missing
// key is generated and saved before first use. A Server Administrator's
// File Storage is node-local, so in a cluster every node keeps its own
// ACME account per CA - which ACME CAs permit.
func newACMEClient(ctx context.Context, c *cgpapi.Client, cfg *Config, contactEmail string, verbose, trace bool) (*acme.Client, error) {
	directory, keyPath, err := acmeEndpoint(cfg)
	if err != nil {
		return nil, err
	}
	eab, err := externalAccountBinding(cfg)
	if err != nil {
		return nil, err
	}

	key, err := loadAccountKey(ctx, c, keyPath, verbose)
	if err != nil {
		return nil, err
	}

	client := &acme.Client{
		Key:          key,
		DirectoryURL: directory,
		UserAgent:    "go-cgp-acme/" + version + " (+https://github.com/gmyzovsky/go-cgp-acme)",
	}
	if trace {
		client.HTTPClient = &http.Client{Transport: newTraceTransport(nil)}
	}

	acct := &acme.Account{ExternalAccountBinding: eab}
	if contactEmail != "" {
		acct.Contact = []string{"mailto:" + contactEmail}
	}
	_, err = client.Register(ctx, acct, acme.AcceptTOS)
	switch {
	case errors.Is(err, acme.ErrAccountAlreadyExists):
		if verbose {
			fmt.Println("ACME account already registered")
		}
	case err != nil:
		return nil, fmt.Errorf("ACME register: %w", err)
	default:
		if verbose {
			fmt.Println("ACME account registered")
		}
	}
	return client, nil
}

// accountContact asks the server for the address of the Account this
// run authenticated as, and offers it as the ACME registration contact.
// GETACCOUNTPREFS on "*" answers with a fully qualified AccountName,
// which beats anything derived from the login string: the server
// resolves aliases (a login in localhost comes back in the real main
// domain) and needs no access right for it - reading one's own Account
// is self-access, not administration.
//
// A server that will not say, or an address a CA could not write to,
// leaves the account without a contact. That is allowed by RFC 8555 and
// better than registering a name invented here.
func accountContact(ctx context.Context, c *cgpapi.Client) string {
	out, err := c.GetAccountPrefs(ctx, &cgpapi.GetAccountPrefsInput{AccountName: "*"})
	if err != nil {
		return ""
	}
	name, ok := out.Prefs.Get("AccountName")
	if !ok {
		return ""
	}
	return validContact(fmt.Sprint(name))
}

// validContact returns addr if a CA could plausibly deliver to it, and
// "" otherwise. CommuniGate Pro is happy with postmaster@localhost or
// an account qualified by an IP literal; a CA wants a domain a human
// could receive mail at.
func validContact(addr string) string {
	at := strings.IndexByte(addr, '@')
	if at <= 0 || at != strings.LastIndexByte(addr, '@') || at == len(addr)-1 {
		return ""
	}
	domain := addr[at+1:]
	if !strings.Contains(domain, ".") || net.ParseIP(domain) != nil {
		return ""
	}
	return addr
}

// acmeEndpoint resolves the active ACME directory URL and the File
// Storage path of its account key. With Staging set it uses StagingURL
// (which must be configured); otherwise DirectoryURL. Each endpoint
// gets its own account-<host>.key, so different CAs - and one CA's
// production vs staging - keep separate accounts.
func acmeEndpoint(cfg *Config) (directory, keyPath string, err error) {
	directory = cfg.ACME.DirectoryURL
	if cfg.ACME.Staging {
		if cfg.ACME.StagingURL == "" {
			return "", "", fmt.Errorf("acme: staging is set but staging_url is empty")
		}
		directory = cfg.ACME.StagingURL
	}
	if directory == "" {
		return "", "", fmt.Errorf("acme: directory_url is empty")
	}
	u, err := url.Parse(directory)
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("acme: invalid directory URL %q", directory)
	}
	return directory, cfg.Storage.Path + "/account-" + u.Host + ".key", nil
}

// externalAccountBinding builds the EAB from cfg, or nil when none is
// configured. It requires both EABKID and EABKey together and decodes
// EABKey with decodeEABKey.
func externalAccountBinding(cfg *Config) (*acme.ExternalAccountBinding, error) {
	kid, key := cfg.ACME.EABKID, cfg.ACME.EABKey
	if kid == "" && key == "" {
		return nil, nil
	}
	if kid == "" || key == "" {
		return nil, fmt.Errorf("acme: eab_kid and eab_key must both be set")
	}
	raw, err := decodeEABKey(key)
	if err != nil {
		return nil, fmt.Errorf("acme: eab_key: %w", err)
	}
	return &acme.ExternalAccountBinding{KID: kid, Key: raw}, nil
}

// decodeEABKey decodes an EAB HMAC key as a CA console presents it.
// EAB keys are conventionally base64url, but CAs vary, so it accepts
// the URL and standard alphabets, padded or not.
func decodeEABKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("not valid base64")
}

// loadAccountKey reads the PKCS#1 DER account key from the CLI
// account's File Storage, generating and storing a new one if the
// file does not exist yet ("599 file is not found").
func loadAccountKey(ctx context.Context, c *cgpapi.Client, path string, verbose bool) (*rsa.PrivateKey, error) {
	out, err := c.ReadStorageFile(ctx, &cgpapi.ReadStorageFileInput{AccountName: "*", FileName: path})
	if err == nil {
		key, err := x509.ParsePKCS1PrivateKey(out.Content)
		if err != nil {
			return nil, fmt.Errorf("account key %s: %w", path, err)
		}
		if verbose {
			fmt.Printf("ACME account key loaded from %s\n", path)
		}
		return key, nil
	}
	var respErr *cgpapi.ResponseError
	if !errors.As(err, &respErr) || respErr.Code != "599" {
		return nil, err
	}

	key, err := rsa.GenerateKey(rand.Reader, accountKeyBits)
	if err != nil {
		return nil, err
	}
	_, err = c.WriteStorageFile(ctx, &cgpapi.WriteStorageFileInput{
		AccountName: "*",
		FileName:    path,
		Content:     x509.MarshalPKCS1PrivateKey(key),
	})
	if err != nil {
		return nil, fmt.Errorf("saving account key %s: %w", path, err)
	}
	if verbose {
		fmt.Printf("ACME account key generated and saved at %s\n", path)
	}
	return key, nil
}
