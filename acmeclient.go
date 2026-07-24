package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	cgpapi "github.com/gmyzovsky/go-cgp-api"
	"golang.org/x/crypto/acme"
)

const (
	letsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	letsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"

	accountKeyBits = 4096
)

// newACMEClient assembles an ACME client whose RSA account key lives
// in the CLI account's File Storage: <storage.path>/account.key for
// production, account-staging.key for staging (separate CAs mean
// separate accounts). A missing key is generated and saved before
// first use. A Server Administrator's File Storage is node-local, so
// in a cluster every node keeps its own ACME account - which Let's
// Encrypt permits.
func newACMEClient(ctx context.Context, c *cgpapi.Client, cfg *Config, contactEmail string, verbose bool) (*acme.Client, error) {
	keyPath := cfg.Storage.Path + "/account.key"
	directory := letsEncryptProduction
	if cfg.ACME.Staging {
		keyPath = cfg.Storage.Path + "/account-staging.key"
		directory = letsEncryptStaging
	}

	key, err := loadAccountKey(ctx, c, keyPath, verbose)
	if err != nil {
		return nil, err
	}

	client := &acme.Client{
		Key:          key,
		DirectoryURL: directory,
		UserAgent:    "go-cgp-acme (+https://github.com/gmyzovsky/go-cgp-acme)",
	}

	acct := &acme.Account{}
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
