package main

import (
	"bytes"
	"testing"
)

func TestAcmeEndpointProduction(t *testing.T) {
	cfg := &Config{Storage: StorageConfig{Path: "private/letsencrypt"}}
	cfg.ACME.DirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"

	dir, key, err := acmeEndpoint(cfg)
	if err != nil || dir != cfg.ACME.DirectoryURL {
		t.Fatalf("directory: %q, %v", dir, err)
	}
	if key != "private/letsencrypt/account-acme-v02.api.letsencrypt.org.key" {
		t.Fatalf("per-host key path = %q", key)
	}
}

func TestAcmeEndpointStaging(t *testing.T) {
	cfg := &Config{Storage: StorageConfig{Path: "p"}}
	cfg.ACME.DirectoryURL = "https://acme.example.com/dir"
	cfg.ACME.StagingURL = "https://staging.example.com/dir"
	cfg.ACME.Staging = true

	dir, key, err := acmeEndpoint(cfg)
	if err != nil || dir != cfg.ACME.StagingURL {
		t.Fatalf("directory: %q, %v", dir, err)
	}
	if key != "p/account-staging.example.com.key" {
		t.Fatalf("staging key path = %q", key)
	}
}

func TestAcmeEndpointStagingRequiresURL(t *testing.T) {
	cfg := &Config{Storage: StorageConfig{Path: "p"}}
	cfg.ACME.DirectoryURL = "https://acme.example.com/dir"
	cfg.ACME.Staging = true // no StagingURL
	if _, _, err := acmeEndpoint(cfg); err == nil {
		t.Fatal("staging without staging_url accepted, want an error")
	}
}

func TestAcmeEndpointEmpty(t *testing.T) {
	cfg := &Config{Storage: StorageConfig{Path: "p"}}
	if _, _, err := acmeEndpoint(cfg); err == nil {
		t.Fatal("empty directory_url accepted, want an error")
	}
}

func TestAcmeEndpointInvalidURL(t *testing.T) {
	cfg := &Config{Storage: StorageConfig{Path: "p"}}
	cfg.ACME.DirectoryURL = "://nonsense"
	if _, _, err := acmeEndpoint(cfg); err == nil {
		t.Fatal("invalid directory_url accepted, want an error")
	}
}

func TestExternalAccountBinding(t *testing.T) {
	// base64url (no padding) of "secret-hmac-key".
	const kid = "kid-123"
	const key = "c2VjcmV0LWhtYWMta2V5"
	cfg := &Config{}
	cfg.ACME.EABKID, cfg.ACME.EABKey = kid, key

	eab, err := externalAccountBinding(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eab == nil || eab.KID != kid || !bytes.Equal(eab.Key, []byte("secret-hmac-key")) {
		t.Fatalf("eab = %+v", eab)
	}
}

func TestExternalAccountBindingNone(t *testing.T) {
	eab, err := externalAccountBinding(&Config{})
	if err != nil || eab != nil {
		t.Fatalf("no EAB expected: %+v, %v", eab, err)
	}
}

func TestExternalAccountBindingIncomplete(t *testing.T) {
	cfg := &Config{}
	cfg.ACME.EABKID = "kid-only"
	if _, err := externalAccountBinding(cfg); err == nil {
		t.Fatal("kid without key accepted, want an error")
	}
}

func TestDecodeEABKeyAlphabets(t *testing.T) {
	// 0xfb 0xfe 0x3f encodes to "-_4_" (base64url) and "+/4/" (standard);
	// 0xfb 0xff needs padding: "-_8=" (url) and "+/8=" (standard). All
	// four alphabet/padding combinations must decode.
	cases := map[string][]byte{
		"-_4_": {0xfb, 0xfe, 0x3f},
		"+/4/": {0xfb, 0xfe, 0x3f},
		"-_8=": {0xfb, 0xff},
		"+/8=": {0xfb, 0xff},
	}
	for s, want := range cases {
		got, err := decodeEABKey(s)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("decodeEABKey(%q) = %x, %v; want %x", s, got, err, want)
		}
	}
	if _, err := decodeEABKey("not base64!!"); err == nil {
		t.Fatal("garbage decoded, want an error")
	}
}
