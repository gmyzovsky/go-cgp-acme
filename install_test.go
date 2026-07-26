package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCertDER makes a self-signed certificate to stand in for what a
// domain has installed.
func testCertDER(t *testing.T, cn string, key *rsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestArchiveFileKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// What this tool installs: PKCS#1, which WebAdmin takes as an
	// "RSA PRIVATE KEY" block.
	suffix, body := archiveFile("PrivateSecureKey", x509.MarshalPKCS1PrivateKey(key))
	if suffix != "privkey.pem" {
		t.Errorf("suffix %q, want privkey.pem", suffix)
	}
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatalf("PKCS#1 key encoded as %v, want an RSA PRIVATE KEY block", block)
	}
	if len(rest) != 0 {
		t.Errorf("%d trailing bytes after the key block", len(rest))
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Errorf("archived key does not parse back: %v", err)
	}

	// A key installed by hand may be PKCS#8; it must not be labelled
	// RSA, or pasting it back fails.
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if suffix, body := archiveFile("PrivateSecureKey", pkcs8); suffix != "privkey.pem" ||
		pemType(t, body) != "PRIVATE KEY" {
		t.Errorf("PKCS#8 key archived as %q/%q, want privkey.pem/PRIVATE KEY", suffix, pemType(t, body))
	}
}

func TestArchiveFileCertificateAndChain(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := testCertDER(t, "example.org", key)
	intermediate := testCertDER(t, "Example CA", key)
	root := testCertDER(t, "Example Root", key)

	suffix, body := archiveFile("SecureCertificate", leaf)
	if suffix != "cert.pem" || pemType(t, body) != "CERTIFICATE" {
		t.Errorf("certificate archived as %q/%q", suffix, pemType(t, body))
	}

	// A CA chain is stored as concatenated DER and has to come back out
	// as one PEM block per certificate, in the same order.
	suffix, body = archiveFile("CAChain", append(append([]byte{}, intermediate...), root...))
	if suffix != "chain.pem" {
		t.Errorf("chain suffix %q, want chain.pem", suffix)
	}
	if n := strings.Count(string(body), "-----BEGIN CERTIFICATE-----"); n != 2 {
		t.Errorf("chain holds %d PEM blocks, want 2", n)
	}
	certs, err := parsePEMChain(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || certs[0].Subject.CommonName != "Example CA" || certs[1].Subject.CommonName != "Example Root" {
		t.Errorf("chain came back as %v, want [Example CA, Example Root]", certs)
	}
}

// Anything unparseable is kept raw: a mislabelled PEM would be worse
// than a blob the administrator has to ask about.
func TestArchiveFileKeepsUnparseableAsDER(t *testing.T) {
	junk := []byte{0x30, 0x82, 0x00, 0x01, 0xff}
	cases := map[string]string{
		"PrivateSecureKey":  "privkey.der",
		"SecureCertificate": "cert.der",
		"CAChain":           "chain.der",
	}
	for key, want := range cases {
		suffix, body := archiveFile(key, junk)
		if suffix != want {
			t.Errorf("%s: suffix %q, want %q", key, suffix, want)
		}
		if string(body) != string(junk) {
			t.Errorf("%s: content was altered", key)
		}
	}
}

func pemType(t *testing.T, body []byte) string {
	t.Helper()
	block, _ := pem.Decode(body)
	if block == nil {
		return ""
	}
	return block.Type
}

func parsePEMChain(body []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(body) > 0 {
		var block *pem.Block
		block, body = pem.Decode(body)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
