package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	cgpapi "github.com/gmyzovsky/go-cgp-api"
	cgpdata "github.com/gmyzovsky/go-cgp-data"
)

// archiveDomain saves the domain's current key and certificates from
// its stored settings into the File Storage archive before they are
// replaced, one PEM file per WebAdmin field:
//
//	<path>/archive/<domain>/<stamp>-privkey.pem
//	<path>/archive/<domain>/<stamp>-cert.pem
//	<path>/archive/<domain>/<stamp>-chain.pem
//
// Putting one back is then a copy and a paste: the domain's Security
// page takes each of the three as PEM text, which is the whole point of
// keeping an archive at all. A directory per domain keeps its history
// in one place on a node carrying hundreds of them; CommuniGate Pro
// creates the intervening directories on write, so a fresh
// installation needs no preparation.
func archiveDomain(ctx context.Context, c *cgpapi.Client, storagePath, domain string, verbose bool) error {
	out, err := c.GetDomainSettings(ctx, &cgpapi.GetDomainSettingsInput{DomainName: domain})
	if err != nil {
		return err
	}
	stamp := time.Now().UTC().Format("20060102-150405Z")
	archived := 0
	for _, key := range []string{"PrivateSecureKey", "SecureCertificate", "CAChain"} {
		v, ok := out.Settings.Get(key)
		if !ok {
			continue
		}
		der, err := settingBytes(v)
		if err != nil {
			return fmt.Errorf("archiving %s of %s: %w", key, domain, err)
		}
		if len(der) == 0 {
			continue
		}
		suffix, content := archiveFile(key, der)
		name := fmt.Sprintf("%s/archive/%s/%s-%s", storagePath, domain, stamp, suffix)
		if _, err := c.WriteStorageFile(ctx, &cgpapi.WriteStorageFileInput{
			AccountName: "*",
			FileName:    name,
			Content:     content,
		}); err != nil {
			return fmt.Errorf("archiving %s of %s: %w", key, domain, err)
		}
		archived++
	}
	if verbose && archived > 0 {
		fmt.Printf("MAIN [ %s ] archived %d objects\n", domain, archived)
	}
	return nil
}

// archiveFile renders one stored setting as the file to keep: PEM
// under the name of the WebAdmin field it came from. A key is labelled
// by what it actually is, since a key installed by hand may be PKCS#8
// where this tool writes PKCS#1, and CAChain is a run of certificates
// that has to be split into a block each. Anything that will not parse
// is kept as the raw DER rather than labelled wrongly - an archive that
// lies is worse than one that needs openssl.
func archiveFile(key string, der []byte) (suffix string, content []byte) {
	switch key {
	case "PrivateSecureKey":
		block := "RSA PRIVATE KEY"
		if _, err := x509.ParsePKCS1PrivateKey(der); err != nil {
			if _, err := x509.ParsePKCS8PrivateKey(der); err != nil {
				return "privkey.der", der
			}
			block = "PRIVATE KEY"
		}
		return "privkey.pem", pem.EncodeToMemory(&pem.Block{Type: block, Bytes: der})
	case "SecureCertificate":
		if body, ok := certificatesToPEM(der); ok {
			return "cert.pem", body
		}
		return "cert.der", der
	default: // CAChain
		if body, ok := certificatesToPEM(der); ok {
			return "chain.pem", body
		}
		return "chain.der", der
	}
}

// certificatesToPEM encodes a run of concatenated DER certificates -
// how CommuniGate Pro stores a CA chain - as consecutive PEM blocks,
// the form its CA Chain field expects back.
func certificatesToPEM(der []byte) ([]byte, bool) {
	certs, err := x509.ParseCertificates(der)
	if err != nil || len(certs) == 0 {
		return nil, false
	}
	var out []byte
	for _, cert := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return out, true
}

// installCertificate installs the new key and certificate chain into
// the domain settings and force-enables PKI Services.
func installCertificate(ctx context.Context, c *cgpapi.Client, domain string, keyDER []byte, chain [][]byte) error {
	leaf := chain[0]
	var ca []byte
	for _, der := range chain[1:] {
		ca = append(ca, der...)
	}
	settings := cgpdata.Dictionary{
		{Key: "CertificateType", Value: cgpdata.String("YES")},
		{Key: "PrivateSecureKey", Value: datablockString(keyDER)},
		{Key: "SecureCertificate", Value: datablockString(leaf)},
		{Key: "CAChain", Value: datablockString(ca)},
	}
	_, err := c.UpdateDomainSettings(ctx, &cgpapi.UpdateDomainSettingsInput{
		DomainName: domain,
		Settings:   settings,
	})
	return err
}

// reportCertificate is what a staging run does instead of installing:
// it describes the certificate that was issued and, when verbose,
// prints the chain in PEM. A test CA's certificate has no business in a
// live domain - and writing settings is not the part of the cycle worth
// rehearsing, unlike validation and issuance, which have just been
// exercised for real. The private key is deliberately not printed: it
// is of no use without an install, and stdout tends to end up in logs.
func reportCertificate(d *decision, chain [][]byte, verbose bool) error {
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return fmt.Errorf("issued certificate of %s: %w", d.Domain, err)
	}
	fmt.Printf("MAIN [ %s ] staging certificate issued for %v, valid until %s, NOT installed\n",
		d.Domain, leaf.DNSNames, leaf.NotAfter.Format("2006-01-02"))
	if !verbose {
		return nil
	}
	for _, der := range chain {
		if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return err
		}
	}
	return nil
}

// datablockString renders binary data the way the domain settings
// expect it: as a string whose text is a "[base64]" datablock.
func datablockString(der []byte) cgpdata.String {
	return cgpdata.String("[" + base64.StdEncoding.EncodeToString(der) + "]")
}
