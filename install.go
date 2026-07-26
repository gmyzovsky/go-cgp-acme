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
// replaced, as raw DER blobs: <path>/archive/<unix>-<domain>-<key>.der.
// Restoring one is a matter of feeding the blob back into the same
// setting.
func archiveDomain(ctx context.Context, c *cgpapi.Client, storagePath, domain string, verbose bool) error {
	out, err := c.GetDomainSettings(ctx, &cgpapi.GetDomainSettingsInput{DomainName: domain})
	if err != nil {
		return err
	}
	stamp := time.Now().Unix()
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
		name := fmt.Sprintf("%s/archive/%d-%s-%s.der", storagePath, stamp, domain, key)
		if _, err := c.WriteStorageFile(ctx, &cgpapi.WriteStorageFileInput{
			AccountName: "*",
			FileName:    name,
			Content:     der,
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
