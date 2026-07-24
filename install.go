package main

import (
	"context"
	"encoding/base64"
	"fmt"
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

// datablockString renders binary data the way the domain settings
// expect it: as a string whose text is a "[base64]" datablock.
func datablockString(der []byte) cgpdata.String {
	return cgpdata.String("[" + base64.StdEncoding.EncodeToString(der) + "]")
}
