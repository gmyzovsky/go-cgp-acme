package main

import (
	"bytes"
	"testing"

	cgpdata "github.com/gmyzovsky/go-cgp-data"
)

func TestSettingBytesFromDataBlock(t *testing.T) {
	got, err := settingBytes(cgpdata.DataBlock("hello"))
	if err != nil || !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("settingBytes(DataBlock) = %q, %v", got, err)
	}
}

func TestSettingBytesFromBracketedString(t *testing.T) {
	// The form GETDOMAINSETTINGS actually returns: a string whose text
	// is a [base64] datablock (verified live on CGP 6.5.6).
	got, err := settingBytes(cgpdata.String("[aGVsbG8=]"))
	if err != nil || !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("settingBytes(String) = %q, %v", got, err)
	}
}

func TestSettingBytesRoundTripsDatablockString(t *testing.T) {
	payload := []byte{0x30, 0x82, 0x01, 0x00, 0xff, 0x00}
	got, err := settingBytes(datablockString(payload))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("round trip = %x, %v, want %x", got, err, payload)
	}
}

func TestSettingBytesRejectsOtherTypes(t *testing.T) {
	if _, err := settingBytes(cgpdata.Number(5)); err == nil {
		t.Fatal("settingBytes(Number) succeeded, want an error")
	}
}
