package main

import (
	"testing"
	"time"

	cgpdata "github.com/gmyzovsky/go-cgp-data"
)

func TestCertificateNames(t *testing.T) {
	aliases := cgpdata.Array{
		cgpdata.String("www.example.org"),
		cgpdata.String("почта.example.org"),
		cgpdata.String("etc.example.org"),
	}

	got, err := certificateNames("example.org", aliases, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.org", "www.example.org", "xn--80a1acny.example.org", "etc.example.org"}
	if len(got) != len(want) {
		t.Fatalf("names = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("names = %v, want %v", got, want)
		}
	}

	// Either spelling of an excluded alias keeps it out.
	for _, spelling := range []string{"почта.example.org", "xn--80a1acny.example.org"} {
		got, err := certificateNames("example.org", aliases, map[string]bool{spelling: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range got {
			if name == "xn--80a1acny.example.org" {
				t.Errorf("exclude %q left the alias in %v", spelling, got)
			}
		}
	}
}

// An alias no IDNA profile will convert is a real thing to find in a
// CGP domain list. Excluded, it must not be converted at all - it used
// to fail the domain (and, through the caller, the whole run) on a name
// the certificate was never going to carry.
func TestCertificateNamesExcludesBeforeConversion(t *testing.T) {
	aliases := cgpdata.Array{cgpdata.String("lost+found"), cgpdata.String("www.example.org")}

	if _, err := certificateNames("example.org", aliases, nil); err == nil {
		t.Fatal("an unconvertible alias was accepted, want an error")
	}

	got, err := certificateNames("example.org", aliases, map[string]bool{"lost+found": true})
	if err != nil {
		t.Fatalf("an excluded alias still failed the domain: %v", err)
	}
	if len(got) != 2 || got[1] != "www.example.org" {
		t.Errorf("names = %v, want the domain and www.example.org", got)
	}
}

func TestRenewalThreshold(t *testing.T) {
	nb := time.Now()
	const day = 24 * time.Hour
	const third = 1.0 / 3.0

	cases := []struct {
		name     string
		lifetime time.Duration
		fraction float64
		floor    time.Duration
		want     time.Duration
	}{
		{"90d fraction", 90 * day, third, 0, 30 * day},
		{"45d fraction", 45 * day, third, 0, 15 * day},
		{"6d shortlived", 6 * day, third, 0, 2 * day},
		{"floor wins on 2d cert", 2 * day, third, day, day},
		{"fraction wins over small floor", 90 * day, third, day, 30 * day},
		{"fraction disabled uses floor", 90 * day, 0, 720 * time.Hour, 720 * time.Hour},
	}
	for _, tc := range cases {
		got := renewalThreshold(nb, nb.Add(tc.lifetime), tc.fraction, tc.floor)
		// The fraction arithmetic is float-based, so allow a small delta.
		if d := got - tc.want; d < -time.Minute || d > time.Minute {
			t.Errorf("%s: threshold %s, want ~%s", tc.name, got, tc.want)
		}
	}
}
