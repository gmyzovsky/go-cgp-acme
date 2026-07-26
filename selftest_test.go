package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hostOf strips the scheme so a test server's address can stand in for
// the domain name fetchChallenge asks for.
func hostOf(srv *httptest.Server) string { return strings.TrimPrefix(srv.URL, "http://") }

func TestFetchChallengeOutcomes(t *testing.T) {
	const token = "test-token"
	const want = token + ".thumbprint"

	cases := []struct {
		name       string
		handler    http.HandlerFunc
		wantStatus string
		wantPass   bool
	}{
		{
			name: "served",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != challengePath+token {
					t.Errorf("requested %s, want %s", r.URL.Path, challengePath+token)
				}
				w.Write([]byte(want))
			},
			wantStatus: "PASS",
			wantPass:   true,
		},
		{
			name: "trailing newline still passes",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(want + "\n"))
			},
			wantStatus: "PASS",
			wantPass:   true,
		},
		{
			name: "another server answered",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("<html>hello</html>"))
			},
			wantStatus: "MISMATCH",
		},
		{
			name: "challenge not served",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.NotFound(w, r)
			},
			wantStatus: "404",
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			wantStatus: "503",
		},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(tc.handler)
		got := fetchChallenge(context.Background(), hostOf(srv), token, want)
		srv.Close()
		if got.Status != tc.wantStatus || got.Pass != tc.wantPass {
			t.Errorf("%s: got %s/%v (%s), want %s/%v", tc.name, got.Status, got.Pass, got.Comment, tc.wantStatus, tc.wantPass)
		}
		if !got.Pass && got.Comment == "" {
			t.Errorf("%s: failure without a comment", tc.name)
		}
	}
}

func TestFetchChallengeFollowsRedirect(t *testing.T) {
	const token = "test-token"
	const want = token + ".thumbprint"

	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(want))
	}))
	defer final.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+r.URL.Path, http.StatusMovedPermanently)
	}))
	defer first.Close()

	// A CA follows redirects when validating http-01, so the rehearsal
	// must too, or a site that redirects would look broken.
	if got := fetchChallenge(context.Background(), hostOf(first), token, want); !got.Pass {
		t.Errorf("redirected challenge: got %s (%s), want PASS", got.Status, got.Comment)
	}
}

func TestFetchChallengeNothingListening(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := hostOf(srv)
	srv.Close()

	got := fetchChallenge(context.Background(), addr, "test-token", "irrelevant")
	if got.Pass || got.Status != "REFUSED" {
		t.Errorf("closed port: got %s (%s), want REFUSED", got.Status, got.Comment)
	}
}

func TestFetchChallengeUnresolvableName(t *testing.T) {
	// .invalid is reserved and never resolves, the shape of the alias
	// this rehearsal exists to catch.
	got := fetchChallenge(context.Background(), "alias.example.invalid", "test-token", "irrelevant")
	if got.Pass || got.Status != "DNS" {
		t.Errorf("unresolvable name: got %s (%s), want DNS", got.Status, got.Comment)
	}
}

func TestClassifyProbes(t *testing.T) {
	const domain = "example.org"
	pass := func(n string) probe { return probe{Name: n, Pass: true, Status: "PASS"} }
	fail := func(n string) probe { return probe{Name: n, Status: "DNS", Comment: "name does not resolve"} }

	cases := []struct {
		name        string
		probes      []probe
		wantBlocked bool
		wantBad     []string
	}{
		{
			name:   "everything answers",
			probes: []probe{pass(domain), pass("www.example.org")},
		},
		{
			name:    "alias missing from DNS",
			probes:  []probe{pass(domain), fail("www.example.org"), pass("mail.example.org")},
			wantBad: []string{"www.example.org"},
		},
		{
			// Nothing to salvage: a certificate without its own domain
			// is not worth ordering.
			name:        "domain itself unreachable",
			probes:      []probe{fail(domain), pass("www.example.org")},
			wantBlocked: true,
		},
		{
			name:        "domain and alias unreachable",
			probes:      []probe{fail(domain), fail("www.example.org")},
			wantBlocked: true,
		},
	}
	for _, tc := range cases {
		blocker, bad := classifyProbes(domain, tc.probes)
		if (blocker != nil) != tc.wantBlocked {
			t.Errorf("%s: blocker %v, want blocked=%v", tc.name, blocker, tc.wantBlocked)
		}
		if blocker != nil && blocker.Name != domain {
			t.Errorf("%s: blocker is %s, want the domain itself", tc.name, blocker.Name)
		}
		if tc.wantBlocked {
			continue
		}
		if len(bad) != len(tc.wantBad) {
			t.Errorf("%s: %d bad alias(es), want %d", tc.name, len(bad), len(tc.wantBad))
			continue
		}
		for i, want := range tc.wantBad {
			if bad[i].Name != want {
				t.Errorf("%s: bad alias %d is %s, want %s", tc.name, i, bad[i].Name, want)
			}
		}
	}
}

func TestRandomToken(t *testing.T) {
	seen := make(map[string]bool, 16)
	for i := 0; i < 16; i++ {
		tok, err := randomToken(43)
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) != 43 {
			t.Fatalf("token %q is %d characters, want 43", tok, len(tok))
		}
		if strings.ContainsFunc(tok, func(r rune) bool { return !strings.ContainsRune(tokenAlphabet, r) }) {
			t.Errorf("token %q leaves the ACME token alphabet", tok)
		}
		if seen[tok] {
			t.Errorf("token %q repeated", tok)
		}
		seen[tok] = true
	}
}
