package main

import (
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// captureStdout runs f with os.Stdout redirected and returns what was
// printed, so a trace can be asserted on instead of cluttering the test
// output.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	printed := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		printed <- string(b)
	}()
	f()
	w.Close()
	os.Stdout = old
	return <-printed
}

// jwsBody wraps a payload the way the ACME client signs one.
func jwsBody(payload string) string {
	return `{"protected":"e30","payload":"` +
		base64.RawURLEncoding.EncodeToString([]byte(payload)) +
		`","signature":"c2ln"}`
}

func TestTraceTransportPassesBodiesThrough(t *testing.T) {
	const payload = `{"identifiers":[{"type":"dns","value":"example.org"}]}`
	// A certificate chain: long, not JSON, and the one body that must
	// come back byte for byte or issuance breaks.
	respBody := strings.Repeat("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", 40)

	var seen string
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading the forwarded request body: %v", err)
		}
		seen = string(b)
		return &http.Response{
			Status:     "200 OK",
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/pem-certificate-chain"}},
			Body:       io.NopCloser(strings.NewReader(respBody)),
		}, nil
	})

	req, err := http.NewRequest(http.MethodPost, "https://ca.example/acme/finalize", strings.NewReader(jwsBody(payload)))
	if err != nil {
		t.Fatal(err)
	}
	var resp *http.Response
	out := captureStdout(t, func() {
		resp, err = newTraceTransport(base).RoundTrip(req)
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen != jwsBody(payload) {
		t.Errorf("the base transport saw %q, want the original request body", seen)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != respBody {
		t.Errorf("response body came back %d bytes, want the original %d", len(got), len(respBody))
	}
	for _, want := range []string{
		"ACME > POST https://ca.example/acme/finalize",
		payload,
		"bytes of application/pem-certificate-chain",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("trace does not mention %q:\n%s", want, out)
		}
	}
	// The chain itself is summarized, never dumped.
	if strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Errorf("trace printed the certificate chain:\n%s", out)
	}
}

func TestTraceTransportPrintsJSONAndHeaders(t *testing.T) {
	const body = `{"status": "invalid", "detail": "no valid A records"}`
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			Status:     "403 Forbidden",
			StatusCode: http.StatusForbidden,
			Header: http.Header{
				"Content-Type": {"application/problem+json"},
				"Location":     {"https://ca.example/acme/order/1"},
				"Retry-After":  {"3"},
			},
			Body: io.NopCloser(strings.NewReader(body)),
		}, nil
	})
	req, err := http.NewRequest(http.MethodGet, "https://ca.example/acme/authz/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if _, err := newTraceTransport(base).RoundTrip(req); err != nil {
			t.Error(err)
		}
	})
	for _, want := range []string{
		"403 Forbidden",
		"Location: https://ca.example/acme/order/1",
		"Retry-After: 3",
		"no valid A records",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("trace does not mention %q:\n%s", want, out)
		}
	}
}

func TestJWSPayload(t *testing.T) {
	const payload = `{"csr":"MIIC"}`
	if got := string(jwsPayload([]byte(jwsBody(payload)))); got != payload {
		t.Errorf("jwsPayload = %q, want %q", got, payload)
	}
	cases := map[string]string{
		"not JSON at all":  "hello",
		"JSON without JWS": `{"status":"valid"}`,
		"POST-as-GET":      `{"protected":"e30","payload":"","signature":"c2ln"}`,
		"broken base64":    `{"protected":"e30","payload":"!!!","signature":"c2ln"}`,
	}
	for name, body := range cases {
		if got := jwsPayload([]byte(body)); got != nil {
			t.Errorf("%s: jwsPayload = %q, want nil", name, got)
		}
	}
}

func TestClipCollapsesAndShortens(t *testing.T) {
	if got := clip([]byte("{\n  \"a\": 1\n}")); got != `{ "a": 1 }` {
		t.Errorf("clip = %q, want the body on one line", got)
	}
	long := clip([]byte(strings.Repeat("x", traceBodyLimit+100)))
	if len(long) != traceBodyLimit+3 || !strings.HasSuffix(long, "...") {
		t.Errorf("clip returned %d characters, want %d and an ellipsis", len(long), traceBodyLimit+3)
	}
}
