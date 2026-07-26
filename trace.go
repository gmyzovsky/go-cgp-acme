package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// traceBodyLimit caps how much of a body is printed. Bodies are always
// read and restored in full - only the printing is cut short, since a
// certificate chain is long and says nothing a summary line does not.
const traceBodyLimit = 2048

// traceTransport prints the ACME exchange: one line per request, one
// per response, plus the JSON both carry. It is installed as the ACME
// client's HTTP transport at the second -verbose level and does nothing
// else - the request and response bodies are handed on untouched.
type traceTransport struct{ base http.RoundTripper }

func (t *traceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	sent, err := readAndRestore(&req.Body)
	if err != nil {
		return nil, err
	}
	if req.Body != nil {
		req.ContentLength = int64(len(sent))
	}
	fmt.Printf("ACME > %s %s\n", req.Method, req.URL)
	// What a request carries is the JWS payload; the protected header
	// and signature are noise once the payload is readable.
	if payload := jwsPayload(sent); len(payload) > 0 {
		fmt.Printf("ACME >   %s\n", clip(payload))
	}

	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		fmt.Printf("ACME < %v\n", err)
		return nil, err
	}
	fmt.Printf("ACME < %s (%dms)\n", resp.Status, time.Since(start).Milliseconds())
	for _, h := range []string{"Location", "Retry-After"} {
		if v := resp.Header.Get(h); v != "" {
			fmt.Printf("ACME <   %s: %s\n", h, v)
		}
	}

	received, err := readAndRestore(&resp.Body)
	if err != nil {
		return resp, err
	}
	switch {
	case len(received) == 0:
	case strings.Contains(resp.Header.Get("Content-Type"), "json"):
		fmt.Printf("ACME <   %s\n", clip(received))
	default:
		// A certificate chain, most likely: its arrival is the news.
		fmt.Printf("ACME <   %d bytes of %s\n", len(received), resp.Header.Get("Content-Type"))
	}
	return resp, nil
}

// newTraceTransport wraps base, or http.DefaultTransport when base is
// nil, in the tracing round tripper.
func newTraceTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &traceTransport{base: base}
}

// readAndRestore consumes a request or response body and puts an
// identical one back in its place, so tracing stays invisible to the
// ACME client reading it afterwards.
func readAndRestore(body *io.ReadCloser) ([]byte, error) {
	if *body == nil {
		return nil, nil
	}
	b, err := io.ReadAll(*body)
	(*body).Close()
	*body = io.NopCloser(bytes.NewReader(b))
	return b, err
}

// jwsPayload decodes the payload of a JWS request body - the actual
// ACME request. Returns nil for a body that is not a JWS, and for the
// empty payload of a POST-as-GET.
func jwsPayload(b []byte) []byte {
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(b, &jws); err != nil || jws.Payload == "" {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return nil
	}
	return payload
}

// clip renders a body as one line, shortened to traceBodyLimit.
func clip(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > traceBodyLimit {
		return s[:traceBodyLimit] + "..."
	}
	return s
}
