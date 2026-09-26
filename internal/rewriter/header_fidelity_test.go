package rewriter

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestResponseHeaderFidelityDropsConnectionFieldsBeforeSpecialCases(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, []string{"AcmeCorp"}, "alias.local")
	headers := http.Header{
		// Exercise multiple field lines, case-insensitive names, whitespace and
		// nominations of both known/special and unknown response fields.
		"cOnNeCtIoN":                {"keep-alive, X-Hop-Diagnostic, LOCATION", " Set-Cookie , Content-Security-Policy, X-Powered-By "},
		"Keep-Alive":                {"timeout=30"},
		"Proxy-Connection":          {"close"},
		"Proxy-Authenticate":        {`Basic realm="proxy"`},
		"Proxy-Authorization":       {"Basic secret"},
		"Proxy-Authentication-Info": {"nextnonce=secret"},
		"Te":                        {"trailers"},
		"Trailer":                   {"X-Trailer-Diagnostic"},
		"Transfer-Encoding":         {"chunked"},
		"Upgrade":                   {"h2c"},
		"X-Hop-Diagnostic":          {"hop-local"},
		"Location":                  {"https://target.com/next"},
		"Set-Cookie":                {"session=abc; HttpOnly"},
		"Content-Security-Policy":   {"default-src 'self'"},
		"X-Powered-By":              {"AcmeCorp"},
		"X-End-To-End":              {"E_DEPENDENCY"},
	}
	initialCount := len(headers)
	got := RewriteResponseHeaders(headers, gate, "alias.local", "target.com")
	if len(got) != 1 || got.Get("X-End-To-End") != "E_DEPENDENCY" {
		t.Fatalf("hop-specific response fields reached downstream: %v", got)
	}
	if len(headers) != initialCount || headers.Get("Location") != "https://target.com/next" {
		t.Fatal("upstream evidence was mutated while removing transport fields")
	}
}

func TestResponseHeaderFidelityDropsInvalidatedRepresentationMetadata(t *testing.T) {
	gate := scrub.NewGate(nil, nil, "alias.local")
	headers := http.Header{
		"Content-Length":      {"9000"},
		"Content-Encoding":    {"gzip"},
		"Etag":                {`"upstream-representation"`},
		"Last-Modified":       {"Tue, 01 Sep 2026 10:00:00 GMT"},
		"Accept-Ranges":       {"bytes"},
		"Content-Range":       {"bytes 0-99/9000"},
		"Content-Md5":         {"upstream-checksum"},
		"Digest":              {"sha-256=upstream-checksum"},
		"Content-Digest":      {"sha-256=:upstream-checksum:"},
		"Repr-Digest":         {"sha-256=:upstream-checksum:"},
		"Signature":           {"sig1=:upstream-signature:"},
		"Signature-Input":     {`sig1=("content-digest")`},
		"Authentication-Info": {`qop=auth-int, rspauth="original-body-hash"`},
		"Content-Type":        {"application/problem+json"},
		"Retry-After":         {"30"},
	}
	got := RewriteResponseHeaders(headers, gate, "alias.local", "target.com")
	if len(got) != 2 || got.Get("Content-Type") != "application/problem+json" || got.Get("Retry-After") != "30" {
		t.Fatalf("invalid representation metadata survived: %v", got)
	}
}

func TestResponseHeaderFidelityDoesNotEnableOriginBoundControls(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, nil, "alias.local")
	headers := http.Header{
		"Alt-Svc":             {`h3="target.com:443"`},
		"Alt-Used":            {"target.com:443"},
		"Nel":                 {`{"report_to":"errors","max_age":3600}`},
		"Report-To":           {`{"group":"errors","endpoints":[{"url":"https://target.com/report"}]}`},
		"Reporting-Endpoints": {`errors="https://target.com/report"`},
		"X-Diagnostic":        {"ordinary diagnostic"},
	}
	got := RewriteResponseHeaders(headers, gate, "alias.local", "target.com")
	if len(got) != 1 || got.Get("X-Diagnostic") != "ordinary diagnostic" {
		t.Fatalf("generic application-header fallback enabled origin-bound controls: %v", got)
	}
}

func TestResponseHeaderFidelityPreservesCaseInsensitiveUnknownValues(t *testing.T) {
	gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	headers := http.Header{"x-app-error": {"AcmeCorp: E_INPUT", "E_RETRY"}}
	got := RewriteResponseHeaders(headers, gate, "alias.local", "target.com")
	values := got.Values("X-App-Error")
	if len(values) != 2 || !strings.Contains(values[0], "E_INPUT") || strings.Contains(values[0], "AcmeCorp") || values[1] != "E_RETRY" {
		t.Fatalf("application field lost its case-insensitive semantics or values: %v", got)
	}
}

func TestResponseHeaderFidelitySuppressesConfiguredIdentityInUnknownNames(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, []string{"AcmeCorp"}, "alias.local")
	headers := http.Header{
		"X-AcmeCorp-Diagnostic":   {"E_INPUT"},
		"x-aCmEcOrP-error":        {"E_RETRY"},
		"X-target.com-Diagnostic": {"E_DEPENDENCY"},
		"X-Diagnostic":            {"E_INPUT", "E_RETRY"},
		"X-Application-Error":     {"AcmeCorp: E_DEPENDENCY"},
	}
	got := RewriteResponseHeaders(headers, gate, "alias.local", "target.com")
	for name := range got {
		if gate.ResidualLeakCount(name) > 0 {
			t.Fatalf("formerly suppressed identity-bearing header name disclosed: %q", name)
		}
	}
	if len(got) != 2 {
		t.Fatalf("expected only identity-bearing unknown names to be suppressed: %v", got)
	}
	values := got.Values("X-Diagnostic")
	if len(values) != 2 || values[0] != "E_INPUT" || values[1] != "E_RETRY" {
		t.Fatalf("ordinary diagnostic values or multiplicity changed: %v", values)
	}
	if value := got.Get("X-Application-Error"); !strings.Contains(value, "E_DEPENDENCY") || strings.Contains(value, "AcmeCorp") {
		t.Fatalf("ordinary named header lost its redacted diagnostic: %q", value)
	}
}
