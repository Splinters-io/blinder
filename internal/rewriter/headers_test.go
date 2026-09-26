package rewriter

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestRewriteResponseHeaders_PassthroughTechHeaders(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, nil, "alias.local")
	headers := http.Header{
		"Server":                    {"nginx/1.25"},
		"X-Powered-By":              {"Express"},
		"X-Content-Type-Options":    {"nosniff"},
		"X-Frame-Options":           {"DENY"},
		"Strict-Transport-Security": {"max-age=31536000"},
	}

	out := RewriteResponseHeaders(headers, gate, "alias.local", "target.com")

	if out.Get("Server") != "nginx/1.25" {
		t.Errorf("Server should pass through, got: %s", out.Get("Server"))
	}
	if out.Get("X-Powered-By") != "Express" {
		t.Errorf("X-Powered-By should pass through, got: %s", out.Get("X-Powered-By"))
	}
	if out.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options should pass through")
	}
}

func TestRewriteResponseHeaders_ScrubLocation(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, nil, "alias.local")
	headers := http.Header{
		"Location": {"https://target.com/new-page"},
	}

	out := RewriteResponseHeaders(headers, gate, "alias.local", "target.com")
	loc := out.Get("Location")
	if strings.Contains(loc, "target.com") {
		t.Errorf("Location should be scrubbed, got: %s", loc)
	}
}

func TestRewriteResponseHeaders_CSPRewrite(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, nil, "alias.local")
	headers := http.Header{
		"Content-Security-Policy": {"default-src 'self'; script-src 'unsafe-inline' target.com cdn.target.com; style-src 'self' data:"},
	}

	out := RewriteResponseHeaders(headers, gate, "alias.local", "target.com")
	csp := out.Get("Content-Security-Policy")

	if !strings.Contains(csp, "'self'") {
		t.Error("CSP 'self' keyword should be preserved")
	}
	if !strings.Contains(csp, "'unsafe-inline'") {
		t.Error("CSP 'unsafe-inline' keyword should be preserved")
	}
	if !strings.Contains(csp, "data:") {
		t.Error("CSP data: scheme should be preserved")
	}
	if strings.Contains(csp, "target.com") {
		t.Errorf("CSP domain should be scrubbed, got: %s", csp)
	}
}

func TestRewriteResponseHeaders_CSPNonces(t *testing.T) {
	gate := scrub.NewGate(nil, nil, "alias.local")
	headers := http.Header{
		"Content-Security-Policy": {"script-src 'nonce-abc123' 'sha256-xyz789='"},
	}

	out := RewriteResponseHeaders(headers, gate, "alias.local", "target.com")
	csp := out.Get("Content-Security-Policy")

	if !strings.Contains(csp, "'nonce-abc123'") {
		t.Error("CSP nonce should be preserved")
	}
	if !strings.Contains(csp, "'sha256-xyz789='") {
		t.Error("CSP hash should be preserved")
	}
}

func TestRewriteResponseHeaders_SetCookie(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, nil, "alias.local")
	headers := http.Header{
		"Set-Cookie": {"session_id=abc123; Domain=target.com; Path=/; HttpOnly; Secure"},
	}

	out := RewriteResponseHeaders(headers, gate, "alias.local", "target.com")
	cookie := out.Get("Set-Cookie")

	if strings.Contains(cookie, "session_id=") {
		t.Error("cookie name should be hashed")
	}
	if !strings.Contains(cookie, "ck_") {
		t.Errorf("cookie name should start with ck_, got: %s", cookie)
	}
	if strings.Contains(cookie, "Domain=") {
		t.Errorf("cookie Domain should be stripped for loopback compatibility, got: %s", cookie)
	}
	if !strings.Contains(cookie, "HttpOnly") {
		t.Error("cookie flags should be preserved")
	}
	if !strings.Contains(cookie, "Secure") {
		t.Error("cookie flags should be preserved")
	}
}

func TestRewriteResponseHeaders_MultiValueHeaders(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, nil, "alias.local")
	headers := http.Header{
		"Set-Cookie": {
			"a=1; Domain=target.com; Path=/",
			"b=2; Domain=target.com; Path=/api",
		},
	}

	out := RewriteResponseHeaders(headers, gate, "alias.local", "target.com")
	cookies := out.Values("Set-Cookie")
	if len(cookies) != 2 {
		t.Fatalf("expected 2 Set-Cookie headers, got %d", len(cookies))
	}
	for _, c := range cookies {
		if strings.Contains(c, "Domain=target.com") {
			t.Errorf("all cookie domains should be rewritten, got: %s", c)
		}
	}
}

func TestRewriteResponseHeaders_PreservesApplicationDiagnostics(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, []string{"AcmeCorp"}, "alias.local")
	headers := http.Header{
		"Server":                {"nginx"},
		"X-Custom-Internal":     {"AcmeCorp: INVALID_INPUT", "dependency target.com unavailable"},
		"X-Internal-Request-Id": {"12345"},
		"X-Diagnostic-Code":     {"VALIDATION_FAILED"},
		"Allow":                 {"GET, POST, PATCH, PROPFIND"},
	}

	out := RewriteResponseHeaders(headers, gate, "alias.local", "target.com")

	if out.Get("Server") != "nginx" {
		t.Error("Server should pass through")
	}
	got := out.Values("X-Custom-Internal")
	if len(got) != 2 || !strings.Contains(got[0], "INVALID_INPUT") || !strings.Contains(got[1], "unavailable") {
		t.Fatalf("application diagnostics or duplicate values lost: %v", got)
	}
	if strings.Contains(strings.Join(got, ";"), "AcmeCorp") || strings.Contains(strings.Join(got, ";"), "target.com") {
		t.Fatalf("configured header redaction omitted: %v", got)
	}
	for _, name := range []string{"X-Internal-Request-Id", "X-Diagnostic-Code", "Allow"} {
		if out.Get(name) != headers.Get(name) {
			t.Errorf("end-to-end %s changed: %q", name, out.Get(name))
		}
	}
	out["X-Custom-Internal"][0] = "edited"
	if headers["X-Custom-Internal"][0] != "AcmeCorp: INVALID_INPUT" {
		t.Fatal("response headers share mutable values with upstream")
	}
}

func TestRewriteResponseHeaders_SetCookieValueScrub(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, []string{"AcmeCorp"}, "alias.local")
	headers := http.Header{
		"Set-Cookie": {"session=tok-AcmeCorp-xyz; Path=/; HttpOnly"},
	}

	out := RewriteResponseHeaders(headers, gate, "alias.local", "target.com")
	cookie := out.Get("Set-Cookie")

	if strings.Contains(cookie, "AcmeCorp") {
		t.Errorf("cookie value should have identity token scrubbed, got: %s", cookie)
	}
	if !strings.Contains(cookie, "[REDACTED:") {
		t.Errorf("cookie value should contain reversible alias, got: %s", cookie)
	}
	if !strings.Contains(cookie, "HttpOnly") {
		t.Error("cookie attributes should be preserved")
	}
}

func TestRewriteRequestHeaders_CookieValueRestored(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, []string{"AcmeCorp"}, "alias.local")

	respHeaders := http.Header{
		"Set-Cookie": {"session=tok-AcmeCorp-xyz; Path=/; HttpOnly"},
	}
	RewriteResponseHeaders(respHeaders, gate, "alias.local", "target.com")

	aliasedName := gate.AliasCookieNameAndRecord("session")
	scrubbedVal := gate.Scrub("tok-AcmeCorp-xyz", "cookie:value")
	req, _ := http.NewRequest("GET", "https://alias.local/page", nil)
	req.Header.Set("Cookie", aliasedName+"="+scrubbedVal)

	origins := mustMapper(t, &url.URL{Scheme: "https", Host: "target.com"}, "127.0.0.1:443", "alias.local")
	rewritten := RewriteRequestHeaders(req, "target.com", gate, origins)

	cookieHeader := rewritten.Header.Get("Cookie")
	if !strings.Contains(cookieHeader, "tok-AcmeCorp-xyz") {
		t.Errorf("cookie value should be restored to original, got: %s", cookieHeader)
	}
	if strings.Contains(cookieHeader, "[REDACTED:") {
		t.Errorf("cookie value should not contain alias after restoration, got: %s", cookieHeader)
	}
}

func TestRewriteResponseHeaders_CORSACAOMapsToLocal(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, nil, "alias.local")
	origins := mustMapper(t, &url.URL{Scheme: "https", Host: "target.com"}, "127.0.0.1:8099", "alias.local")
	headers := http.Header{
		"Access-Control-Allow-Origin": {"https://target.com"},
	}

	out := RewriteResponseHeaders(headers, gate, "alias.local", "target.com",
		ResponseHeaderOpts{OriginMapper: origins})
	acao := out.Get("Access-Control-Allow-Origin")

	if strings.Contains(acao, "target.com") {
		t.Errorf("ACAO should be mapped to local origin, got: %s", acao)
	}
	if !strings.Contains(acao, "alias.local:8099") {
		t.Errorf("ACAO should contain alias domain, got: %s", acao)
	}
}

func TestRewriteResponseHeaders_LocationOriginAware(t *testing.T) {
	gate := scrub.NewGate([]string{"app.example.com"}, nil, "alias.local")
	origins := mustMapper(t,
		&url.URL{Scheme: "https", Host: "app.example.com"},
		"127.0.0.1:8099", "alias.local",
	)
	headers := http.Header{
		"Location": {"https://app.example.com/dashboard?ref=login"},
	}

	out := RewriteResponseHeaders(headers, gate, "alias.local", "app.example.com",
		ResponseHeaderOpts{OriginMapper: origins})
	loc := out.Get("Location")

	if strings.Contains(loc, "app.example.com") {
		t.Errorf("Location should have upstream origin replaced, got: %s", loc)
	}
	if !strings.Contains(loc, "alias.local:8099") {
		t.Errorf("Location should use alias domain, got: %s", loc)
	}
	if !strings.Contains(loc, "/dashboard") {
		t.Errorf("Location path should be preserved, got: %s", loc)
	}
	if !strings.Contains(loc, "ref=login") {
		t.Errorf("Location query should be preserved, got: %s", loc)
	}
}

func TestRewriteResponseHeaders_CORSACAOMapsToAliasDomain(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, nil, "alias.local")
	origins := mustMapper(t,&url.URL{Scheme: "https", Host: "target.com"}, "127.0.0.1:8099", "alias.local")
	headers := http.Header{
		"Access-Control-Allow-Origin": {"https://target.com"},
	}

	out := RewriteResponseHeaders(headers, gate, "alias.local", "target.com",
		ResponseHeaderOpts{OriginMapper: origins})
	acao := out.Get("Access-Control-Allow-Origin")

	if !strings.Contains(acao, "alias.local") {
		t.Errorf("ACAO should map to alias domain origin, got: %s", acao)
	}
	if strings.Contains(acao, "127.0.0.1") {
		t.Errorf("ACAO should not use raw IP when alias domain exists, got: %s", acao)
	}
}

func TestRewriteResponseHeaders_CORSACAOWildcardPreserved(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, nil, "alias.local")
	origins := mustMapper(t,&url.URL{Scheme: "https", Host: "target.com"}, "127.0.0.1:8099", "alias.local")
	headers := http.Header{
		"Access-Control-Allow-Origin": {"*"},
	}

	out := RewriteResponseHeaders(headers, gate, "alias.local", "target.com",
		ResponseHeaderOpts{OriginMapper: origins})
	if out.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("ACAO wildcard should be preserved, got: %s", out.Get("Access-Control-Allow-Origin"))
	}
}

func TestRewriteResponseHeaders_CORSACAOUnrelatedOriginUntouched(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, nil, "alias.local")
	origins := mustMapper(t,&url.URL{Scheme: "https", Host: "target.com"}, "127.0.0.1:8099", "alias.local")
	headers := http.Header{
		"Access-Control-Allow-Origin": {"https://other-site.com"},
	}

	out := RewriteResponseHeaders(headers, gate, "alias.local", "target.com",
		ResponseHeaderOpts{OriginMapper: origins})
	acao := out.Get("Access-Control-Allow-Origin")
	if strings.Contains(acao, "127.0.0.1") {
		t.Errorf("unrelated ACAO should not be mapped to local, got: %s", acao)
	}
}

func TestRewriteResponseHeaders_CORSACAOMatchesRequestOrigin(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, nil, "alias.local")
	origins := mustMapper(t,&url.URL{Scheme: "https", Host: "target.com"}, "127.0.0.1:8099", "alias.local")

	for _, tc := range []struct {
		name, requestOrigin, wantACAO string
	}{
		{"localhost", "https://localhost:8099", "https://localhost:8099"},
		{"loopback", "https://127.0.0.1:8099", "https://127.0.0.1:8099"},
		{"alias", "https://alias.local:8099", "https://alias.local:8099"},
		{"no request origin", "", "https://alias.local:8099"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{"Access-Control-Allow-Origin": {"https://target.com"}}
			out := RewriteResponseHeaders(headers, gate, "alias.local", "target.com",
				ResponseHeaderOpts{OriginMapper: origins, RequestOrigin: tc.requestOrigin})
			got := out.Get("Access-Control-Allow-Origin")
			if got != tc.wantACAO {
				t.Errorf("ACAO = %q; want %q", got, tc.wantACAO)
			}
		})
	}
}

func TestRewriteResponseHeaders_CORSACAOUnknownUpstreamScrubbed(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, nil, "alias.local")
	origins := mustMapper(t, &url.URL{Scheme: "https", Host: "target.com"}, "127.0.0.1:8099", "alias.local")
	headers := http.Header{
		"Access-Control-Allow-Origin": {"https://subdomain.target.com"},
	}

	out := RewriteResponseHeaders(headers, gate, "alias.local", "target.com",
		ResponseHeaderOpts{OriginMapper: origins})
	acao := out.Get("Access-Control-Allow-Origin")

	if strings.Contains(acao, "target.com") {
		t.Errorf("ACAO with non-registered upstream subdomain should be scrubbed to prevent identity leak, got: %s", acao)
	}
}

func TestRewriteResponseHeaders_CORSNegativeCasePreserved(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, nil, "alias.local")
	origins := mustMapper(t, &url.URL{Scheme: "https", Host: "target.com"}, "127.0.0.1:8099", "alias.local")

	out := RewriteResponseHeaders(http.Header{}, gate, "alias.local", "target.com",
		ResponseHeaderOpts{OriginMapper: origins})
	if out.Get("Access-Control-Allow-Origin") != "" {
		t.Error("absent ACAO should not be fabricated by the proxy")
	}
}

func TestRewriteRequestHeaders(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://alias.local/path", nil)
	req.Header.Set("Referer", "https://alias.local/previous")
	req.Header.Set("Origin", "https://alias.local")
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	gate := scrub.NewGate(nil, nil, "alias.local")
	rewritten := RewriteRequestHeaders(req, "target.com", gate, mustMapper(t,&url.URL{Scheme: "https", Host: "target.com"}, "127.0.0.1:443", "alias.local"))

	if rewritten.Host != "target.com" {
		t.Errorf("host should be target, got: %s", rewritten.Host)
	}
	if !strings.Contains(rewritten.Header.Get("Referer"), "target.com") {
		t.Errorf("referer should use target domain, got: %s", rewritten.Header.Get("Referer"))
	}
	if !strings.Contains(rewritten.Header.Get("Origin"), "target.com") {
		t.Errorf("origin should use target domain, got: %s", rewritten.Header.Get("Origin"))
	}
	if rewritten.Header.Get("Accept-Encoding") != "" {
		t.Error("Accept-Encoding should be removed to get uncompressed responses")
	}
}
