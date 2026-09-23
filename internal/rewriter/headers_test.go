package rewriter

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestRewriteResponseHeaders_PassthroughTechHeaders(t *testing.T) {
	gate := scrub.NewGate([]string{"target.com"}, nil, "alias.local")
	headers := http.Header{
		"Server":                 {"nginx/1.25"},
		"X-Powered-By":          {"Express"},
		"X-Content-Type-Options": {"nosniff"},
		"X-Frame-Options":       {"DENY"},
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
	if strings.Contains(cookie, "Domain=target.com") {
		t.Error("cookie domain should be rewritten")
	}
	if !strings.Contains(cookie, "Domain=alias.local") {
		t.Errorf("cookie domain should be alias, got: %s", cookie)
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

func TestRewriteResponseHeaders_DropsUnknownHeaders(t *testing.T) {
	gate := scrub.NewGate(nil, nil, "alias.local")
	headers := http.Header{
		"Server":                 {"nginx"},
		"X-Custom-Internal":     {"secret-value"},
		"X-Internal-Request-Id": {"12345"},
	}

	out := RewriteResponseHeaders(headers, gate, "alias.local", "target.com")

	if out.Get("Server") != "nginx" {
		t.Error("Server should pass through")
	}
	if out.Get("X-Custom-Internal") != "" {
		t.Error("unknown headers should be dropped")
	}
	if out.Get("X-Internal-Request-Id") != "" {
		t.Error("unknown headers should be dropped")
	}
}

func TestRewriteRequestHeaders(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://alias.local/path", nil)
	req.Header.Set("Referer", "https://alias.local/previous")
	req.Header.Set("Origin", "https://alias.local")
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	gate := scrub.NewGate(nil, nil, "alias.local")
	rewritten := RewriteRequestHeaders(req, "target.com", "alias.local", gate)

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
