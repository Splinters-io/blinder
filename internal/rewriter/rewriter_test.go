package rewriter

import (
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func newTestGate() *scrub.Gate {
	return scrub.NewGate(
		[]string{"target.example.com"},
		[]string{"AcmeCorp"},
		"target-001.local",
	)
}

func TestRewriteBody_HTMLScrubsDomains(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<html><body><a href="https://target.example.com/login">Login</a></body></html>`)
	result := RewriteBody(body, "text/html; charset=utf-8", "/", gate, false)
	if strings.Contains(string(result), "target.example.com") {
		t.Error("domain should be scrubbed from HTML")
	}
}

func TestRewriteBody_HTMLScrubsTitle(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<html><head><title>AcmeCorp Admin</title></head></html>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	if strings.Contains(string(result), "AcmeCorp") {
		t.Error("identity token should be scrubbed from title")
	}
	if !strings.Contains(string(result), "[Blinder: title removed]") {
		t.Error("title should be replaced")
	}
}

func TestRewriteBody_HTMLStripsComments(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<html><!-- internal: build v3.2.1 by dev@target.example.com --><body>hi</body></html>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	if strings.Contains(string(result), "internal:") {
		t.Error("HTML comments should be stripped")
	}
}

func TestRewriteBody_HTMLPreservesFormStructure(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<form action="/login" method="post"><input type="text" name="username"><input type="password" name="password"><input type="hidden" name="csrf_token" value="abc123"></form>`)
	result := RewriteBody(body, "text/html", "/login", gate, false)
	resultStr := string(result)
	if !strings.Contains(resultStr, `name="username"`) {
		t.Error("form input names should be preserved")
	}
	if !strings.Contains(resultStr, `name="password"`) {
		t.Error("form input names should be preserved")
	}
	if !strings.Contains(resultStr, `name="csrf_token"`) {
		t.Error("CSRF token field should be preserved")
	}
	if !strings.Contains(resultStr, `method="post"`) {
		t.Error("form method should be preserved")
	}
}

func TestRewriteBody_HTMLReplacesImages(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<img src="https://target.example.com/logo.png" alt="AcmeCorp Logo">`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	resultStr := string(result)
	if strings.Contains(resultStr, "target.example.com/logo.png") {
		t.Error("image src should be replaced")
	}
	if strings.Contains(resultStr, "data:image/gif;base64,") == false {
		t.Error("image should be replaced with data URI")
	}
}

func TestRewriteBody_HTMLParanoidMode(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<html><body><p>This is sensitive internal content about our quarterly earnings</p></body></html>`)
	result := RewriteBody(body, "text/html", "/", gate, true)
	resultStr := string(result)
	if strings.Contains(resultStr, "quarterly earnings") {
		t.Error("paranoid mode should replace text content")
	}
}

func TestRewriteBody_JSONScrubs(t *testing.T) {
	gate := newTestGate()
	body := []byte(`{"company":"AcmeCorp","domain":"target.example.com"}`)
	result := RewriteBody(body, "application/json", "/api", gate, false)
	resultStr := string(result)
	if strings.Contains(resultStr, "AcmeCorp") {
		t.Error("identity token should be scrubbed from JSON")
	}
	if strings.Contains(resultStr, "target.example.com") {
		t.Error("domain should be scrubbed from JSON")
	}
}

func TestRewriteBody_CSSUrlRewrite(t *testing.T) {
	gate := newTestGate()
	body := []byte(`body { background: url("https://target.example.com/bg.png"); }`)
	result := RewriteBody(body, "text/css", "/style.css", gate, false)
	if strings.Contains(string(result), "target.example.com") {
		t.Error("domain in CSS url() should be scrubbed")
	}
}

func TestRewriteBody_ImageReplacement(t *testing.T) {
	gate := newTestGate()
	body := []byte("fake jpeg data with AcmeCorp identity")
	result := RewriteBody(body, "image/jpeg", "/photo.jpg", gate, false)
	if string(result) == string(body) {
		t.Error("image should be replaced, not passed through")
	}
	if result[0] != 0x47 || result[1] != 0x49 || result[2] != 0x46 {
		t.Error("should be replaced with GIF header")
	}
}

func TestRewriteBody_UnknownContentType(t *testing.T) {
	gate := newTestGate()
	body := []byte("random data with AcmeCorp and target.example.com in it")
	result := RewriteBody(body, "application/octet-stream", "/file.bin", gate, false)
	resultStr := string(result)
	if strings.Contains(resultStr, "AcmeCorp") {
		t.Error("identity token should be scrubbed even from unknown content types")
	}
}

func TestNormalizeContentType(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"text/html; charset=utf-8", "text/html"},
		{"application/json", "application/json"},
		{"TEXT/HTML", "text/html"},
		{"text/css ; charset=utf-8", "text/css"},
	}
	for _, tt := range tests {
		got := normalizeContentType(tt.input)
		if got != tt.expect {
			t.Errorf("normalizeContentType(%q) = %q, want %q", tt.input, got, tt.expect)
		}
	}
}
