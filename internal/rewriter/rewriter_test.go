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
	if strings.Contains(string(result.Body), "target.example.com") {
		t.Error("domain should be scrubbed from HTML")
	}
}

func TestRewriteBody_HTMLScrubsTitle(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<html><head><title>AcmeCorp Admin</title></head></html>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	if strings.Contains(string(result.Body), "AcmeCorp") {
		t.Error("identity token should be scrubbed from title")
	}
	if !strings.Contains(string(result.Body), "[Blinder: title removed]") {
		t.Error("title should be replaced")
	}
}

func TestRewriteBody_HTMLStripsComments(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<html><!-- internal: build v3.2.1 by dev@target.example.com --><body>hi</body></html>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	if strings.Contains(string(result.Body), "internal:") {
		t.Error("HTML comments should be stripped")
	}
}

func TestRewriteBody_HTMLPreservesFormStructure(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<form action="/login" method="post"><input type="text" name="username"><input type="password" name="password"><input type="hidden" name="csrf_token" value="abc123"></form>`)
	result := RewriteBody(body, "text/html", "/login", gate, false)
	resultStr := string(result.Body)
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
	resultStr := string(result.Body)
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
	resultStr := string(result.Body)
	if strings.Contains(resultStr, "quarterly earnings") {
		t.Error("paranoid mode should replace text content")
	}
}

func TestRewriteBody_JSONScrubs(t *testing.T) {
	gate := newTestGate()
	body := []byte(`{"company":"AcmeCorp","domain":"target.example.com"}`)
	result := RewriteBody(body, "application/json", "/api", gate, false)
	resultStr := string(result.Body)
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
	if strings.Contains(string(result.Body), "target.example.com") {
		t.Error("domain in CSS url() should be scrubbed")
	}
}

func TestRewriteBody_ImageReplacement(t *testing.T) {
	gate := newTestGate()
	body := []byte("fake jpeg data with AcmeCorp identity")
	result := RewriteBody(body, "image/jpeg", "/photo.jpg", gate, false)
	if string(result.Body) == string(body) {
		t.Error("image should be replaced, not passed through")
	}
	if result.Body[0] != 0x47 || result.Body[1] != 0x49 || result.Body[2] != 0x46 {
		t.Error("should be replaced with GIF header")
	}
	if result.Metadata == nil {
		t.Error("image replacement should produce metadata")
	}
}

func TestRewriteBody_UnknownContentType(t *testing.T) {
	gate := newTestGate()
	body := []byte("random data with AcmeCorp and target.example.com in it")
	result := RewriteBody(body, "application/octet-stream", "/file.bin", gate, false)
	resultStr := string(result.Body)
	if strings.Contains(resultStr, "AcmeCorp") {
		t.Error("identity token should be scrubbed even from unknown content types")
	}
}

func TestRewriteBody_PDFMetadata(t *testing.T) {
	gate := newTestGate()
	body := []byte("%PDF-1.7\n/JavaScript (alert)\n/Author (Secret Agent)\n%%EOF")
	result := RewriteBody(body, "application/pdf", "/doc.pdf", gate, false)
	if result.Metadata == nil {
		t.Fatal("PDF should produce metadata")
	}
	if result.Metadata.Format != "pdf" {
		t.Errorf("expected format 'pdf', got %q", result.Metadata.Format)
	}
	if !result.Metadata.HasJavaScript {
		t.Error("expected HasJavaScript=true")
	}
	if result.Metadata.Identity.Author != "Secret Agent" {
		t.Errorf("expected identity author 'Secret Agent', got %q", result.Metadata.Identity.Author)
	}
	techJSON := result.Metadata.TechnicalJSON()
	if strings.Contains(techJSON, "Secret Agent") {
		t.Error("technical JSON must not leak identity author")
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
