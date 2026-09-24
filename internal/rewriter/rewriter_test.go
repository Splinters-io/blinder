package rewriter

import (
	"net/url"
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

func TestRewriteBody_HTMLEntityDecodesBeforeScrub(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<p>Welcome to &#65;cmeCorp headquarters</p>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	resultStr := string(result.Body)
	if strings.Contains(resultStr, "AcmeCorp") || strings.Contains(resultStr, "&#65;cmeCorp") {
		t.Errorf("HTML entity-encoded identity token should be decoded and scrubbed, got: %s", resultStr)
	}
}

func TestRewriteBody_HTMLEntityInAttribute(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<a href="https://target&#46;example&#46;com/login">login</a>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	resultStr := string(result.Body)
	if strings.Contains(resultStr, "target.example.com") || strings.Contains(resultStr, "target&#46;") {
		t.Errorf("entity-encoded domain in attribute should be decoded and scrubbed, got: %s", resultStr)
	}
}

func TestRewriteBody_HTMLPreservesScriptLogic(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<html><script>var x = "AcmeCorp"; if(x) { console.log(x); }</script></html>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	resultStr := string(result.Body)
	if strings.Contains(resultStr, "AcmeCorp") {
		t.Error("identity token in JS string should be scrubbed")
	}
	if !strings.Contains(resultStr, "console.log") {
		t.Error("JS code structure should be preserved")
	}
}

func TestRewriteBody_HTMLBaseHrefScrub(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<html><head><base href="https://target.example.com/"></head></html>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	if strings.Contains(string(result.Body), "target.example.com") {
		t.Error("base href should be scrubbed")
	}
}

func TestRewriteBody_HTMLCanonicalScrub(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<link rel="canonical" href="https://target.example.com/page">`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	if strings.Contains(string(result.Body), "target.example.com") {
		t.Error("canonical link href should be scrubbed")
	}
}

func TestRewriteBody_HTMLDataAttrScrub(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<div data-company="AcmeCorp" data-domain="target.example.com">text</div>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	resultStr := string(result.Body)
	if strings.Contains(resultStr, "AcmeCorp") {
		t.Errorf("data-attr identity token should be scrubbed, got: %s", resultStr)
	}
	if strings.Contains(resultStr, "target.example.com") {
		t.Errorf("data-attr domain should be scrubbed, got: %s", resultStr)
	}
}

func TestRewriteBody_HTMLMetaContentScrub(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<meta name="author" content="AcmeCorp Engineering Team">`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	if strings.Contains(string(result.Body), "AcmeCorp") {
		t.Error("meta content identity should be scrubbed")
	}
}

func TestRewriteBody_HTMLStripsSRIIntegrity(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<script src="/main.bundle" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	resultStr := string(result.Body)
	if strings.Contains(resultStr, "integrity=") {
		t.Error("SRI integrity attribute should be stripped for proxied resources")
	}
	if strings.Contains(resultStr, "crossorigin=") {
		t.Error("crossorigin attribute should be stripped for proxied resources")
	}
	if !strings.Contains(resultStr, `src="`) {
		t.Error("src attribute should be preserved")
	}
}

func TestRewriteBody_HTMLStripsSRIOnLink(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<link rel="stylesheet" href="/styles/main" integrity="sha256-abc123" crossorigin="anonymous">`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	resultStr := string(result.Body)
	if strings.Contains(resultStr, "integrity=") {
		t.Error("SRI integrity attribute should be stripped for proxied link tags")
	}
	if !strings.Contains(resultStr, `href="`) {
		t.Error("href attribute should be preserved on link")
	}
}

func TestRewriteBody_HTMLStripsSRIForProxiedRelativeURL(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<script src="/bundle.js" integrity="sha384-abc123" crossorigin="anonymous"></script>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	resultStr := string(result.Body)
	if strings.Contains(resultStr, "integrity=") {
		t.Error("SRI should be stripped for relative URLs (content will be scrubbed by proxy)")
	}
}

func TestRewriteBody_HTMLPreservesSRIForExternalCDN(t *testing.T) {
	gate := newTestGate()
	origins := NewOriginMapper(
		&url.URL{Scheme: "https", Host: "target.example.com"},
		"127.0.0.1:8099", "target-001.local",
	)
	body := []byte(`<script src="https://cdn.jsdelivr.net/npm/lib@1.0/dist.js" integrity="sha384-real" crossorigin="anonymous"></script>`)
	result := RewriteBody(body, "text/html", "/", gate, false, RewriteOpts{Origins: origins})
	resultStr := string(result.Body)
	if !strings.Contains(resultStr, `integrity="sha384-real"`) {
		t.Error("SRI should be preserved for external CDN URLs (not proxied)")
	}
	if !strings.Contains(resultStr, `crossorigin="anonymous"`) {
		t.Error("crossorigin should be preserved for external CDN URLs")
	}
}

func TestRewriteBody_HTMLStripsSRIForUpstreamURL(t *testing.T) {
	gate := newTestGate()
	origins := NewOriginMapper(
		&url.URL{Scheme: "https", Host: "target.example.com"},
		"127.0.0.1:8099", "target-001.local",
	)
	body := []byte(`<script src="https://target.example.com/app.js" integrity="sha384-abc123" crossorigin="anonymous"></script>`)
	result := RewriteBody(body, "text/html", "/", gate, false, RewriteOpts{Origins: origins})
	resultStr := string(result.Body)
	if strings.Contains(resultStr, "integrity=") {
		t.Error("SRI should be stripped when src points to proxied upstream")
	}
}

func TestRewriteBody_HTMLBodyURLsUseOriginMapper(t *testing.T) {
	gate := scrub.NewGate([]string{"app.example.com", "api.example.com"}, nil, "target-001.local")
	primary, _ := url.Parse("https://app.example.com")
	api, _ := url.Parse("https://api.example.com")
	origins := NewOriginMapper(primary, "127.0.0.1:8099", "target-001.local",
		OriginRoute{Upstream: api, Alias: "host-api.target-001.local"},
	)

	body := []byte(`<a href="https://api.example.com/v1/users">API</a>`)
	result := RewriteBody(body, "text/html", "/", gate, false, RewriteOpts{Origins: origins})
	resultStr := string(result.Body)

	if strings.Contains(resultStr, "api.example.com") {
		t.Errorf("upstream domain should be rewritten in HTML body, got: %s", resultStr)
	}
	if !strings.Contains(resultStr, "host-api.target-001.local:8099") {
		t.Errorf("HTML body URL should use origin-aware alias, got: %s", resultStr)
	}
}

func TestRewriteBody_HTMLPreservesIntegrityOnNonSRIElements(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<div integrity="custom-value">text</div>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	resultStr := string(result.Body)
	if !strings.Contains(resultStr, `integrity="`) {
		t.Error("integrity attribute on non-script/link should be preserved")
	}
}

func TestRewriteBody_HTMLMetadataExtractsTitle(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<html><head><title>Internal Dashboard</title></head><body>content</body></html>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	if result.Metadata == nil {
		t.Fatal("HTML with title should produce metadata")
	}
	if result.Metadata.Format != "html" {
		t.Errorf("expected format 'html', got %q", result.Metadata.Format)
	}
	if result.Metadata.Identity.Title != "Internal Dashboard" {
		t.Errorf("expected title 'Internal Dashboard', got %q", result.Metadata.Identity.Title)
	}
}

func TestRewriteBody_HTMLMetadataExtractsAuthor(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<html><head><meta name="author" content="Jane Doe"><title>Page</title></head><body>x</body></html>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	if result.Metadata == nil {
		t.Fatal("HTML with author meta should produce metadata")
	}
	if result.Metadata.Identity.Author != "Jane Doe" {
		t.Errorf("expected author 'Jane Doe', got %q", result.Metadata.Identity.Author)
	}
}

func TestRewriteBody_HTMLMetadataExtractsGenerator(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<html><head><meta name="generator" content="WordPress 6.3"><title>Blog</title></head></html>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	if result.Metadata == nil {
		t.Fatal("HTML with generator meta should produce metadata")
	}
	if result.Metadata.Producer != "WordPress 6.3" {
		t.Errorf("expected producer 'WordPress 6.3', got %q", result.Metadata.Producer)
	}
}

func TestRewriteBody_HTMLNoMetadataWhenEmpty(t *testing.T) {
	gate := newTestGate()
	body := []byte(`<html><body><p>No metadata here</p></body></html>`)
	result := RewriteBody(body, "text/html", "/", gate, false)
	if result.Metadata != nil {
		t.Error("HTML without title/author/generator should not produce metadata")
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
