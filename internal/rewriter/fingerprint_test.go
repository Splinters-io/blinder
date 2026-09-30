package rewriter

import (
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func fingerprintGate() *scrub.Gate {
	return scrub.NewGate(
		[]string{"pentesterlab.com"},
		[]string{"PentesterLab"},
		"alias.local",
	)
}

// --- HTML comments ---

func TestParanoidRemovesHTMLComments(t *testing.T) {
	gate := fingerprintGate()
	body := []byte(`<html><body><!-- TODO: fix layout for course page --><p>Hello world</p></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if strings.Contains(got, "TODO") || strings.Contains(got, "course page") {
		t.Fatal("paranoid should remove HTML comments")
	}
	if !strings.Contains(got, "<p>") {
		t.Fatal("surrounding markup should survive comment removal")
	}
}

func TestNonParanoidPreservesHTMLComments(t *testing.T) {
	gate := fingerprintGate()
	body := []byte(`<html><body><!-- navigation --><p>Hello</p></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, false).Body)
	if !strings.Contains(got, "navigation") {
		t.Fatal("non-paranoid should preserve comments")
	}
}

// --- Meta description / og tags ---

func TestParanoidReplacesMeta(t *testing.T) {
	gate := fingerprintGate()
	body := []byte(`<html><head><meta name="description" content="Learn web security with 700 hands-on exercises"><meta property="og:title" content="Security Training Platform"><meta property="og:description" content="The best way to learn application security"></head><body></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if strings.Contains(got, "700 hands-on") {
		t.Fatal("meta description content should be replaced")
	}
	if strings.Contains(got, "Security Training Platform") {
		t.Fatal("og:title content should be replaced")
	}
	if strings.Contains(got, "best way to learn") {
		t.Fatal("og:description content should be replaced")
	}
}

func TestParanoidReplacesTwitterMetaByName(t *testing.T) {
	gate := fingerprintGate()
	body := []byte(`<html><head><meta name="twitter:title" content="Advanced Web Hacking Training"><meta name="twitter:description" content="Learn through real-world CVEs and hands-on exploitation"></head><body></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if strings.Contains(got, "Advanced Web Hacking") {
		t.Fatal("twitter:title via name attribute should be replaced")
	}
	if strings.Contains(got, "real-world CVEs") {
		t.Fatal("twitter:description via name attribute should be replaced")
	}
}

func TestParanoidPreservesMetaCharsetAndViewport(t *testing.T) {
	gate := fingerprintGate()
	body := []byte(`<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head><body></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if !strings.Contains(got, `charset="utf-8"`) {
		t.Fatal("meta charset should be preserved")
	}
	if !strings.Contains(got, "width=device-width") {
		t.Fatal("meta viewport should be preserved")
	}
}

// --- Title attribute ---

func TestParanoidReplacesDisplayTitleAttr(t *testing.T) {
	gate := fingerprintGate()
	body := []byte(`<html><body><div title="Our comprehensive security training platform"><p>Content</p></div></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if strings.Contains(got, "comprehensive security training") {
		t.Fatal("display element title attribute should be replaced")
	}
}

func TestParanoidPreservesInteractiveTitleAttr(t *testing.T) {
	gate := fingerprintGate()
	body := []byte(`<html><body><button title="Click to submit">Submit</button></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if !strings.Contains(got, "Click to submit") {
		t.Fatal("interactive element title attribute should be preserved")
	}
}

// --- JSON-LD ---

func TestParanoidStripsJSONLD(t *testing.T) {
	gate := fingerprintGate()
	body := []byte(`<html><head><script type="application/ld+json">{"@type":"Organization","name":"Security Training Corp","url":"https://example.com"}</script></head><body><p>Hello</p></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if strings.Contains(got, "Security Training Corp") {
		t.Fatal("JSON-LD content should be stripped in paranoid mode")
	}
}

func TestNonParanoidKeepsJSONLD(t *testing.T) {
	gate := fingerprintGate()
	body := []byte(`<html><head><script type="application/ld+json">{"@type":"Organization","name":"TestCo"}</script></head><body></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, false).Body)
	if !strings.Contains(got, "TestCo") {
		t.Fatal("non-paranoid should keep JSON-LD content")
	}
}

// --- CSS class name aliasing ---

func TestParanoidAliasesCSSClassNames(t *testing.T) {
	gate := fingerprintGate()
	body := []byte(`<html><head><style>.course-card { color: red; } .lab-exercise { margin: 0; }</style></head><body><div class="course-card">Content</div><div class="lab-exercise">More</div></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if strings.Contains(got, "course-card") {
		t.Fatal("CSS class name 'course-card' should be aliased")
	}
	if strings.Contains(got, "lab-exercise") {
		t.Fatal("CSS class name 'lab-exercise' should be aliased")
	}
}

func TestParanoidClassAliasIsConsistent(t *testing.T) {
	gate := fingerprintGate()
	body := []byte(`<html><head><style>.hero-section { display: flex; }</style></head><body><div class="hero-section">Content</div><span class="hero-section">Other</span></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if strings.Contains(got, "hero-section") {
		t.Fatal("class name should be aliased")
	}
	// The aliased name used in <style> must match the one in class attributes.
	// Extract the class alias from the first class attribute occurrence.
	// Both div and span should use the same alias.
	styleIdx := strings.Index(got, "<style>")
	if styleIdx < 0 {
		t.Fatal("style tag missing")
	}
	styleEnd := strings.Index(got[styleIdx:], "</style>")
	styleBlock := got[styleIdx : styleIdx+styleEnd]
	dotIdx := strings.Index(styleBlock, ".")
	if dotIdx < 0 {
		t.Fatal("no class selector in style block")
	}
	spaceIdx := strings.IndexAny(styleBlock[dotIdx+1:], " {")
	aliasInCSS := styleBlock[dotIdx+1 : dotIdx+1+spaceIdx]

	classAttrIdx := strings.Index(got, `class="`)
	if classAttrIdx < 0 {
		t.Fatal("no class attribute found")
	}
	classVal := got[classAttrIdx+7:]
	quoteIdx := strings.IndexByte(classVal, '"')
	aliasInHTML := classVal[:quoteIdx]

	if aliasInCSS != aliasInHTML {
		t.Fatalf("class alias mismatch: CSS=%q HTML=%q", aliasInCSS, aliasInHTML)
	}
}

func TestParanoidAliasesHTMLIDs(t *testing.T) {
	gate := fingerprintGate()
	body := []byte(`<html><head><style>#main-content { padding: 1em; }</style></head><body><div id="main-content">Hello</div></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if strings.Contains(got, "main-content") {
		t.Fatal("HTML id should be aliased in both CSS and HTML")
	}
}

func TestNonParanoidKeepsClassNames(t *testing.T) {
	gate := fingerprintGate()
	body := []byte(`<html><body><div class="course-card">Content</div></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, false).Body)
	if !strings.Contains(got, "course-card") {
		t.Fatal("non-paranoid should preserve class names")
	}
}

// --- Data attributes ---

func TestParanoidScrubsDataAttributes(t *testing.T) {
	gate := fingerprintGate()
	body := []byte(`<html><body><div data-testid="course-viewer" data-component="lab-panel">Content</div></body></html>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if strings.Contains(got, "course-viewer") {
		t.Fatal("data-testid should be scrubbed in paranoid mode")
	}
	if strings.Contains(got, "lab-panel") {
		t.Fatal("data-component should be scrubbed in paranoid mode")
	}
}
