package rewriter

import (
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestRewriteSVG_RemovesPathBranding(t *testing.T) {
	logo := `<svg width="192" height="44" viewBox="0 0 192 44" fill="none" xmlns="http://www.w3.org/2000/svg">
<g clip-path="url(#clip0)">
<path d="M18.5486 32.1587L18.2878 31.9754C17.0914 31.1509 15.6407 30.7814" fill="#6BCEF3"/>
<path d="M74.9276 22.5181H70.244C69.947 22.4955" fill="white"/>
</g>
</svg>`
	gate := scrub.NewGate(nil, []string{"TargetApp"}, "alias.local")
	result := rewriteSVG([]byte(logo), gate)
	if strings.Contains(string(result), "18.5486") {
		t.Error("path coordinates from original SVG should not appear in output")
	}
	if !strings.Contains(string(result), "<svg") {
		t.Error("output must be a valid SVG element")
	}
	if !strings.Contains(string(result), `width="192"`) {
		t.Error("output must preserve original width")
	}
	if !strings.Contains(string(result), `height="44"`) {
		t.Error("output must preserve original height")
	}
	if !strings.Contains(string(result), "<rect") {
		t.Error("output must contain a placeholder rectangle")
	}
}

func TestRewriteSVG_PreservesViewBoxDimensions(t *testing.T) {
	svg := `<svg viewBox="0 0 300 150" xmlns="http://www.w3.org/2000/svg"><circle cx="50" cy="50" r="40"/></svg>`
	gate := scrub.NewGate(nil, nil, "alias.local")
	result := rewriteSVG([]byte(svg), gate)
	if !strings.Contains(string(result), `width="300"`) || !strings.Contains(string(result), `height="150"`) {
		t.Errorf("should derive dimensions from viewBox: %s", result)
	}
}

func TestRewriteSVG_DefaultDimensions(t *testing.T) {
	svg := `<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0 L10 10"/></svg>`
	gate := scrub.NewGate(nil, nil, "alias.local")
	result := rewriteSVG([]byte(svg), gate)
	if !strings.Contains(string(result), `width="300"`) || !strings.Contains(string(result), `height="150"`) {
		t.Errorf("should use browser default 300x150 when no dimensions: %s", result)
	}
}

func TestRewriteSVG_RoutedViaContentType(t *testing.T) {
	svg := `<svg width="100" height="50" xmlns="http://www.w3.org/2000/svg"><text>BrandName</text></svg>`
	gate := scrub.NewGate(nil, []string{"BrandName"}, "alias.local")
	result := RewriteBody([]byte(svg), "image/svg+xml", "/logo.svg", gate, false)
	if strings.Contains(string(result.Body), "BrandName") {
		t.Error("SVG routed via image/svg+xml must not leak identity text")
	}
	if strings.Contains(string(result.Body), "<text>") {
		t.Error("SVG must be replaced, not just text-scrubbed")
	}
}
