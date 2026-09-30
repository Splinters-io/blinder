package rewriter

import (
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestAliasCSSSelectorNamesPreservesColors(t *testing.T) {
	gate := scrub.NewGate(nil, nil, "alias.local")
	css := `.hero { border: 1px solid #ccc; color: #ff0000; background: #abc; }`
	got := aliasCSSSelectorNames(css, gate)
	if !strings.Contains(got, "#ccc") {
		t.Fatalf("CSS color #ccc was aliased: %s", got)
	}
	if !strings.Contains(got, "#ff0000") {
		t.Fatalf("CSS color #ff0000 was aliased: %s", got)
	}
	if strings.Contains(got, ".hero") {
		t.Fatalf("class selector .hero was not aliased: %s", got)
	}
}

func TestAliasCSSSelectorNamesHandlesIDSelector(t *testing.T) {
	gate := scrub.NewGate(nil, nil, "alias.local")
	css := `#main-nav { display: flex; } .sidebar { width: 200px; }`
	got := aliasCSSSelectorNames(css, gate)
	if strings.Contains(got, "main-nav") {
		t.Fatalf("ID selector #main-nav was not aliased: %s", got)
	}
	if strings.Contains(got, "sidebar") {
		t.Fatalf("class selector .sidebar was not aliased: %s", got)
	}
}

func TestAliasCSSSelectorNamesHandlesMediaQueries(t *testing.T) {
	gate := scrub.NewGate(nil, nil, "alias.local")
	css := `@media (max-width: 768px) { .menu { display: none; } .nav-link { color: #333; } } .top-level { margin: 0; }`
	got := aliasCSSSelectorNames(css, gate)
	if strings.Contains(got, ".menu") {
		t.Fatalf("selector .menu inside @media was not aliased: %s", got)
	}
	if strings.Contains(got, ".nav-link") {
		t.Fatalf("selector .nav-link inside @media was not aliased: %s", got)
	}
	if strings.Contains(got, ".top-level") {
		t.Fatalf("top-level selector was not aliased: %s", got)
	}
	if !strings.Contains(got, "#333") {
		t.Fatalf("CSS color #333 inside @media was aliased: %s", got)
	}
}

func TestAliasCSSSelectorNamesHandlesNestedAtRules(t *testing.T) {
	gate := scrub.NewGate(nil, nil, "alias.local")
	css := `@supports (display: grid) { @media (min-width: 600px) { .grid-item { grid-column: 1; } } }`
	got := aliasCSSSelectorNames(css, gate)
	if strings.Contains(got, ".grid-item") {
		t.Fatalf("selector inside nested at-rules was not aliased: %s", got)
	}
}

func TestAliasCSSSelectorNamesFontFaceIsDecl(t *testing.T) {
	gate := scrub.NewGate(nil, nil, "alias.local")
	css := `@font-face { font-family: "Icons"; src: url(icons.woff); }`
	got := aliasCSSSelectorNames(css, gate)
	if got != css {
		t.Fatalf("@font-face block content was modified: %s", got)
	}
}

func TestAliasNameDeterministic(t *testing.T) {
	gate := scrub.NewGate(nil, nil, "alias.local")
	a := aliasName("course-card", gate)
	b := aliasName("course-card", gate)
	if a != b {
		t.Fatalf("aliasName not deterministic: %q vs %q", a, b)
	}
	c := aliasName("lab-exercise", gate)
	if a == c {
		t.Fatalf("different names produced same alias: %q", a)
	}
}
