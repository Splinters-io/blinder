package scrub

import (
	"strings"
	"testing"
)

func TestScrubNoDomains_PreservesDottedFilenames(t *testing.T) {
	g := NewGate(
		[]string{"target.example"},
		[]string{"target.example", "TargetCo"},
		"target-001.localhost",
	)

	paths := []string{
		"/newdesign/dist/css/custom.min.css",
		"/css/navbar.min.css",
		"/newdesign/imgs/vulns-art.svg",
		"/img/photo.jpg",
		"/uploads/doc.pdf",
		"./style.min.js",
		"../assets/bundle.vendor.js",
		"/path/to/file.woff2",
		"/deep/path/font.subset.woff",
		"/a/b/image.avif",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			result := g.ScrubNoDomains(path, "test")
			if result != path {
				t.Errorf("ScrubNoDomains mangled dotted filename:\n  input:  %s\n  output: %s", path, result)
			}
		})
	}
}

func TestScrubNoDomains_ScrubVsNoDomains(t *testing.T) {
	g := NewGate(nil, nil, "target-001.localhost")

	inputs := []string{
		"/css/custom.min.css",
		"/img/hero-art.svg",
		"photo.large.jpg",
	}
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			scrubbed := g.Scrub(input, "test")
			noDomains := g.ScrubNoDomains(input, "test")

			if scrubbed == input {
				t.Errorf("Scrub should mangle dotted filename %q but didn't", input)
			}
			if noDomains != input {
				t.Errorf("ScrubNoDomains should preserve %q but got %q", input, noDomains)
			}
		})
	}
}

func TestScrubNoDomains_StillCatchesTargetDomains(t *testing.T) {
	g := NewGate(
		[]string{"evil.example"},
		nil,
		"target-001.localhost",
	)

	tests := []struct {
		name  string
		input string
	}{
		{"domain_in_path", "/api/check?host=evil.example&ok=1"},
		{"domain_in_query", "/search?q=evil.example"},
		{"domain_bare", "evil.example"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := g.ScrubNoDomains(tc.input, "test")
			if strings.Contains(result, "evil.example") {
				t.Errorf("ScrubNoDomains should scrub target domain:\n  input:  %s\n  output: %s", tc.input, result)
			}
			if !strings.Contains(result, "target-001.localhost") {
				t.Errorf("expected alias domain in output:\n  input:  %s\n  output: %s", tc.input, result)
			}
		})
	}
}

func TestScrubNoDomains_StillCatchesIdentityTokens(t *testing.T) {
	g := NewGate(
		nil,
		[]string{"TargetCo", "target.example"},
		"target-001.localhost",
	)

	tests := []struct {
		name  string
		input string
	}{
		{"token_in_path", "/uploads/TargetCo-hero.png"},
		{"domain_token_in_url", "/check?site=target.example"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := g.ScrubNoDomains(tc.input, "test")
			if strings.Contains(result, "TargetCo") || strings.Contains(result, "target.example") {
				t.Errorf("ScrubNoDomains should scrub identity token:\n  input:  %s\n  output: %s", tc.input, result)
			}
		})
	}
}

func TestScrubNoDomains_StillCatchesEmails(t *testing.T) {
	g := NewGate(nil, nil, "target-001.localhost")

	input := "/contact?email=admin@evilcorp.com"
	result := g.ScrubNoDomains(input, "test")
	if strings.Contains(result, "admin@evilcorp.com") {
		t.Errorf("ScrubNoDomains should scrub email:\n  input:  %s\n  output: %s", input, result)
	}
}

func TestScrubNoDomains_PreservesSafeDomainEmails(t *testing.T) {
	g := NewGate(nil, nil, "target-001.localhost")

	input := "/contact?email=user@google.com"
	result := g.ScrubNoDomains(input, "test")
	if !strings.Contains(result, "user@google.com") {
		t.Errorf("ScrubNoDomains should preserve safe domain email:\n  input:  %s\n  output: %s", input, result)
	}
}

func TestScrubNoDomains_StillCatchesPublicIPv4(t *testing.T) {
	g := NewGate(nil, nil, "target-001.localhost")

	input := "/api?server=93.184.216.34"
	result := g.ScrubNoDomains(input, "test")
	if strings.Contains(result, "93.184.216.34") {
		t.Errorf("ScrubNoDomains should scrub public IPv4:\n  input:  %s\n  output: %s", input, result)
	}
}

func TestScrubNoDomains_PreservesPrivateIPs(t *testing.T) {
	g := NewGate(nil, nil, "target-001.localhost")

	privates := []string{
		"/api?host=127.0.0.1",
		"/api?host=192.168.1.1",
		"/api?host=10.0.0.1",
	}
	for _, input := range privates {
		t.Run(input, func(t *testing.T) {
			result := g.ScrubNoDomains(input, "test")
			if result != input {
				t.Errorf("ScrubNoDomains should preserve private IP:\n  input:  %s\n  output: %s", input, result)
			}
		})
	}
}

func TestScrubNoDomains_StillCatchesPublicIPv6(t *testing.T) {
	g := NewGate(nil, nil, "target-001.localhost")

	input := "/api?server=2607:f8b0:4004:800::200e"
	result := g.ScrubNoDomains(input, "test")
	if strings.Contains(result, "2607:f8b0:4004:800::200e") {
		t.Errorf("ScrubNoDomains should scrub public IPv6:\n  input:  %s\n  output: %s", input, result)
	}
}

func TestScrubNoDomains_EmptyAndEdgeCases(t *testing.T) {
	g := NewGate(nil, nil, "target-001.localhost")

	tests := []struct {
		name, input, want string
	}{
		{"empty_string", "", ""},
		{"plain_path", "/foo/bar/baz", "/foo/bar/baz"},
		{"query_only", "?key=value", "?key=value"},
		{"fragment_only", "#section", "#section"},
		{"single_dot", ".", "."},
		{"dotdot", "..", ".."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := g.ScrubNoDomains(tc.input, "test")
			if result != tc.want {
				t.Errorf("ScrubNoDomains(%q) = %q, want %q", tc.input, result, tc.want)
			}
		})
	}
}

func TestAddDomains_BasicRegistration(t *testing.T) {
	g := NewGate(
		[]string{"original.example"},
		nil,
		"target-001.localhost",
	)

	result := g.Scrub("original.example and newdomain.example", "test")
	if strings.Contains(result, "original.example") {
		t.Fatal("initial domain should be scrubbed")
	}
	if !strings.Contains(result, "newdomain.example") {
		t.Fatal("unknown domain should survive Scrub's domain patterns (caught by domainRe instead)")
	}

	g.AddDomains([]string{"newdomain.example"})

	result = g.ScrubNoDomains("check newdomain.example here", "test")
	if strings.Contains(result, "newdomain.example") {
		t.Errorf("AddDomains domain should be caught by ScrubNoDomains:\n  output: %s", result)
	}
	if !strings.Contains(result, "target-001.localhost") {
		t.Errorf("expected alias in output:\n  output: %s", result)
	}
}

func TestAddDomains_DeduplicatesExisting(t *testing.T) {
	g := NewGate(
		[]string{"existing.example"},
		nil,
		"target-001.localhost",
	)

	g.AddDomains([]string{"existing.example", "existing.example", "new.example"})

	count := 0
	for _, d := range g.targetDomains {
		if d == "existing.example" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("existing.example appears %d times, want 1", count)
	}

	hasNew := false
	for _, d := range g.targetDomains {
		if d == "new.example" {
			hasNew = true
		}
	}
	if !hasNew {
		t.Error("new.example should be in targetDomains")
	}
}

func TestAddDomains_SkipsEmpty(t *testing.T) {
	g := NewGate(nil, nil, "target-001.localhost")

	g.AddDomains([]string{"", "", "real.example"})

	if len(g.targetDomains) != 1 || g.targetDomains[0] != "real.example" {
		t.Errorf("expected only real.example, got %v", g.targetDomains)
	}
}

func TestAddDomains_ChildDelegatesToParent(t *testing.T) {
	parent := NewGate(nil, nil, "target-001.localhost")
	child := parent.ForRequest()

	child.AddDomains([]string{"delegated.example"})

	found := false
	for _, d := range parent.targetDomains {
		if d == "delegated.example" {
			found = true
		}
	}
	if !found {
		t.Error("AddDomains on child should delegate to parent")
	}
}

func TestAddDomains_NewDomainsAreScrubbed(t *testing.T) {
	g := NewGate(nil, nil, "target-001.localhost")

	input := "visit assets.target.example today"
	before := g.ScrubNoDomains(input, "test")
	if !strings.Contains(before, "assets.target.example") {
		t.Fatal("domain should survive before AddDomains")
	}

	g.AddDomains([]string{"assets.target.example"})

	after := g.ScrubNoDomains(input, "test")
	if strings.Contains(after, "assets.target.example") {
		t.Errorf("domain should be scrubbed after AddDomains:\n  output: %s", after)
	}
}
