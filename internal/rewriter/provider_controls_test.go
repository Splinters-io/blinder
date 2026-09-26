package rewriter

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestProviderPolicyOriginsDoNotAuthorizeTargetRouting(t *testing.T) {
	target, _ := url.Parse("https://target.example")
	provider, _ := url.Parse("https://provider.example")
	m, err := NewOriginMapper(target, "127.0.0.1:8099", "target.localhost")
	if err != nil {
		t.Fatal(err)
	}
	m = m.WithPolicyOrigins(map[string]string{provider.String(): "https://captcha-fixture.localhost:8099"})
	if m.IsKnownFullOrigin(provider) || m.Resolve("captcha-fixture.localhost:8099") != nil {
		t.Fatal("policy translation granted target/SRI access")
	}
	gate := scrub.NewGate([]string{"target.example"}, nil, "target.localhost")
	policy := "script-src https://provider.example/api/ 'sha256-AAAA'; frame-src 'none'"
	want := "script-src https://captcha-fixture.localhost:8099/api/ 'sha256-AAAA'; frame-src 'none'"
	if got := rewriteCSP(policy, gate, "target.localhost", m); got != want {
		t.Fatalf("policy = %q, want %q", got, want)
	}
}

func TestProviderPolicyTranslationPreservesControlGrammar(t *testing.T) {
	mapSource := func(s string) string {
		return strings.Replace(s, "https://provider.example", "https://captcha-fixture.localhost:8099", 1)
	}
	policy := "script-src\t'self' 'nonce-abc' 'sha384-AAAA' https://provider.example/a/;script-src 'none', default-src 'none'; report-uri https://provider.example/report; trusted-types https://provider.example; script-src\u00a0https://provider.example"
	want := "script-src\t'self' 'nonce-abc' 'sha384-AAAA' https://captcha-fixture.localhost:8099/a/;script-src 'none', default-src 'none'; report-uri https://captcha-fixture.localhost:8099/report; trusted-types https://provider.example; script-src\u00a0https://provider.example"
	if got := RewriteCSPOrigins(policy, mapSource); got != want {
		t.Fatalf("policy changed control syntax: %q", got)
	}
}

func TestOpaqueProviderHTMLKeepsScriptAndIntegrityBytes(t *testing.T) {
	base, _ := url.Parse("https://provider.example/widget/")
	const script = "\n const source = 'https://provider.example/token';\r\nwindow.signal=source;\n"
	body := []byte(`<head><meta http-equiv="Content-Security-Policy" content="script-src 'self'; connect-src https://provider.example"><script nonce="abc">` + script + `</script><script src="https://provider.example/api.js?x=1&amp;x=2" integrity="sha256-AAAA" crossorigin="anonymous"></script></head>`)
	mapSource := func(s string) string {
		return strings.Replace(s, "https://provider.example", "https://captcha-fixture.localhost:8099", 1)
	}
	got := string(RewriteOpaqueHTML(body, base, nil, func(raw string, _ *url.URL) (string, bool) { return mapSource(raw), true }, func(p string) string { return RewriteCSPOrigins(p, mapSource) }))
	for _, value := range []string{script, `integrity="sha256-AAAA"`, `nonce="abc"`, `crossorigin="anonymous"`, `src="https://captcha-fixture.localhost:8099/api.js?x=1&amp;x=2"`} {
		if !strings.Contains(got, value) {
			t.Fatalf("lost original script/control or route %q: %s", value, got)
		}
	}
	if strings.Contains(got, "unsafe-inline") || strings.Contains(got, "bootstrap") {
		t.Fatal("injected new script permission")
	}
}

func TestOpaqueProviderBaseSelectionRetainsOriginalPolicy(t *testing.T) {
	for _, tc := range []struct{ name, policy, markup, want string }{
		{"first_relative", "", `<base href="first/"><base href="second/"><script src="api.js"></script>`, "https://provider.example/widget/first/api.js"},
		{"blocked_first", "base-uri 'none'", `<base href="https://other.example/"><base href="second/"><script src="api.js"></script>`, "https://provider.example/widget/api.js"},
		{"meta_blocked", "", `<meta http-equiv="Content-Security-Policy" content="base-uri 'none'"><base href="first/"><script src="api.js"></script>`, "https://provider.example/widget/api.js"},
		{"template_inert", "", `<template><base href="wrong/"></template><base href="right/"><script src="api.js"></script>`, "https://provider.example/widget/right/api.js"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, _ := url.Parse("https://provider.example/widget/")
			var got string
			RewriteOpaqueHTML([]byte(tc.markup), base, []string{tc.policy}, func(raw string, b *url.URL) (string, bool) {
				if raw == "api.js" {
					u, _ := b.Parse(raw)
					got = u.String()
				}
				return raw, false
			}, nil)
			if got != tc.want {
				t.Fatalf("resource resolution=%q, want %q", got, tc.want)
			}
		})
	}
}
