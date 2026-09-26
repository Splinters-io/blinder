package rewriter

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestCSPRegisteredOriginsFollowRequestAuthority(t *testing.T) {
	for _, host := range []string{"127.0.0.1:8099", "localhost:8099", "[::1]:8099"} {
		t.Run(host, func(t *testing.T) {
			gate, shared := resourceRouteFixture(t)
			origins := shared.ForRequestHost(host)
			policy := "default-src 'none'; script-src https://target.example.com:8443/scripts/; connect-src wss://target.example.com:8443/events http://assets.example.com:8080/api/"
			want := "default-src 'none'; script-src https://" + host + "/scripts/; connect-src wss://" + host + "/events https://assets.alias.local:8099/api/"
			input := http.Header{
				"Content-Security-Policy":             {policy},
				"Content-Security-Policy-Report-Only": {policy, "object-src 'none'"},
			}
			got := RewriteResponseHeaders(input, gate, "127.0.0.1", "target.example.com:8443", ResponseHeaderOpts{OriginMapper: origins})
			for _, name := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
				if got.Get(name) != want {
					t.Errorf("%s = %q; want %q", name, got.Get(name), want)
				}
			}
			if values := got.Values("Content-Security-Policy-Report-Only"); len(values) != 2 || values[1] != "object-src 'none'" {
				t.Fatalf("independent report-only policies changed: %v", values)
			}
			body := string(RewriteBody([]byte(`<script src="https://target.example.com:8443/scripts/app"></script>`), "text/html", "/", gate, false, RewriteOpts{Origins: origins}).Body)
			if !strings.Contains(body, `src="https://`+host+`/scripts/app"`) {
				t.Fatalf("body and policy disagree on resource authority: %s", body)
			}
			if input.Get("Content-Security-Policy") != policy {
				t.Fatal("rewriter mutated upstream policy")
			}
			if shared.RewriteUpstreamURL("https://target.example.com:8443/scripts/") != "https://127.0.0.1:8099/scripts/" {
				t.Fatal("request-specific CSP mutated shared routes")
			}
		})
	}
}

func TestCSPPreservesProtocolTokensAndDirectiveNames(t *testing.T) {
	gate := scrub.NewGate(nil, []string{"script", "unsafe", "self", "AcmeCorp", "Custom", "report"}, "alias.local")
	policy := "script-src 'SELF' 'unsafe-inline' 'unsafe-eval' 'strict-dynamic' 'unsafe-hashes' 'report-sample' 'unsafe-allow-redirects' 'wasm-unsafe-eval' 'trusted-types-eval' 'inline-speculation-rules' 'report-sha256' 'report-sha384' 'report-sha512' 'unsafe-webtransport-hashes' 'nonce-AcmeCorp_-==' 'sha256-AcmeCorp_-==' 'SHA384-AcmeCorp+/=' 'sha512-AcmeCorp' Custom.Scheme: data: blob: https: wss: *; object-src 'none'"
	if got := rewriteCSP(policy, gate, "alias.local"); got != policy {
		t.Fatalf("CSP protocol values were treated as identity text:\n%s", got)
	}
}

func TestCSPDoesNotInventRoutesOrBroadenWildcardSources(t *testing.T) {
	for _, source := range []string{
		"https://*.target.example.com:8443/images/",
		"https://target.example.com:*/images/",
		"https://*:8443/images/",
		"https://target.example.com:9443/images/",
		"http://target.example.com:8443/images/",
		"https://unknown.example/images/",
		"target.example.com:8443/images/",
	} {
		t.Run(source, func(t *testing.T) {
			gate, origins := resourceRouteFixture(t)
			got := rewriteCSP("img-src "+source, gate, "127.0.0.1", origins)
			want := "img-src " + gate.Scrub(source, "csp")
			if got != want {
				t.Fatalf("non-exact source gained a registered route: %q; want %q", got, want)
			}
			if strings.Count(got, "*") != strings.Count(source, "*") || !strings.HasSuffix(got, "/images/") {
				t.Fatalf("wildcard/path restriction changed: %q", got)
			}
		})
	}
}

func TestLocationHeadersProtectIssuedAuthorityAndRestoreSuffix(t *testing.T) {
	gate, shared := resourceRouteFixture(t)
	origins := shared.ForRequestHost("127.0.0.1:8099")
	for _, name := range []string{"Location", "Content-Location"} {
		for _, prefix := range []string{"https://target.example.com:8443", "https://127.0.0.1:8099"} {
			input := http.Header{name: {prefix + "/AcmeCorp?label=AcmeCorp#AcmeCorp"}}
			got := RewriteResponseHeaders(input, gate, "127.0.0.1", "target.example.com:8443", ResponseHeaderOpts{OriginMapper: origins}).Get(name)
			u, err := url.Parse(got)
			if err != nil || u.Scheme != "https" || u.Host != "127.0.0.1:8099" {
				t.Fatalf("%s rescrubbed issued authority: %q (%v)", name, got, err)
			}
			if strings.Contains(got, "AcmeCorp") || gate.RestoreBody(u.Path) != "/AcmeCorp" || gate.RestoreBody(u.Query().Get("label")) != "AcmeCorp" || gate.RestoreBody(u.Fragment) != "AcmeCorp" {
				t.Fatalf("%s suffix did not mask and round-trip: %q", name, got)
			}
		}
	}
}
