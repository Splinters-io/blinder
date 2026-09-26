package captcha

import (
	"crypto/tls"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func routesForTest(t *testing.T, scheme, listen string, providers ...Provider) *ProviderRoutes {
	t.Helper()
	cfg := &Config{}
	for _, p := range providers {
		compiled, err := compileProvider(p)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Providers = append(cfg.Providers, compiled)
	}
	routes, err := NewProviderRoutes(NewMatcher(cfg), scheme, listen)
	if err != nil {
		t.Fatal(err)
	}
	return routes
}

func TestProviderRoutesFullOriginIdentityAndCanonicalDedup(t *testing.T) {
	origins := []string{"https://CAPTCHA.example:443", "https://captcha.example", "http://captcha.example", "https://captcha.example:8443"}
	routes := routesForTest(t, "https", "127.0.0.1:18099", Provider{Name: "vendor", ResourceOrigins: origins})
	if len(routes.Routes()) != 3 {
		t.Fatalf("routes = %d; want three full origins", len(routes.Routes()))
	}
	seen := make(map[string]bool)
	for _, r := range routes.Routes() {
		if seen[r.Local.Host] {
			t.Fatalf("two upstream origins collapsed to %s", r.Local)
		}
		seen[r.Local.Host] = true
		if r.Local.Port() != "18099" || !strings.HasSuffix(r.Local.Hostname(), ".localhost") {
			t.Fatalf("bad browser endpoint %s", r.Local)
		}
	}
	other := routesForTest(t, "http", "127.0.0.1:28099", Provider{Name: "vendor", ResourceOrigins: []string{origins[3], origins[2], origins[1]}})
	if !reflect.DeepEqual(routes.AliasHosts(), other.AliasHosts()) {
		t.Fatalf("hostnames depend on config order or listening endpoint: %v / %v", routes.AliasHosts(), other.AliasHosts())
	}
	canonical, ok := routes.RewriteURL("https://captcha.example/widget", nil)
	if !ok {
		t.Fatal("canonical resource did not map")
	}
	if equivalent, ok := routes.RewriteURL("https://CAPTCHA.example:0443/widget", nil); !ok || equivalent != canonical {
		t.Fatalf("canonical-equivalent origin used a different route: %s, %v", equivalent, ok)
	}
}

func TestProviderRoutesOpaqueURLRoundTripAndRegex(t *testing.T) {
	routes := routesForTest(t, "https", "127.0.0.1:18099", Provider{
		Name: "vendor", ResourceOrigins: []string{"https://captcha.example"},
		RawURLRegexes: []string{`^https://captcha\.example/widget/`},
	})
	base := mustParse("https://captcha.example/widget/page")
	for _, suffix := range []string{"a%2Fb.js?token=a%2Bb&token=c+d&&empty=#foo%2Fbar", "script.js?", "./script.js?x=%FF"} {
		upstream := base.ResolveReference(mustParse(suffix))
		mapped, ok := routes.RewriteURL(suffix, base)
		if !ok {
			t.Fatalf("matching URL not mapped: %s", suffix)
		}
		local := mustParse(mapped)
		if upstream.RawPath != local.RawPath || upstream.RawQuery != local.RawQuery || upstream.ForceQuery != local.ForceQuery || upstream.RawFragment != local.RawFragment {
			t.Fatalf("opaque URL fields changed: %s -> %s", upstream, local)
		}
		req := httptest.NewRequest("CUSTOM-METHOD", mapped, nil)
		resolved, ok := routes.Resolve(req)
		if !ok || resolved.String() != upstream.String() {
			t.Fatalf("round trip %s -> %s: %v", upstream, resolved, ok)
		}
	}
	for _, raw := range []string{"https://captcha.example/admin", "https://captcha.example:8443/widget/a", "http://captcha.example/widget/a", "https://other.example/widget/a", "https://user@captcha.example/widget/a"} {
		if _, ok := routes.RewriteURL(raw, base); ok {
			t.Fatalf("out-of-scope URL mapped: %s", raw)
		}
	}
	denied := httptest.NewRequest("POST", routes.Routes()[0].Local.String()+"/admin", nil)
	if _, ok := routes.Resolve(denied); ok || !routes.IsAliasHost(denied.Host) {
		t.Fatal("regex-denied request must remain recognized as a provider request")
	}
}

func TestProviderRoutesAuthorityAndSchemeChecks(t *testing.T) {
	routes := routesForTest(t, "https", "127.0.0.1:18099", Provider{Name: "vendor", ResourceOrigins: []string{"https://captcha.example"}})
	local := routes.Routes()[0].Local
	for _, tc := range []struct {
		name, host, absolute string
		tls                  bool
	}{
		{"wrong port", local.Hostname() + ":18098", "", true},
		{"no port", local.Hostname(), "", true},
		{"malformed port", local.Hostname() + ":bad", "", true},
		{"wrong scheme", local.Host, "", false},
		{"mismatched absolute authority", local.Host, "https://other.example/path", true},
		{"mismatched absolute scheme", local.Host, "http://" + local.Host + "/path", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", local.String()+"/path", nil)
			req.Host = tc.host
			if !tc.tls {
				req.TLS = nil
			}
			if tc.absolute != "" {
				req.URL = mustParse(tc.absolute)
			}
			if _, ok := routes.Resolve(req); ok {
				t.Fatal("invalid provider authority accepted")
			}
			if !routes.IsAliasHost(req.Host) {
				t.Fatal("invalid provider request escaped provider dispatch")
			}
		})
	}
	if routes.IsAliasHost("evil." + local.Host) {
		t.Fatal("suffix hostname matched registered alias")
	}
	valid := httptest.NewRequest("GET", "/path", nil)
	valid.Host, valid.TLS = strings.ToUpper(local.Host), &tls.ConnectionState{}
	if got, ok := routes.Resolve(valid); !ok || got.String() != "https://captcha.example/path" {
		t.Fatalf("valid origin-form request rejected: %s, %v", got, ok)
	}
}

func TestProviderRoutesExactOriginTranslation(t *testing.T) {
	routes := routesForTest(t, "https", "127.0.0.1:443", Provider{Name: "vendor", ResourceOrigins: []string{"https://captcha.example"}})
	local := routes.Routes()[0].Local.String()
	if got := routes.MapOrigin("https://captcha.example", false); got != local {
		t.Fatalf("map upstream origin = %s", got)
	}
	if got := routes.MapOrigin(local, true); got != "https://captcha.example" {
		t.Fatalf("map local origin = %s", got)
	}
	for _, raw := range []string{"null", "*", "https://other.example", "https://captcha.example/path", "https://captcha.example?", "https://captcha.example#", "http://captcha.example", "https://captcha.example:8443", "https://CAPTCHA.example", "HTTPS://captcha.example", "https://captcha.example:443"} {
		if got := routes.MapOrigin(raw, false); got != raw {
			t.Fatalf("unregistered origin changed: %s -> %s", raw, got)
		}
	}
}

func TestProviderRoutesDirectPolicyAndOverlappingRules(t *testing.T) {
	routes := routesForTest(t, "http", "127.0.0.1:18099",
		Provider{Name: "direct", ResourceOrigins: []string{"https://direct.example", "https://mixed.example"}, TorPolicy: TorPolicyDirect},
		Provider{Name: "routed", ResourceOrigins: []string{"https://mixed.example"}, RawURLRegexes: []string{`/routed/`}},
	)
	if len(routes.Routes()) != 1 {
		t.Fatalf("direct-only provider gained an alias: %v", routes.Routes())
	}
	for _, raw := range []string{"https://direct.example/a", "https://mixed.example/direct/a"} {
		if _, ok := routes.RewriteURL(raw, nil); ok {
			t.Fatalf("direct URL routed: %s", raw)
		}
	}
	if _, ok := routes.RewriteURL("https://mixed.example/routed/a", nil); !ok {
		t.Fatal("overlapping direct declaration suppressed more restrictive route")
	}
}

func TestProviderRoutesReturnedRoutesCannotMutateRegistry(t *testing.T) {
	routes := routesForTest(t, "https", "127.0.0.1:18099", Provider{Name: "vendor", ResourceOrigins: []string{"https://captcha.example"}})
	copy := routes.Routes()
	copy[0].Local.Host, copy[0].Upstream.Host = "mutated.invalid", "changed.invalid"
	hosts := routes.AliasHosts()
	hosts[0] = "other.invalid"
	mapped, ok := routes.RewriteURL("https://captcha.example/widget", nil)
	if !ok || strings.Contains(mapped, "invalid") {
		t.Fatalf("returned values changed registry: %s, %v", mapped, ok)
	}
}

func TestProviderRoutesRejectInvalidListenAndManuallyConfiguredOrigin(t *testing.T) {
	for _, listen := range []string{"127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:bad"} {
		if _, err := NewProviderRoutes(nil, "https", listen); err == nil {
			t.Fatalf("invalid listen accepted: %s", listen)
		}
	}
	if _, err := NewProviderRoutes(nil, "ftp", "127.0.0.1:18099"); err == nil {
		t.Fatal("invalid local scheme accepted")
	}
	m := NewMatcher(&Config{Providers: []Provider{{Name: "invalid", ResourceOrigins: []string{"https://captcha.example/path"}}}})
	if _, err := NewProviderRoutes(m, "https", "127.0.0.1:18099"); err == nil {
		t.Fatal("manual Config bypassed strict origin validation")
	}
}

func TestProviderResourceOriginsRejectURLFeatures(t *testing.T) {
	for _, raw := range []string{
		"captcha.example", "//captcha.example", "ftp://captcha.example", "javascript:alert(1)",
		"https://user:secret@captcha.example", "https://captcha.example/", "https://captcha.example/path",
		"https://captcha.example?x=1", "https://captcha.example?", "https://captcha.example#fragment", "https://captcha.example#",
		"https://*.captcha.example", "https://captcha.example:", "https://captcha.example:0", "https://captcha.example:65536", "https://captcha.example:abc",
		"https://[::1%25zone]", "https://a..example", "https://-a.example", "https://a-.example", "https://a_b.example",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := compileProvider(Provider{Name: "bad", ResourceOrigins: []string{raw}}); err == nil {
				t.Fatalf("origin with URL features accepted: %s", raw)
			}
		})
	}
}

func TestProviderResourceOriginsCanonicalEquivalentDefaults(t *testing.T) {
	p, err := compileProvider(Provider{Name: "vendor", ResourceOrigins: []string{"HTTPS://CAPTCHA.example:0443", "https://captcha.example", "http://captcha.example:80", "http://captcha.example", "https://[0:0:0:0:0:0:0:1]:443"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://captcha.example", "http://captcha.example", "https://[::1]"}
	if !reflect.DeepEqual(p.ResourceOrigins, want) {
		t.Fatalf("canonical origins = %v; want %v", p.ResourceOrigins, want)
	}
	for _, raw := range p.ResourceOrigins {
		if _, err := url.Parse(raw); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProviderRoutesIPv6DoesNotCollapseIntoIPv4(t *testing.T) {
	routes := routesForTest(t, "https", "127.0.0.1:18099", Provider{Name: "vendor", ResourceOrigins: []string{"https://127.0.0.1", "https://[::ffff:127.0.0.1]"}})
	if len(routes.Routes()) != 2 || routes.Routes()[0].Local.Host == routes.Routes()[1].Local.Host {
		t.Fatal("distinct IPv4 and IPv6 origin hostnames collapsed")
	}
}
