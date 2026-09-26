package rewriter

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func mustMapper(t *testing.T, target *url.URL, listen, alias string, extras ...OriginRoute) *OriginMapper {
	t.Helper()
	m, err := NewOriginMapper(target, listen, alias, extras...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMultiOriginRewrite(t *testing.T) {
	primary, _ := url.Parse("https://app.example.com")
	api, _ := url.Parse("https://api.example.com")
	m := mustMapper(t, primary, "127.0.0.1:8099", "target-001.local",
		OriginRoute{Upstream: api, Alias: "host-api.target-001.local"},
	)

	for _, tc := range []struct {
		input, want string
		origin      bool
	}{
		// Primary alias → primary upstream
		{"https://target-001.local:8099", "https://app.example.com", true},
		{"https://target-001.local:8099/page?q=1", "https://app.example.com/page?q=1", false},
		// Loopback → primary upstream
		{"https://127.0.0.1:8099", "https://app.example.com", true},
		{"https://localhost:8099", "https://app.example.com", true},
		// Extra alias → extra upstream
		{"https://host-api.target-001.local:8099", "https://api.example.com", true},
		{"https://host-api.target-001.local:8099/v1/data", "https://api.example.com/v1/data", false},
		// Unrelated → unchanged
		{"https://other.example.com", "https://other.example.com", true},
	} {
		if got := m.Rewrite(tc.input, tc.origin); got != tc.want {
			t.Errorf("Rewrite(%q, %v) = %q; want %q", tc.input, tc.origin, got, tc.want)
		}
	}
}

func TestMultiOriginResolve(t *testing.T) {
	primary, _ := url.Parse("https://app.example.com")
	api, _ := url.Parse("https://api.example.com")
	m := mustMapper(t, primary, "127.0.0.1:8099", "target-001.local",
		OriginRoute{Upstream: api, Alias: "host-api.target-001.local"},
	)

	for _, tc := range []struct {
		host string
		want string
	}{
		{"target-001.local:8099", "app.example.com"},
		{"127.0.0.1:8099", "app.example.com"},
		{"localhost:8099", "app.example.com"},
		{"host-api.target-001.local:8099", "api.example.com"},
	} {
		got := m.Resolve(tc.host)
		if got == nil {
			t.Errorf("Resolve(%q) = nil; want %s", tc.host, tc.want)
			continue
		}
		if got.Host != tc.want {
			t.Errorf("Resolve(%q).Host = %q; want %q", tc.host, got.Host, tc.want)
		}
	}

	for _, host := range []string{
		"unknown.example.com:8099",
		"target-001.local",
		"target-001.local:9999",
	} {
		if got := m.Resolve(host); got != nil {
			t.Errorf("Resolve(%q) = %v; want nil", host, got)
		}
	}
}

func TestResolveDefaultPort(t *testing.T) {
	primary, _ := url.Parse("https://app.example.com")
	m := mustMapper(t, primary, "127.0.0.1:443", "target-001.local")

	if got := m.Resolve("target-001.local"); got == nil {
		t.Error("bare hostname should resolve when listen port is 443")
	}
	if got := m.Resolve("target-001.local:443"); got == nil {
		t.Error("explicit :443 should resolve when listen port is 443")
	}
	if got := m.Resolve("target-001.local:8099"); got != nil {
		t.Errorf("wrong port should not resolve, got %v", got)
	}
}

func TestResolveRejectsWrongPort(t *testing.T) {
	primary, _ := url.Parse("https://app.example.com")
	m := mustMapper(t, primary, "127.0.0.1:8099", "target-001.local")

	if got := m.Resolve("target-001.local:8099"); got == nil {
		t.Error("correct port should resolve")
	}
	if got := m.Resolve("target-001.local:9999"); got != nil {
		t.Errorf("wrong port should not resolve, got %v", got)
	}
	if got := m.Resolve("target-001.local"); got != nil {
		t.Errorf("bare hostname on non-443 listen should not resolve, got %v", got)
	}
}

func TestMultiOriginResponseOrigin(t *testing.T) {
	primary, _ := url.Parse("https://app.example.com")
	api, _ := url.Parse("https://api.example.com")
	m := mustMapper(t, primary, "127.0.0.1:8099", "target-001.local",
		OriginRoute{Upstream: api, Alias: "host-api.target-001.local"},
	)

	for _, tc := range []struct {
		input, want string
	}{
		// Primary upstream → local primary alias address
		{"https://app.example.com", "https://target-001.local:8099"},
		// Extra upstream → local extra alias address
		{"https://api.example.com", "https://host-api.target-001.local:8099"},
		// Wildcard preserved
		{"*", "*"},
		// Null preserved
		{"null", "null"},
		// Unrelated unchanged
		{"https://other.example.com", "https://other.example.com"},
	} {
		if got := m.RewriteResponseOrigin(tc.input, ""); got != tc.want {
			t.Errorf("RewriteResponseOrigin(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
}

func TestMultiOriginPortCollisionDetection(t *testing.T) {
	primary, _ := url.Parse("https://app.example.com")
	api1, _ := url.Parse("https://api.example.com:8443")
	api2, _ := url.Parse("https://api.example.com:9443")

	alias1 := scrub.AliasOrigin(api1.Scheme, api1.Hostname(), api1.Port(), "target-001.local")
	alias2 := scrub.AliasOrigin(api2.Scheme, api2.Hostname(), api2.Port(), "target-001.local")

	if alias1 == alias2 {
		t.Fatalf("AliasOrigin should produce different aliases for different ports, both got %s", alias1)
	}

	mustMapper(t, primary, "127.0.0.1:8099", "target-001.local",
		OriginRoute{Upstream: api1, Alias: alias1},
		OriginRoute{Upstream: api2, Alias: alias2},
	)
}

func TestRouteCollisionRejected(t *testing.T) {
	primary, _ := url.Parse("https://app.example.com")
	api1, _ := url.Parse("https://api1.example.com")
	api2, _ := url.Parse("https://api2.example.com")

	_, err := NewOriginMapper(primary, "127.0.0.1:8099", "target-001.local",
		OriginRoute{Upstream: api1, Alias: "shared.target-001.local"},
		OriginRoute{Upstream: api2, Alias: "shared.target-001.local"},
	)
	if err == nil {
		t.Fatal("duplicate alias hostnames should be rejected")
	}
	if !strings.Contains(err.Error(), "route collision") {
		t.Fatalf("error should mention route collision: %v", err)
	}
}

func TestRouteCollisionWithPrimaryRejected(t *testing.T) {
	primary, _ := url.Parse("https://app.example.com")
	extra, _ := url.Parse("https://api.example.com")

	_, err := NewOriginMapper(primary, "127.0.0.1:8099", "target-001.local",
		OriginRoute{Upstream: extra, Alias: "target-001.local"},
	)
	if err == nil {
		t.Fatal("extra alias colliding with primary should be rejected")
	}
}

func TestRewriteUpstreamURL(t *testing.T) {
	primary, _ := url.Parse("https://app.example.com")
	api, _ := url.Parse("https://api.example.com")
	m := mustMapper(t, primary, "127.0.0.1:8099", "target-001.local",
		OriginRoute{Upstream: api, Alias: "host-api.target-001.local"},
	)

	for _, tc := range []struct {
		input, want string
	}{
		{"https://app.example.com/redirect?to=/home", "https://target-001.local:8099/redirect?to=/home"},
		{"https://api.example.com/v1/users?page=2", "https://host-api.target-001.local:8099/v1/users?page=2"},
		{"https://other.example.com/path", "https://other.example.com/path"},
		{"not-a-url", "not-a-url"},
	} {
		if got := m.RewriteUpstreamURL(tc.input); got != tc.want {
			t.Errorf("RewriteUpstreamURL(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
}

func TestOriginMappingPreservesScannerInputs(t *testing.T) {
	target, _ := url.Parse("http://upstream.example:8080/base")
	m := mustMapper(t, target, "127.0.0.1:18099", "alias.local")
	for _, tc := range []struct {
		input, want string
		origin      bool
	}{
		{"https://127.0.0.1:18099", "http://upstream.example:8080", true},
		{"https://LOCALHOST:18099", "http://upstream.example:8080", true},
		{"https://[::1]:18099", "http://upstream.example:8080", true},
		{"https://alias.local:18099/a%2Fb?q=https%3A%2F%2Falias.local#part", "http://upstream.example:8080/a%2Fb?q=https%3A%2F%2Falias.local#part", false},
		{"null", "null", true},
		{"https://unrelated.example/?next=alias.local", "https://unrelated.example/?next=alias.local", false},
		{"https://alias.local.attacker.example:18099", "https://alias.local.attacker.example:18099", true},
		{"https://alias.local@attacker.example:18099", "https://alias.local@attacker.example:18099", true},
		{"https://user@alias.local:18099", "https://user@alias.local:18099", true},
		{"https://alias.local:18099/", "https://alias.local:18099/", true},
		{"https://alias.local:18099?", "https://alias.local:18099?", true},
		{"https://alias.local:18099#", "https://alias.local:18099#", true},
		{"https://alias.local:18099 https://other.example", "https://alias.local:18099 https://other.example", true},
		{"https://127.0.0.1:9999", "https://127.0.0.1:9999", true},
		{"http://127.0.0.1:18099", "http://127.0.0.1:18099", true},
		{"https://alias.local:", "https://alias.local:", true},
	} {
		if got := m.Rewrite(tc.input, tc.origin); got != tc.want {
			t.Errorf("Rewrite(%q, %v) = %q; want %q", tc.input, tc.origin, got, tc.want)
		}
	}
	standard := mustMapper(t, target, "127.0.0.1:443", "alias.local")
	if got := standard.Rewrite("https://alias.local", true); got != "http://upstream.example:8080" {
		t.Fatalf("default HTTPS port: %s", got)
	}
	// Duplicate Origin fields are invalid input, not permission to repair it.
	r := httptest.NewRequest("POST", "https://alias.local:18099/form", nil)
	r.Header.Add("Origin", "https://alias.local:18099")
	r.Header.Add("Origin", "https://unrelated.example")
	out := RewriteRequestHeaders(r, target.Host, scrub.NewGate(nil, nil, "alias.local"), m)
	if got := out.Header.Values("Origin"); len(got) != 2 || got[0] != "https://alias.local:18099" {
		t.Fatalf("duplicate origins changed: %v", got)
	}
}

func TestRouteAliases(t *testing.T) {
	primary, _ := url.Parse("https://app.example.com")
	api, _ := url.Parse("https://api.example.com")
	m := mustMapper(t, primary, "127.0.0.1:8099", "target-001.local",
		OriginRoute{Upstream: api, Alias: "host-api.target-001.local"},
	)

	aliases := m.RouteAliases()
	if len(aliases) != 2 {
		t.Fatalf("expected 2 aliases, got %d: %v", len(aliases), aliases)
	}
	if aliases[0] != "target-001.local" {
		t.Errorf("first alias should be primary: got %s", aliases[0])
	}
	if aliases[1] != "host-api.target-001.local" {
		t.Errorf("second alias should be extra: got %s", aliases[1])
	}

	aliases[0] = "mutated"
	if m.RouteAliases()[0] != "target-001.local" {
		t.Error("RouteAliases should return a defensive copy")
	}
}

func TestRouteAliasesNil(t *testing.T) {
	var m *OriginMapper
	if got := m.RouteAliases(); got != nil {
		t.Errorf("nil mapper should return nil aliases, got %v", got)
	}
}
