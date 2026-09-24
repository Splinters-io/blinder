package rewriter

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestMultiOriginRewrite(t *testing.T) {
	primary, _ := url.Parse("https://app.example.com")
	api, _ := url.Parse("https://api.example.com")
	m := NewOriginMapper(primary, "127.0.0.1:8099", "target-001.local",
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
	m := NewOriginMapper(primary, "127.0.0.1:8099", "target-001.local",
		OriginRoute{Upstream: api, Alias: "host-api.target-001.local"},
	)

	for _, tc := range []struct {
		host string
		want string
	}{
		{"target-001.local:8099", "app.example.com"},
		{"target-001.local", "app.example.com"},
		{"127.0.0.1:8099", "app.example.com"},
		{"localhost:8099", "app.example.com"},
		{"host-api.target-001.local:8099", "api.example.com"},
		{"host-api.target-001.local", "api.example.com"},
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

	if got := m.Resolve("unknown.example.com:8099"); got != nil {
		t.Errorf("Resolve(unknown) = %v; want nil", got)
	}
}

func TestMultiOriginResponseOrigin(t *testing.T) {
	primary, _ := url.Parse("https://app.example.com")
	api, _ := url.Parse("https://api.example.com")
	m := NewOriginMapper(primary, "127.0.0.1:8099", "target-001.local",
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

	_ = NewOriginMapper(primary, "127.0.0.1:8099", "target-001.local",
		OriginRoute{Upstream: api1, Alias: alias1},
		OriginRoute{Upstream: api2, Alias: alias2},
	)
}

func TestRewriteUpstreamURL(t *testing.T) {
	primary, _ := url.Parse("https://app.example.com")
	api, _ := url.Parse("https://api.example.com")
	m := NewOriginMapper(primary, "127.0.0.1:8099", "target-001.local",
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
	m := NewOriginMapper(target, "127.0.0.1:18099", "alias.local")
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
	standard := NewOriginMapper(target, "127.0.0.1:443", "alias.local")
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
