package rewriter

import (
	"net/url"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestRestoreResourceValueRequiresCompleteLocalOrigin(t *testing.T) {
	primary, _ := url.Parse("http://main.example:8080")
	extra, _ := url.Parse("https://assets.example:8443")
	m := mustMapper(t, primary, "127.0.0.1:18099", "alias.local", OriginRoute{Upstream: extra, Alias: "assets.alias.local"})
	g := scrub.NewGate([]string{"main.example"}, []string{"AcmeCorp"}, "alias.local")
	for _, tc := range []struct{ input, want string }{
		{"https://127.0.0.1:18099/a%2fb?x=%2f#", "http://main.example:8080/a%2fb?x=%2f#"},
		{"wss://alias.local:18099/socket", "ws://main.example:8080/socket"},
		{"https://assets.alias.local:18099/value", "https://assets.example:8443/value"},
		{"wss://assets.alias.local:18099/socket", "wss://assets.example:8443/socket"},
		{"https://alias.local:18098/value", "https://alias.local:18098/value"},
		{"http://alias.local:18099/value", "http://alias.local:18099/value"},
		{"ws://alias.local:18099/value", "ws://alias.local:18099/value"},
		{"ftp://alias.local:18099/value", "ftp://alias.local:18099/value"},
		{"https://unknown.invalid:18099/value", "https://unknown.invalid:18099/value"},
		{"https://user@alias.local:18099/value", "https://user@alias.local:18099/value"},
	} {
		if got := RestoreResourceValue(tc.input, g, m); got != tc.want {
			t.Errorf("%s => %s want %s", tc.input, got, tc.want)
		}
	}
}

func TestRestoreResourceValueRetainsIssuedDomainAliasInverse(t *testing.T) {
	primary, _ := url.Parse("http://main.example:8080")
	m := mustMapper(t, primary, "127.0.0.1:18099", "alias.local")
	g := scrub.NewGate([]string{"main.example"}, nil, "alias.local")
	for _, original := range []string{"http://main.example:8080/return", "https://main.example:9999/return", "ws://main.example:8080/socket", "wss://main.example:8443/socket", "ftp://main.example:21/file"} {
		alias := g.Scrub(original, "fixture")
		if alias == original {
			t.Fatalf("fixture did not mask %q", original)
		}
		if got := m.RestoreResourceURL(alias); got != alias {
			t.Fatalf("unknown full origin inferred a route: %q => %q", alias, got)
		}
		if got := RestoreResourceValue(alias, g, m); got != original {
			t.Fatalf("issued alias inverse: %q => %q want %q", alias, got, original)
		}
		if u, _ := url.Parse(alias); m.Resolve(u.Host) != nil {
			t.Fatalf("restoring an application value created a route: %q", alias)
		}
	}
}
