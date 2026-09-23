package rewriter

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

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
