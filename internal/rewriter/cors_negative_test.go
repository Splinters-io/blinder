package rewriter

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestCORSInvalidOriginDoesNotBecomePermission(t *testing.T) {
	upstream, _ := url.Parse("https://upstream.private")
	m, err := NewOriginMapper(upstream, "127.0.0.1:8099", "alias.local")
	if err != nil {
		t.Fatal(err)
	}
	const local = "https://127.0.0.1:8099"
	for _, suffix := range []string{"/", "/path", "?", "?a=b", "#", "#fragment"} {
		t.Run(suffix, func(t *testing.T) {
			g := scrub.NewGate([]string{"upstream.private"}, nil, "alias.local")
			h := http.Header{"Access-Control-Allow-Origin": {upstream.String() + suffix}}
			got := RewriteResponseHeaders(h, g, "alias.local", upstream.Host, ResponseHeaderOpts{OriginMapper: m, RequestOrigin: local}).Get("Access-Control-Allow-Origin")
			if got == local || got == "https://alias.local:8099" || got == "*" {
				t.Fatalf("invalid upstream CORS value became valid permission: %q -> %q", h.Get("Access-Control-Allow-Origin"), got)
			}
			if strings.Contains(got, "upstream.private") || !strings.HasSuffix(got, suffix) {
				t.Fatalf("invalid origin lost masking or its invalid suffix: %q", got)
			}
		})
	}
}

func TestCORSNoncanonicalOriginRemainsNegative(t *testing.T) {
	u, _ := url.Parse("https://upstream.private")
	m, err := NewOriginMapper(u, "127.0.0.1:8099", "alias.local")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"HTTPS://upstream.private", "https://UPSTREAM.PRIVATE", "https://upstream.private:443", "https://upstream.private:0443"} {
		if got := m.RewriteResponseOrigin(value, "https://127.0.0.1:8099"); got != value {
			t.Errorf("negative CORS value repaired: %q -> %q", value, got)
		}
	}
	if got := m.RewriteResponseOrigin(u.String(), "https://127.0.0.1:8099"); got != "https://127.0.0.1:8099" {
		t.Fatalf("valid CORS translation lost: %q", got)
	}
}

func TestCORSProxyOriginsAndProtocolValuesAreNotRescrubbed(t *testing.T) {
	u, _ := url.Parse("https://upstream.private")
	m, err := NewOriginMapper(u, "127.0.0.1:8099", "alias.local")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ value, want string }{
		{u.String(), "https://alias.local:8099"}, {"null", "null"}, {"*", "*"},
	} {
		g := scrub.NewGate([]string{"upstream.private"}, []string{"alias", "null"}, "alias.local")
		h := http.Header{"Access-Control-Allow-Origin": {tc.value}}
		got := RewriteResponseHeaders(h, g, "alias.local", u.Host, ResponseHeaderOpts{OriginMapper: m, RequestOrigin: "https://alias.local:8099"}).Get("Access-Control-Allow-Origin")
		if got != tc.want {
			t.Errorf("CORS control corrupted by identity matching: %q -> %q, want %q", tc.value, got, tc.want)
		}
	}
}
