package rewriter

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestProtocolRelativeOriginMapping(t *testing.T) {
	target, _ := url.Parse("https://pentesterlab.com")
	assetsURL, _ := url.Parse("https://assets.pentesterlab.com")
	alias := scrub.AliasOrigin(assetsURL.Scheme, assetsURL.Hostname(), assetsURL.Port(), "target-001.localhost")
	extra := OriginRoute{Upstream: assetsURL, Alias: alias}
	origins, err := NewOriginMapper(target, "127.0.0.1:18100", "target-001.localhost", extra)
	if err != nil {
		t.Fatal(err)
	}
	gate := scrub.NewGate([]string{"pentesterlab.com"}, []string{"PentesterLab"}, "target-001.localhost")

	input := "//assets.pentesterlab.com/svgs/logo.svg"
	got := scrubResourceURL(input, gate, "test", origins)

	if strings.Contains(got, "pentesterlab") {
		t.Fatalf("identity leaked in output: %s", got)
	}
	if !strings.HasPrefix(got, "//") {
		t.Fatalf("protocol-relative prefix lost: %s", got)
	}
	if !strings.Contains(got, "/svgs/logo.svg") {
		t.Fatalf("path lost: %s", got)
	}
	if !strings.Contains(got, alias) {
		t.Fatalf("origin alias %s not used: %s", alias, got)
	}
}
