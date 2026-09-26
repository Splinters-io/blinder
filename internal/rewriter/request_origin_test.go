package rewriter

import (
	"net/url"
	"testing"
)

func TestRequestOriginViewDoesNotMutateOrAuthorizeRoutes(t *testing.T) {
	primary, _ := url.Parse("https://upstream.example")
	extra, _ := url.Parse("https://assets.example")
	mapper := mustMapper(t, primary, "127.0.0.1:18099", "alias.local", OriginRoute{Upstream: extra, Alias: "assets.alias.local"})
	for _, host := range []string{"127.0.0.1:18099", "localhost:18099", "alias.local:18099"} {
		view := mapper.ForRequestHost(host)
		if view == nil {
			t.Fatalf("valid host %s rejected", host)
		}
		if got := view.RewriteUpstreamURL("https://upstream.example/account/entry?x=1#part"); got != "https://"+host+"/account/entry?x=1#part" {
			t.Fatalf("local URL = %q", got)
		}
		if got := view.RewriteUpstreamURL("https://assets.example/style"); got != "https://assets.alias.local:18099/style" {
			t.Fatalf("extra origin collapsed: %q", got)
		}
		if got := mapper.RewriteUpstreamURL("https://upstream.example/account"); got != "https://alias.local:18099/account" {
			t.Fatalf("shared mapper mutated: %q", got)
		}
	}
	for _, host := range []string{"attacker.invalid:18099", "127.0.0.1:18098", "127.0.0.1", "user@127.0.0.1:18099"} {
		if mapper.ForRequestHost(host) != nil {
			t.Fatalf("invalid host created mapping: %q", host)
		}
	}
}
