package rewriter

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func websocketLiteralMapper(t *testing.T) *OriginMapper {
	t.Helper()
	parse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	return mustMapper(t, parse("https://main.example"), "127.0.0.1:18099", "alias.local",
		OriginRoute{Upstream: parse("https://api.example:8443"), Alias: "api.alias.local"},
		OriginRoute{Upstream: parse("http://plain.example"), Alias: "plain.alias.local"},
		OriginRoute{Upstream: parse("http://main.example:8443"), Alias: "http.alias.local"},
		OriginRoute{Upstream: parse("https://main.example:8443"), Alias: "https.alias.local"},
	)
}

func TestRewriteWebSocketURLUsesOnlyRegisteredFullOrigins(t *testing.T) {
	mapper := websocketLiteralMapper(t)
	for _, tc := range []struct{ source, want string }{
		{"wss://main.example/socket", "wss://alias.local:18099/socket"},
		{"WSS://MAIN.EXAMPLE:443/socket", "wss://alias.local:18099/socket"},
		{"wss://api.example:8443/socket", "wss://api.alias.local:18099/socket"},
		{"ws://plain.example/socket", "wss://plain.alias.local:18099/socket"},
		{"ws://plain.example:80/socket", "wss://plain.alias.local:18099/socket"},
		{"ws://main.example:8443/socket", "wss://http.alias.local:18099/socket"},
		{"wss://main.example:8443/socket", "wss://https.alias.local:18099/socket"},
		{"wss://main.example/a%2fb?x=1&x=2&y=%2f#part%2fone", "wss://alias.local:18099/a%2fb?x=1&x=2&y=%2f#part%2fone"},
		{"wss://main.example?", "wss://alias.local:18099?"},
		{"wss://main.example#", "wss://alias.local:18099#"},
		{"wss://main.example", "wss://alias.local:18099"},
	} {
		t.Run(tc.source, func(t *testing.T) {
			if got := mapper.RewriteWebSocketURL(tc.source); got != tc.want {
				t.Fatalf("WebSocket route: got %q want %q", got, tc.want)
			}
			parsed, err := url.Parse(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			if mapper.IsKnownFullOrigin(parsed) {
				t.Fatal("WebSocket literal mapping expanded HTTP/SRI fetch authorization")
			}
			if got := mapper.RewriteUpstreamURL(tc.source); got != tc.source {
				t.Fatalf("generic HTTP URL mapper now accepts WebSocket URLs: %q", got)
			}
		})
	}
}

func TestRewriteWebSocketURLLeavesUnknownOrMalformedOriginsUntouched(t *testing.T) {
	mapper := websocketLiteralMapper(t)
	for _, source := range []string{
		"ws://main.example/socket", "ws://main.example:443/socket", "wss://main.example:80/socket",
		"wss://api.example/socket", "wss://api.example:9443/socket", "wss://plain.example/socket",
		"wss://unknown.example/socket", "wss://main.example.unrelated.example/socket",
		"wss://alias.local:18099/socket", "https://main.example/socket", "//main.example/socket", "/socket",
		"wss://user@main.example/socket", "wss://user:pass@main.example/socket", "wss:main.example/socket",
		"wss:///socket", "wss://main.example:/socket", "wss://main.example:0/socket", "wss://main.example:65536/socket",
		"wss://main.example/%zz", "wss://main.example/socket\n", " wss://main.example/socket", "wss://[bad-ip/socket",
	} {
		t.Run(source, func(t *testing.T) {
			if got := mapper.RewriteWebSocketURL(source); got != source {
				t.Fatalf("unregistered or malformed origin mapped: %q -> %q", source, got)
			}
		})
	}
	var absent *OriginMapper
	if got := absent.RewriteWebSocketURL("wss://main.example/socket"); got != "wss://main.example/socket" {
		t.Fatal("nil mapper changed source")
	}
}

func TestJavaScriptWebSocketLiteralMappingPreservesOtherBytes(t *testing.T) {
	mapper := websocketLiteralMapper(t)
	gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	source := "\tconst first = new WebSocket('wss://main.example/socket?x=1&x=2');\r\n" +
		`const other="wss://api.example:8443/stream"; const plain = 'ws://plain.example/events';` + "\n" +
		`const product = "AcmeCorp"; const unknown = 'wss://unknown.example/socket';` + "\n"
	want := strings.NewReplacer(
		"wss://main.example/socket?x=1&x=2", "wss://alias.local:18099/socket?x=1&x=2",
		"wss://api.example:8443/stream", "wss://api.alias.local:18099/stream",
		"ws://plain.example/events", "wss://plain.alias.local:18099/events",
		"AcmeCorp", gate.Scrub("AcmeCorp", "fixture"),
	).Replace(source)
	for _, mime := range []string{"application/javascript", "text/javascript; charset=utf-8"} {
		got := RewriteBody([]byte(source), mime, "/app.js", gate, false, RewriteOpts{Origins: mapper}).Body
		if string(got) != want {
			t.Fatalf("JS literal routing changed unrelated source bytes (%s):\n got %q\nwant %q", mime, got, want)
		}
	}
}

func TestJavaScriptWebSocketMappingDoesNotGuessAssembledOrEscapedURLs(t *testing.T) {
	mapper := websocketLiteralMapper(t)
	gate := scrub.NewGate(nil, nil, "alias.local")
	for _, source := range []string{
		`const socket = "wss:\/\/main.example/socket";`,
		`const socket = "\u0077ss://main.example/socket";`,
		`const socket = "wss://main.example/\u0073ocket";`,
		`const socket = "wss://main.example/socket`,
		`const socket = "wss://main.example/socket/" + name;`,
		`const socket = prefix + "wss://main.example/socket";`,
		`const socket = "wss://" + host + "/socket";`,
		"const socket = `wss://main.example/${name}`;",
		"const socket = `wss://main.example/socket`;",
		`// "wss://main.example/socket"` + "\nconst untouched = true;",
		`/* "wss://main.example/socket" */ const untouched = true;`,
		`const text = "prefix wss://main.example/socket";`,
	} {
		t.Run(source, func(t *testing.T) {
			got := rewriteJS([]byte(source), gate, "/app.js", mapper)
			if string(got) != source {
				t.Fatalf("unsupported URL form was guessed: got %q want %q", got, source)
			}
		})
	}
}
