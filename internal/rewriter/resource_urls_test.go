package rewriter

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func resourceRouteFixture(t *testing.T) (*scrub.Gate, *OriginMapper) {
	t.Helper()
	target, _ := url.Parse("https://target.example.com:8443")
	extra, _ := url.Parse("http://assets.example.com:8080")
	gate := scrub.NewGate([]string{"target.example.com", "assets.example.com"}, []string{"AcmeCorp"}, "127.0.0.1")
	origins, err := NewOriginMapper(target, "127.0.0.1:8099", "127.0.0.1", OriginRoute{Upstream: extra, Alias: "assets.alias.local"})
	if err != nil {
		t.Fatal(err)
	}
	return gate, origins
}

func TestResourceURLsKeepGeneratedAuthorityAndRestoreData(t *testing.T) {
	for _, tc := range []struct{ name, value, prefix string }{
		{"primary", "https://target.example.com:8443/item?label=AcmeCorp#AcmeCorp", "https://127.0.0.1:8099/item?label="},
		{"extra", "http://assets.example.com:8080/item?label=AcmeCorp", "https://assets.alias.local:8099/item?label="},
		{"websocket", "wss://target.example.com:8443/events?label=AcmeCorp", "wss://127.0.0.1:8099/events?label="},
		{"already-local", "https://127.0.0.1:8099/item?label=AcmeCorp", "https://127.0.0.1:8099/item?label="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate, origins := resourceRouteFixture(t)
			got := scrubResourceURL(tc.value, gate, "test", origins)
			if !strings.HasPrefix(got, tc.prefix) || strings.Contains(got, "AcmeCorp") {
				t.Fatalf("invalid routed URL %q", got)
			}
			u, err := url.Parse(got)
			if err != nil || gate.RestoreBody(u.Query().Get("label")) != "AcmeCorp" {
				t.Fatalf("functional query did not restore: %q, %v", got, err)
			}
		})
	}
}

func TestCompleteResourceLiteralsUseRegisteredRoutes(t *testing.T) {
	for _, tc := range []struct{ name, contentType, body, want string }{
		{"js-fetch", "text/javascript", `fetch('https://target.example.com:8443/data')`, "https://127.0.0.1:8099/data"},
		{"js-template", "text/javascript", "fetch(`https://target.example.com:8443/data`)", "https://127.0.0.1:8099/data"},
		{"js-ws", "text/javascript", `new WebSocket('wss://target.example.com:8443/events')`, "wss://127.0.0.1:8099/events"},
		{"js-ws-template", "text/javascript", "new WebSocket(`wss://target.example.com:8443/events`)", "wss://127.0.0.1:8099/events"},
		{"css-url", "text/css", `p { background: url("https://target.example.com:8443/image") }`, "https://127.0.0.1:8099/image"},
		{"css-import", "text/css", `@import "http://assets.example.com:8080/style" screen;`, "https://assets.alias.local:8099/style"},
		{"html-script", "text/html", `<script src="https://target.example.com:8443/script"></script>`, "https://127.0.0.1:8099/script"},
		{"html-style", "text/html", `<style>p {background:url('https://target.example.com:8443/image')}</style>`, "https://127.0.0.1:8099/image"},
		{"html-style-attribute", "text/html", `<p style="background:url('https://target.example.com:8443/image')">text</p>`, "https://127.0.0.1:8099/image"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate, origins := resourceRouteFixture(t)
			got := string(RewriteBody([]byte(tc.body), tc.contentType, "/", gate, false, RewriteOpts{Origins: origins}).Body)
			if !strings.Contains(got, tc.want) || strings.Contains(got, ":8443") || strings.Contains(got, ":8080") {
				t.Fatalf("resource did not use registered route: %s", got)
			}
		})
	}
}

func TestResourceRoutingDoesNotInventUnknownOriginRoutes(t *testing.T) {
	gate, origins := resourceRouteFixture(t)
	for _, raw := range []string{"https://target.example.com:9443/item", "http://target.example.com:8443/item", "https://unknown.example/item", "https://user:pass@target.example.com:8443/item"} {
		got := scrubResourceURL(raw, gate, "test", origins)
		if got != gate.Scrub(raw, "test") {
			t.Fatalf("unregistered origin gained a local route: %s", got)
		}
	}
}

func TestResourceURLPathFilenameNotTreatedAsDomain(t *testing.T) {
	gate, origins := resourceRouteFixture(t)
	for _, tc := range []struct {
		name, value, wantPath string
	}{
		{
			"webp_extension",
			"https://target.example.com:8443/uploads/Hero-Image.webp",
			"/uploads/Hero-Image.webp",
		},
		{
			"png_extension",
			"https://target.example.com:8443/uploads/Overview-Card.png",
			"/uploads/Overview-Card.png",
		},
		{
			"identity_token_in_filename",
			"https://target.example.com:8443/uploads/AcmeCorp-Hero.webp",
			"/uploads/",
		},
		{
			"no_domain_scrub_in_path",
			"https://target.example.com:8443/uploads/Fancy-Product.svg",
			"/uploads/Fancy-Product.svg",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := scrubResourceURL(tc.value, gate, "test", origins)
			if !strings.Contains(got, tc.wantPath) {
				t.Errorf("filename corrupted in path:\n  input: %s\n  got:   %s\n  want path containing: %s", tc.value, got, tc.wantPath)
			}
			if strings.Contains(got, "target.example.com") {
				t.Errorf("target domain leaked: %s", got)
			}
		})
	}
}

func TestResourceURLPathFilenameRoundTrips(t *testing.T) {
	gate, origins := resourceRouteFixture(t)
	for _, tc := range []struct {
		name, value, wantFilename string
	}{
		{
			"mixed_case_webp",
			"https://target.example.com:8443/uploads/Hero-Image.webp",
			"Hero-Image.webp",
		},
		{
			"identity_plus_ext",
			"https://target.example.com:8443/uploads/AcmeCorp-Platform.webp",
			"AcmeCorp-Platform.webp",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scrubbed := scrubResourceURL(tc.value, gate, "test", origins)
			restored := gate.RestoreBody(scrubbed)
			if !strings.Contains(restored, tc.wantFilename) {
				t.Errorf("filename did not round-trip:\n  scrubbed: %s\n  restored: %s\n  want: %s", scrubbed, restored, tc.wantFilename)
			}
		})
	}
}

func TestCSSResourceURLRetainsSyntaxWhitespace(t *testing.T) {
	for _, whitespace := range []string{"  ", "\t", "\r\n", "\f"} {
		gate, origins := resourceRouteFixture(t)
		body := "p{background:url(https://target.example.com:8443/image" + whitespace + ")}"
		want := "p{background:url(https://127.0.0.1:8099/image" + whitespace + ")}"
		if got := string(rewriteCSS([]byte(body), gate, "/", origins)); got != want {
			t.Fatalf("syntax whitespace became URL data: got %q want %q", got, want)
		}
	}
}
