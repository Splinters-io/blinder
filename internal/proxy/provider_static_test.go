package proxy

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/rewriter"
	"github.com/Splinters-io/blinder/internal/scrub"
	"golang.org/x/net/html"
)

func TestProviderRestrictedBaseAndRefreshStayOnAlias(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "target") }))
	defer target.Close()
	var origin string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<base href="%s/"><meta http-equiv="refresh" content="2;url='%s/v1/next?x=1&amp;x=2'"><script src="v1/api.js"></script>`, origin, origin)
	}))
	defer provider.Close()
	origin = provider.URL
	_, _, client, aliases, _ := providerOriginFixture(t, target, []*httptest.Server{provider}, true)
	status, headers, body := providerOriginDo(t, client, "GET", aliases[0].String()+"/v1/widget", "", nil)
	if status != 200 || headers.Get("Content-Length") != fmt.Sprint(len(body)) {
		t.Fatalf("status/length: %d %v", status, headers)
	}
	if strings.Contains(body, origin) || !strings.Contains(body, aliases[0].String()+"/") {
		t.Fatalf("provider base/refresh escaped alias: %s", body)
	}
	z := html.NewTokenizer(strings.NewReader(body))
	base := aliases[0]
	var resource string
	for z.Next() != html.ErrorToken {
		token := z.Token()
		for _, attr := range token.Attr {
			if token.Data == "base" && attr.Key == "href" {
				base, _ = url.Parse(attr.Val)
			}
			if token.Data == "script" && attr.Key == "src" {
				u, _ := base.Parse(attr.Val)
				resource = u.String()
			}
		}
	}
	if resource != aliases[0].String()+"/v1/api.js" {
		t.Fatalf("base changed relative routing: %s", resource)
	}
}

func TestProviderLegacyRouteUnavailableOnTargetAndOperator(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("legacy route reached target") }))
	defer target.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("legacy route reached provider") }))
	defer provider.Close()
	s, local, client, _, _ := providerOriginFixture(t, target, []*httptest.Server{provider}, false)
	u, _ := url.Parse(local.URL)
	for _, host := range []string{u.Host, "blinder-operator.localhost:" + u.Port()} {
		for _, tor := range []bool{true, false} {
			// Endpoint dispatch is forbidden even if there is no active route
			// registry (the direct-mode configuration).
			if !tor {
				s.providerRoutes = nil
			}
			status, _, _ := providerOriginDo(t, client, "GET", "http://"+host+"/__blinder/captcha/res?u="+url.QueryEscape(provider.URL), "", nil)
			if status != 404 {
				t.Fatalf("legacy %s tor=%v status=%d", host, tor, status)
			}
		}
	}
}

func TestProviderStaticReturnURLsUsePrimaryAndExtraTargetRoutes(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "target") }))
	defer target.Close()
	extra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "extra") }))
	defer extra.Close()
	const suffix = "/resume/a%2Fb?x=%2f&x=two+words&bare&empty=#fragment"
	const relative = "scripts/loader.js?x=%2f&x=2"
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		for _, destination := range []struct{ name, origin string }{{"primary", target.URL}, {"extra", extra.URL}} {
			value := strings.ReplaceAll(destination.origin+suffix, "&", "&amp;")
			fmt.Fprintf(w, `<form id="%s-form" action="%s"></form><iframe id="%s-frame" src="%s"></iframe><a id="%s-anchor" href="%s">return</a><link id="%s-link" rel="stylesheet" href="%s"><meta id="%s-refresh" http-equiv="refresh" content="2; url='%s'">`, destination.name, value, destination.name, value, destination.name, value, destination.name, value, destination.name, value)
		}
		fmt.Fprintf(w, `<script id="relative-provider" src="%s"></script>`, strings.ReplaceAll(relative, "&", "&amp;"))
	}))
	defer provider.Close()
	s, _, client, aliases, _ := providerOriginFixture(t, target, []*httptest.Server{provider}, true, func(s *Server) http.Handler {
		extraURL, _ := url.Parse(extra.URL)
		s.cfg.ExtraOrigins = []*url.URL{extraURL}
		alias := scrub.AliasOrigin(extraURL.Scheme, extraURL.Hostname(), extraURL.Port(), s.cfg.AliasDomain)
		mapper, err := rewriter.NewOriginMapper(s.cfg.TargetURL, s.cfg.ListenAddr, s.cfg.AliasDomain, rewriter.OriginRoute{Upstream: extraURL, Alias: alias})
		if err != nil {
			t.Fatal(err)
		}
		s.origins = mapper
		return s
	})
	status, headers, body := providerOriginDo(t, client, "GET", aliases[0].String()+"/v1/widget", "", nil)
	if status != 200 || headers.Get("Content-Length") != fmt.Sprint(len(body)) {
		t.Fatalf("status/length: %d %v", status, headers)
	}
	want := make(map[string]string)
	for _, destination := range []struct{ name, origin string }{{"primary", target.URL}, {"extra", extra.URL}} {
		mapped := s.origins.RewriteUpstreamURL(destination.origin + suffix)
		if mapped == destination.origin+suffix {
			t.Fatal("fixture target was not registered")
		}
		for _, name := range []string{"form", "frame", "anchor", "link"} {
			want[destination.name+"-"+name] = mapped
		}
		want[destination.name+"-refresh"] = "2; url='" + mapped + "'"
	}
	want["relative-provider"] = relative
	z := html.NewTokenizer(strings.NewReader(body))
	for z.Next() != html.ErrorToken {
		token := z.Token()
		var id, value string
		for _, attr := range token.Attr {
			switch attr.Key {
			case "id":
				id = attr.Val
			case "action", "src", "href", "content":
				value = attr.Val
			}
		}
		if expected, ok := want[id]; ok {
			if value != expected {
				t.Errorf("%s=%q want %q", id, value, expected)
			}
			delete(want, id)
		}
	}
	if len(want) != 0 {
		t.Fatalf("expected elements missing: %v; body=%s", want, body)
	}
}

func TestProviderHTMLNegotiatesSupportedEncoding(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "target") }))
	defer target.Close()
	var providerOrigin string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept-Encoding"); got != "gzip, identity" {
			t.Errorf("unsupported browser encoding forwarded: %q", got)
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		compressed := gzip.NewWriter(w)
		fmt.Fprintf(compressed, `<iframe src="%s/v1/frame?x=1&amp;x=2"></iframe>`, providerOrigin)
		compressed.Close()
	}))
	defer provider.Close()
	providerOrigin = provider.URL
	_, _, client, aliases, _ := providerOriginFixture(t, target, []*httptest.Server{provider}, true)
	status, headers, body := providerOriginDo(t, client, "GET", aliases[0].String()+"/v1/widget", "", http.Header{"Accept-Encoding": {"gzip, deflate, br, zstd"}})
	if status != 200 || headers.Get("Content-Encoding") != "" || !strings.Contains(body, aliases[0].String()+"/v1/frame?x=1&amp;x=2") || strings.Contains(body, providerOrigin) {
		t.Fatalf("gzip HTML forwarding failed: %d %v %q", status, headers, body)
	}
}
