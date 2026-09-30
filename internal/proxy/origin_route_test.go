package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/rewriter"
	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestHTTPRejectedOriginsDoNotReachTarget(t *testing.T) {
	var primaryCalls, extraCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls.Add(1)
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, "primary")
	}))
	defer primary.Close()
	extra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extraCalls.Add(1)
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, "extra")
	}))
	defer extra.Close()
	cfg, err := config.New(primary.URL, "127.0.0.1:18099", "alias.local", nil, true, false, false, "", "", 0, "", "", 30, 60)
	if err != nil {
		t.Fatal(err)
	}
	extraURL, _ := url.Parse(extra.URL)
	cfg.ExtraOrigins = []*url.URL{extraURL}
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.transport.(*http.Transport).CloseIdleConnections()
	front := httptest.NewTLSServer(s)
	defer front.Close()
	extraAlias := s.origins.Load().RouteAliases()[1]
	for _, host := range []string{"alias.local:18098", "unknown.example:18099", "alias.local", extraAlias + ":18098", "alias.local:0", "alias.local:65536"} {
		t.Run(host, func(t *testing.T) {
			if got := s.origins.Load().Resolve(host); got != nil {
				t.Fatalf("fixture Host should be rejected by mapper: %q -> %v", host, got)
			}
			primaryBefore, extraBefore := primaryCalls.Load(), extraCalls.Load()
			req, _ := http.NewRequest(http.MethodGet, front.URL+"/fixture", nil)
			req.Host = host
			response, err := front.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusMisdirectedRequest || primaryCalls.Load() != primaryBefore || extraCalls.Load() != extraBefore {
				t.Fatalf("rejected Host reached upstream: Host=%q status=%d body=%q primaryCalls=%d extraCalls=%d", host, response.StatusCode, body, primaryCalls.Load()-primaryBefore, extraCalls.Load()-extraBefore)
			}
		})
	}
	for _, route := range []struct{ host, body string }{
		{"alias.local:18099", "primary"},
		{"ALIAS.local:018099", "primary"},
		{extraAlias + ":18099", "extra"},
		{extraAlias + ":018099", "extra"},
	} {
		t.Run("accepted_"+route.host, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, front.URL+"/fixture", nil)
			req.Host = route.host
			response, err := front.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusOK || string(body) != route.body {
				t.Fatalf("valid route rejected or misrouted: Host=%q status=%d body=%q", route.host, response.StatusCode, body)
			}
		})
	}
}

func TestTLSNamesMatchRegisteredOriginAliases(t *testing.T) {
	cfg, err := config.New("https://primary.example", "127.0.0.1:18099", "Alias.local", nil, true, false, false, "", "", 0, "", t.TempDir()+"/private", 30, 60)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"https://assets.example", "https://assets.example:8443", "http://assets.example:8080"} {
		u, _ := url.Parse(raw)
		cfg.ExtraOrigins = append(cfg.ExtraOrigins, u)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.transport.(*http.Transport).CloseIdleConnections()
	certificate, err := x509.ParseCertificate(s.server.TLSConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range s.origins.Load().RouteAliases() {
		if err := certificate.VerifyHostname(alias); err != nil {
			t.Errorf("registered alias missing from TLS SAN: %s: %v", alias, err)
		}
		if s.origins.Load().Resolve(alias+":18099") == nil {
			t.Errorf("registered alias missing from route table: %s", alias)
		}
	}
}

func TestEquivalentListenPortHasConsistentOriginAndRoute(t *testing.T) {
	primary, _ := url.Parse("https://primary.example")
	extra, _ := url.Parse("https://assets.example")
	alias := scrub.AliasOrigin(extra.Scheme, extra.Hostname(), extra.Port(), "alias.local")
	mapper, err := rewriter.NewOriginMapper(primary, "127.0.0.1:018099", "alias.local", rewriter.OriginRoute{Upstream: extra, Alias: alias})
	if err != nil {
		t.Fatal(err)
	}
	local, _ := url.Parse("https://" + alias + ":18099")
	if !mapper.IsKnownFullOrigin(local) {
		t.Fatal("fixture canonical origin should be recognized")
	}
	if got := mapper.Resolve(local.Host); got == nil || got.Host != extra.Host {
		t.Fatalf("recognized origin has no matching route: origin=%s Resolve=%v", local, got)
	}
}

func TestOriginRouteDefaultHTTPSPortAndIPv6(t *testing.T) {
	primary, _ := url.Parse("https://primary.example")
	for _, listen := range []string{"[::1]:443", "[::1]:00443", "[::1]:18099"} {
		mapper, err := rewriter.NewOriginMapper(primary, listen, "alias.local")
		if err != nil {
			t.Fatal(err)
		}
		for _, host := range []string{"[::1]", "alias.local", "[::1]:443", "[::1]:00443", "[::1]:18099", "[::1]:018099", "[::1]:", "::1", "[::1]:0", "[::1]:65536", "[::1]:https"} {
			t.Run(listen+"_"+host, func(t *testing.T) {
				want := host == "[::1]" || host == "alias.local" || host == "[::1]:443" || host == "[::1]:00443"
				if listen == "[::1]:18099" {
					want = host == "[::1]:18099" || host == "[::1]:018099"
				}
				got := mapper.Resolve(host)
				if (got != nil) != want {
					t.Fatalf("Resolve(%q) on listen %q=%v; accepted=%v", host, listen, got, want)
				}
			})
		}
	}
}
