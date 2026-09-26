package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
	"github.com/Splinters-io/blinder/internal/sri"
)

// Each route has a real upstream, while the downstream TLS server runs the
// production handler. Host selects the configured alias independently of the
// loopback address used to connect to this fixture.
func cookieOriginServer(t *testing.T, handler http.Handler) (*Server, *httptest.Server, []string) {
	t.Helper()
	primary := httptest.NewServer(handler)
	extra := httptest.NewServer(handler)
	t.Cleanup(primary.Close)
	t.Cleanup(extra.Close)
	extraURL, _ := url.Parse(extra.URL)
	cfg := newTestConfig(t, primary.URL)
	cfg.ListenAddr = "127.0.0.1:18099"
	cfg.ExtraOrigins = []*url.URL{extraURL}
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.transport.(*http.Transport).CloseIdleConnections)
	t.Cleanup(s.captchaQueue.Shutdown)
	proxy := httptest.NewTLSServer(s)
	t.Cleanup(proxy.Close)
	extraAlias := scrub.AliasOrigin(extraURL.Scheme, extraURL.Hostname(), extraURL.Port(), cfg.AliasDomain)
	return s, proxy, []string{cfg.AliasDomain, extraAlias}
}

func cookieOriginRequest(t *testing.T, proxy *httptest.Server, host, method, path string, cookie *http.Cookie, upgrade bool) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, proxy.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = host + ":18099"
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if upgrade {
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		r.Header.Set("Sec-WebSocket-Version", "13")
	}
	resp, err := proxy.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func cookieOriginResponseCookie(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	cookies := resp.Cookies()
	if len(cookies) != 1 || strings.Contains(cookies[0].Value, "AcmeCorp") {
		t.Fatalf("expected one transformed cookie: %v", resp.Header.Values("Set-Cookie"))
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return cookies[0]
}

func TestCookieOriginHTTPAndWebSocketRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name, method string
		status       int
	}{
		{"body", http.MethodGet, http.StatusOK},
		{"head", http.MethodHead, http.StatusOK},
		{"no-content", http.MethodGet, http.StatusNoContent},
		{"not-modified", http.MethodGet, http.StatusNotModified},
		{"error", http.MethodGet, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			received := make(chan string, 4)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Cache-Control", "no-store")
				if r.URL.Path == "/set" {
					w.Header().Set("Set-Cookie", "session=tok-AcmeCorp-secret; Path=/; Secure; HttpOnly")
					w.WriteHeader(tc.status)
				} else {
					received <- r.Header.Get("Cookie")
					if r.Header.Get("Upgrade") != "" {
						w.WriteHeader(http.StatusForbidden)
					}
				}
				fmt.Fprint(w, "fixture")
			})
			_, proxy, aliases := cookieOriginServer(t, handler)
			for _, alias := range aliases {
				t.Run(alias, func(t *testing.T) {
					set := cookieOriginRequest(t, proxy, alias, tc.method, "/set", nil, false)
					if set.StatusCode != tc.status {
						t.Fatalf("set status %d, want %d", set.StatusCode, tc.status)
					}
					cookie := cookieOriginResponseCookie(t, set)
					for _, upgrade := range []bool{false, true} {
						got := cookieOriginRequest(t, proxy, alias, http.MethodGet, "/check", cookie, upgrade)
						io.Copy(io.Discard, got.Body)
						got.Body.Close()
						wantStatus := http.StatusOK
						if upgrade {
							wantStatus = http.StatusForbidden
						}
						if got.StatusCode != wantStatus {
							t.Fatalf("check status %d, want %d", got.StatusCode, wantStatus)
						}
						if value := <-received; value != "session=tok-AcmeCorp-secret" {
							t.Fatalf("upgrade=%v: upstream received %q, want original cookie", upgrade, value)
						}
					}
				})
			}
		})
	}
}

func TestCookieOriginCachedResponseRoundTrip(t *testing.T) {
	var sets atomic.Int32
	received := make(chan string, 2)
	_, proxy, aliases := cookieOriginServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/set" {
			sets.Add(1)
			w.Header().Set("Cache-Control", "max-age=3600")
			w.Header().Set("Set-Cookie", "session=cache-AcmeCorp-secret; Path=/")
		} else {
			w.Header().Set("Cache-Control", "no-store")
			received <- r.Header.Get("Cookie")
		}
		fmt.Fprint(w, "fixture")
	}))
	for _, alias := range aliases {
		first := cookieOriginRequest(t, proxy, alias, http.MethodGet, "/set", nil, false)
		cookieOriginResponseCookie(t, first)
		before := sets.Load()
		cached := cookieOriginRequest(t, proxy, alias, http.MethodGet, "/set", nil, false)
		cookie := cookieOriginResponseCookie(t, cached)
		if sets.Load() != before {
			t.Fatal("fixture did not exercise the fresh response cache")
		}
		check := cookieOriginRequest(t, proxy, alias, http.MethodGet, "/check", cookie, false)
		io.Copy(io.Discard, check.Body)
		check.Body.Close()
		if got := <-received; got != "session=cache-AcmeCorp-secret" {
			t.Fatalf("cached cookie on %s restored as %q", alias, got)
		}
	}
}

func TestCookieOriginDoesNotRestoreAnotherRoute(t *testing.T) {
	received := make(chan string, 1)
	_, proxy, aliases := cookieOriginServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path == "/set" {
			w.Header().Set("Set-Cookie", "session=primary-AcmeCorp-secret; Path=/")
		} else {
			received <- r.Header.Get("Cookie")
		}
		fmt.Fprint(w, "fixture")
	}))
	initial := cookieOriginRequest(t, proxy, aliases[0], http.MethodGet, "/set", nil, false)
	cookie := cookieOriginResponseCookie(t, initial)
	check := cookieOriginRequest(t, proxy, aliases[1], http.MethodGet, "/check", cookie, false)
	io.Copy(io.Discard, check.Body)
	check.Body.Close()
	if got, want := <-received, "session="+cookie.Value; got != want {
		t.Fatalf("a different upstream port restored another route's value: got %q, want %q", got, want)
	}
}

func TestCookieOriginSRIRequestAndCachedResponseRoundTrip(t *testing.T) {
	asset := []byte(`const answer = 42;`)
	received := make(chan string, 8)
	var assets atomic.Int32
	_, proxy, aliases := cookieOriginServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		switch r.URL.Path {
		case "/set":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Set-Cookie", "session=page-AcmeCorp-secret; Path=/")
			fmt.Fprint(w, "fixture")
		case "/page":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<script src="/asset" integrity="%s"></script>`, sri.ComputeIntegrity(asset, "sha384"))
		case "/asset":
			assets.Add(1)
			received <- r.Header.Get("Cookie")
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Set("Cache-Control", "max-age=3600")
			w.Header().Set("Set-Cookie", "session=asset-AcmeCorp-secret; Path=/")
			w.Write(asset)
		case "/check":
			received <- r.Header.Get("Cookie")
			fmt.Fprint(w, "fixture")
		default:
			http.NotFound(w, r)
		}
	}))
	for _, alias := range aliases {
		t.Run(alias, func(t *testing.T) {
			initial := cookieOriginRequest(t, proxy, alias, http.MethodGet, "/set", nil, false)
			cookie := cookieOriginResponseCookie(t, initial)
			page := cookieOriginRequest(t, proxy, alias, http.MethodGet, "/page", cookie, false)
			html, err := io.ReadAll(page.Body)
			page.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			src := codexSRIAttribute(string(html), "src")
			if !strings.HasPrefix(src, "/asset?") {
				t.Fatalf("expected versioned SRI resource, got %s", html)
			}
			if got := <-received; got != "session=page-AcmeCorp-secret" {
				t.Fatalf("SRI prefetch received %q, want restored page cookie", got)
			}
			before := assets.Load()
			cached := cookieOriginRequest(t, proxy, alias, http.MethodGet, src, cookie, false)
			if cached.StatusCode != http.StatusOK {
				t.Fatalf("SRI resource status %d", cached.StatusCode)
			}
			assetCookie := cookieOriginResponseCookie(t, cached)
			if assets.Load() != before {
				t.Fatal("fixture did not exercise the SRI cache")
			}
			check := cookieOriginRequest(t, proxy, alias, http.MethodGet, "/check", assetCookie, false)
			io.Copy(io.Discard, check.Body)
			check.Body.Close()
			if got := <-received; got != "session=asset-AcmeCorp-secret" {
				t.Fatalf("SRI cached response cookie restored as %q", got)
			}
		})
	}
}

func TestCookieOriginSRIPrefetchUsesConfiguredHostSpelling(t *testing.T) {
	received := make(chan string, 1)
	asset := []byte("const answer = 42;")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			w.Header().Set("Set-Cookie", "session=tok-AcmeCorp-secret; Path=/")
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "fixture")
			return
		}
		received <- r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(asset)
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	target := "http://LOCALHOST:" + parsed.Port()
	cfg := newTestConfig(t, target)
	cfg.ListenAddr = "127.0.0.1:18099"
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.transport.(*http.Transport).CloseIdleConnections()
	defer s.captchaQueue.Shutdown()
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://127.0.0.1:18099/set", nil))
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal(w.Header())
	}
	base := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:18099/page", nil)
	base.AddCookie(cookies[0])
	result := s.sriPipeline.Process(strings.ToLower(target)+"/asset", sri.ComputeIntegrity(asset, "sha384"), "application/javascript", "", cfg.TargetURL, base)
	if result == nil || !result.UpstreamValid {
		t.Fatalf("prefetch: %+v", result)
	}
	if got := <-received; got != "session=tok-AcmeCorp-secret" {
		t.Fatalf("same-origin SRI host spelling lost session: %q", got)
	}
}
