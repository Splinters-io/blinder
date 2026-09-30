package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/sri"
)

func TestResponseLocationTLSRedirectPreservesBrowserSession(t *testing.T) {
	var targetURL string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "AcmeCorp_session", Value: "fixture-session", Path: "/", Secure: true, HttpOnly: true})
			http.Redirect(w, r, targetURL+"/account?return=%2Fhome#section", http.StatusSeeOther)
			return
		}
		cookie, err := r.Cookie("AcmeCorp_session")
		if r.URL.Path != "/account" || err != nil || cookie.Value != "fixture-session" {
			http.Error(w, "session lost", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Location", targetURL+"/account?return=%2Fhome#section")
		io.WriteString(w, "session-ok")
	}))
	defer target.Close()
	targetURL = target.URL
	front := httptest.NewUnstartedServer(nil)
	cfg, err := config.New(target.URL, front.Listener.Addr().String(), "target-001.local", []string{"AcmeCorp"}, true, false, false, "", "", 0, "", "", 30, 60)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.transport.(*http.Transport).CloseIdleConnections()
	front.Config.Handler = s
	front.StartTLS()
	defer front.Close()
	client := front.Client() // Verifies the local TLS fixture's certificate.
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := url.Parse(front.URL)
	redirects := 0
	client.CheckRedirect = func(r *http.Request, previous []*http.Request) error {
		redirects++
		if r.URL.Scheme != entry.Scheme || r.URL.Host != entry.Host {
			return fmt.Errorf("same-upstream redirect left the browser entry origin: %s", r.URL)
		}
		return nil
	}
	response, err := client.Get(front.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if redirects != 1 || response.StatusCode != 200 || string(body) != "session-ok" {
		t.Fatalf("redirect/session: redirects=%d status=%d body=%q", redirects, response.StatusCode, body)
	}
	if got := response.Header.Get("Content-Location"); got != front.URL+"/account?return=%2Fhome#section" {
		t.Fatalf("Content-Location = %q", got)
	}
}

func TestResponseLocationsRemainRequestScopedAcrossCaches(t *testing.T) {
	for _, mode := range []string{"fresh", "revalidated", "sri"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			s := mappingReviewServer(t, "https://upstream.example", nil, func(r *http.Request) (*http.Response, error) {
				calls++
				resp := audit267CacheResponse("cache fixture")
				if mode == "revalidated" && r.Header.Get("If-None-Match") != "" {
					if r.Header.Get("If-None-Match") != `"original"` {
						t.Error("stale response was not revalidated with upstream ETag")
					}
					resp.StatusCode = http.StatusNotModified
					return resp, nil
				}
				resp.Header.Set("ETag", `"original"`)
				if mode == "revalidated" {
					resp.Header.Set("Cache-Control", "max-age=0")
				}
				resp.Header.Set("Location", "https://upstream.example/account?next=%2Fhome#part")
				resp.Header.Set("Content-Location", "https://upstream.example/representation")
				return resp, nil
			})
			if mode == "sri" {
				for _, host := range []string{"127.0.0.1:18099", "localhost:18099", "alias.local:18099"} {
					s.sriCache.Put(sri.CacheKeyForAuthority("https://upstream.example/resource", nil, host), &sri.CacheEntry{
						ScrubbedBody: []byte("cache fixture"), ContentType: "text/plain",
						ResponseHeaders: http.Header{
							"Location":         {"https://upstream.example/account?next=%2Fhome#part"},
							"Content-Location": {"https://upstream.example/representation"},
							"Cache-Control":    {"max-age=3600"},
						},
					})
				}
			}
			etag := ""
			for i, host := range []string{"127.0.0.1:18099", "localhost:18099", "alias.local:18099", "alias.local:18099"} {
				r := httptest.NewRequest("GET", "https://"+host+"/resource", nil)
				r.Header.Set("Origin", "https://unrelated.invalid")
				if i == 1 {
					r.Header.Set("If-None-Match", etag)
				}
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				wantStatus := 200
				if i == 1 {
					wantStatus = 304
				}
				if w.Code != wantStatus {
					t.Fatalf("request %d status=%d body=%q", i, w.Code, w.Body.String())
				}
				if got := w.Header().Get("Location"); got != "https://"+host+"/account?next=%2Fhome#part" {
					t.Fatalf("request %d Location = %q", i, got)
				}
				if got := w.Header().Get("Content-Location"); got != "https://"+host+"/representation" {
					t.Fatalf("request %d Content-Location = %q", i, got)
				}
				etag = w.Header().Get("ETag")
			}
			wantCalls := map[string]int{"fresh": 3, "revalidated": 4, "sri": 0}[mode]
			if calls != wantCalls {
				t.Fatalf("upstream calls = %d, want %d", calls, wantCalls)
			}
		})
	}
}

func TestResponseLocationOriginBoundaries(t *testing.T) {
	s := mappingReviewServer(t, "https://upstream.example", nil, nil, "http://upstream.example", "https://upstream.example:8443")
	aliases := s.origins.Load().RouteAliases()
	for _, tc := range []struct{ name, host, location, want string }{
		{"same-origin", "127.0.0.1:18099", "https://alias.local:18099/account", "https://127.0.0.1:18099/account"},
		{"double-slash-path", "127.0.0.1:18099", "https://alias.local:18099//unrelated.invalid/path", "https://127.0.0.1:18099//unrelated.invalid/path"},
		{"different-scheme-route", "127.0.0.1:18099", "https://" + aliases[1] + ":18099/account", ""},
		{"different-port-route", "127.0.0.1:18099", "https://" + aliases[2] + ":18099/account", ""},
		{"unregistered-host", "unrelated.invalid:18099", "https://alias.local:18099/account", ""},
		{"mismatched-request-port", "127.0.0.1:18098", "https://alias.local:18099/account", ""},
		{"mismatched-location-port", "127.0.0.1:18099", "https://alias.local:18098/account", ""},
		{"downgrade", "127.0.0.1:18099", "http://alias.local:18099/account", ""},
		{"userinfo", "127.0.0.1:18099", "https://user@alias.local:18099/account", ""},
		{"protocol-relative", "127.0.0.1:18099", "//unrelated.invalid/path", ""},
		{"relative", "127.0.0.1:18099", "/account", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{"Location": {tc.location}, "Content-Location": {tc.location}}
			s.localizeResponseLocations(h, tc.host, s.cfg.TargetURL)
			want := tc.want
			if want == "" {
				want = tc.location
			}
			for _, name := range []string{"Location", "Content-Location"} {
				if got := h.Get(name); got != want {
					t.Fatalf("%s = %q, want %q", name, got, want)
				}
			}
		})
	}
}
