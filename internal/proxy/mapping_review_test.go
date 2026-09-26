package proxy

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/rewriter"
	"github.com/Splinters-io/blinder/internal/scrub"
	"github.com/Splinters-io/blinder/internal/sri"
)

func mappingReviewServer(t *testing.T, target string, tokens []string, fn audit267SRITransport, extra ...string) *Server {
	t.Helper()
	return mappingReviewServerAt(t, target, "127.0.0.1:18099", tokens, fn, extra...)
}

// Synthetic HTTP front ends bind an ephemeral port. Declare that explicitly
// when the test exercises body fidelity rather than emitted local-origin URLs.
func mappingReviewEphemeralServer(t *testing.T, target string, tokens []string, fn audit267SRITransport, extra ...string) *Server {
	t.Helper()
	return mappingReviewServerAt(t, target, "127.0.0.1:0", tokens, fn, extra...)
}

func mappingReviewServerAt(t *testing.T, target, listen string, tokens []string, fn audit267SRITransport, extra ...string) *Server {
	t.Helper()
	cfg, err := config.New(target, listen, "alias.local", tokens, true, false, false, "", "", 0, "", "", 30, 60, extra...)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	if fn != nil {
		s.transport = fn
		s.sriPipeline = sri.NewPipeline(scopeSRIRepresentation(sri.PipelineConfig{Transport: fn, Cache: s.sriCache, IsAllowedOrigin: s.origins.IsKnownFullOrigin, CookieRestoreFn: s.gate.RestoreCookieHeader, ScrubFn: func(body []byte, ct, path string) []byte {
			return rewriter.RewriteBody(body, ct, path, s.gate, false).Body
		}}, s.origins, s.gate, s.cfg.Paranoid))
	}
	return s
}

// The standard Go transport, not a stub, must accept the restored request.
func TestMappingReviewRealTransportRestoresLength(t *testing.T) {
	for _, ct := range []string{"application/json", "application/x-www-form-urlencoded"} {
		t.Run(ct, func(t *testing.T) {
			received := make(chan string, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					w.Header().Set("Content-Type", "application/json")
					io.WriteString(w, `{"name":"AcmeCorp"}`)
					return
				}
				b, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, err.Error(), 400)
					return
				}
				received <- string(b)
				io.WriteString(w, "ok")
			}))
			defer upstream.Close()
			s := mappingReviewServer(t, upstream.URL, []string{"AcmeCorp"}, nil)
			page := audit267CacheRequest(s, "GET", "/model", nil)
			var values map[string]string
			if err := json.Unmarshal(page.Body.Bytes(), &values); err != nil {
				t.Fatal(err)
			}
			if values["name"] == "AcmeCorp" {
				t.Fatal("fixture wasn't transformed")
			}
			payload := page.Body.String()
			want := `{"name":"AcmeCorp"}`
			if ct == "application/x-www-form-urlencoded" {
				payload = url.Values{"name": {values["name"]}}.Encode()
				want = "name=AcmeCorp"
			}
			r := httptest.NewRequest("POST", "https://alias.local:18099/submit", strings.NewReader(payload))
			r.Header.Set("Content-Type", ct)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("restored body rejected by actual HTTP transport: status=%d body=%q", w.Code, w.Body.String())
			}
			select {
			case got := <-received:
				if got != want {
					t.Fatalf("got %q want %q", got, want)
				}
			default:
				t.Fatal("upstream did not receive complete request")
			}
		})
	}
}

func TestMappingReviewJSONRestorationRespectsEscaping(t *testing.T) {
	for _, tc := range []struct {
		name, original string
		escapeAlias    bool
	}{{"quoted_original", `Acme"Corp`, false}, {"escaped_alias", "AcmeCorp", true}} {
		t.Run(tc.name, func(t *testing.T) {
			var received []byte
			raw, _ := json.Marshal(map[string]string{"name": tc.original})
			s := mappingReviewServer(t, "https://main.example", []string{tc.original}, func(r *http.Request) (*http.Response, error) {
				if r.Method == "POST" {
					received, _ = io.ReadAll(r.Body)
					return audit267SRIResponse("text/plain", "ok"), nil
				}
				return audit267SRIResponse("application/json", string(raw)), nil
			})
			page := audit267CacheRequest(s, "GET", "/model", nil)
			var values map[string]string
			if err := json.Unmarshal(page.Body.Bytes(), &values); err != nil {
				t.Fatal(err)
			}
			values["note"] = "operator edit"
			body, _ := json.Marshal(values)
			payload := string(body)
			if tc.escapeAlias {
				payload = strings.ReplaceAll(payload, "[", `\u005b`)
			}
			r := httptest.NewRequest("POST", "https://alias.local:18099/submit", strings.NewReader(payload))
			r.Header.Set("Content-Type", "application/json")
			s.ServeHTTP(httptest.NewRecorder(), r)
			var got map[string]string
			if err := json.Unmarshal(received, &got); err != nil {
				t.Fatalf("inverse inserted unescaped JSON text: %v; forwarded=%s", err, received)
			}
			if got["name"] != tc.original || got["note"] != "operator edit" {
				t.Fatalf("JSON round trip failed: got=%v want name=%q plus edit", got, tc.original)
			}
		})
	}
}

func TestMappingReviewLiteralAliasIsNotAnInstruction(t *testing.T) {
	g := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	alias := g.Scrub("AcmeCorp", "fixture")
	original := "literal " + alias + " and identity AcmeCorp"
	transformed := g.Scrub(original, "document")
	if got := g.RestoreBody(transformed); got != original {
		t.Fatalf("literal placeholder confused with generated reference: original=%q transformed=%q restored=%q", original, transformed, got)
	}
}

func TestMappingReviewInverseCoversQueryAndFormKeys(t *testing.T) {
	t.Run("query", func(t *testing.T) {
		var received string
		s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/page" {
				return audit267SRIResponse("text/html", `<a href="/search?name=AcmeCorp">search</a>`), nil
			}
			received = r.URL.Query().Get("name")
			return audit267SRIResponse("text/plain", "ok"), nil
		})
		page := audit267CacheRequest(s, "GET", "/page", nil)
		href := audit267SRIAttribute(page.Body.String(), "href")
		audit267CacheRequest(s, "GET", href, nil)
		if received != "AcmeCorp" {
			t.Fatalf("following rewritten link forwards alias: href=%q upstream value=%q", href, received)
		}
	})
	t.Run("form_key", func(t *testing.T) {
		var received url.Values
		s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
			if r.Method == "POST" {
				r.ParseForm()
				received = r.PostForm
				return audit267SRIResponse("text/plain", "ok"), nil
			}
			return audit267SRIResponse("text/html", `<form><input name="AcmeCorp" value="value"></form>`), nil
		})
		page := audit267CacheRequest(s, "GET", "/page", nil)
		key := audit267SRIAttribute(page.Body.String(), "name")
		r := httptest.NewRequest("POST", "https://alias.local:18099/submit", strings.NewReader(url.Values{key: {"value"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		s.ServeHTTP(httptest.NewRecorder(), r)
		if received.Get("AcmeCorp") != "value" {
			t.Fatalf("form field name not restored: %v", received)
		}
	})
}

// Apply standard cookie-jar host/path rules to the URL emitted into the page.
func mappingReviewBrowser(t *testing.T, s *Server, jar http.CookieJar, address string) *httptest.ResponseRecorder {
	t.Helper()
	u, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", address, nil)
	for _, c := range jar.Cookies(u) {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	jar.SetCookies(u, w.Result().Cookies())
	return w
}

func TestMappingReviewVersionRouteKeepsOriginCredentials(t *testing.T) {
	const asset = "var value=1;"
	var observed []string
	s := mappingReviewServer(t, "https://main.example", []string{"AcmeCorp"}, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "assets.example" {
			observed = append(observed, r.Header.Get("Cookie"))
			resp := audit267SRIResponse("application/javascript", asset)
			resp.Header.Set("Cache-Control", "no-store")
			return resp, nil
		}
		if r.URL.Path == "/login" {
			resp := audit267SRIResponse("text/plain", "ok")
			resp.Header.Set("Set-Cookie", "sid=primary-session; Path=/; Secure; HttpOnly")
			return resp, nil
		}
		return audit267SRIResponse("text/html", audit267SRIPage("https://assets.example/asset", asset)), nil
	}, "https://assets.example")
	jar, _ := cookiejar.New(nil)
	base, _ := url.Parse("https://alias.local:18099/page")
	mappingReviewBrowser(t, s, jar, "https://alias.local:18099/login")
	page := mappingReviewBrowser(t, s, jar, base.String())
	src := audit267SRIAttribute(page.Body.String(), "src")
	if src == "" || len(observed) != 1 || observed[0] != "" {
		t.Fatalf("expected one credential-free prefetch: src=%q cookies=%q", src, observed)
	}
	resource, err := base.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	response := mappingReviewBrowser(t, s, jar, resource.String())
	if len(observed) != 2 {
		t.Fatalf("fixture expected no-store upstream refetch: got %q", observed)
	}
	if observed[1] != "" {
		t.Fatalf("primary-origin cookie leaked to extra origin through issued URL %q: upstream cookies=%q status=%d", resource, observed, response.Code)
	}
}

func TestMappingReviewVersionRouteKeepsPathCookies(t *testing.T) {
	const asset = "var value=1;"
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/account/login":
			resp := audit267SRIResponse("text/plain", "ok")
			resp.Header.Set("Set-Cookie", "sid=path-session; Path=/account; Secure")
			return resp, nil
		case "/account/page":
			return audit267SRIResponse("text/html", audit267SRIPage("/account/asset", asset)), nil
		case "/account/asset":
			resp := audit267SRIResponse("application/javascript", asset)
			resp.Header.Set("Cache-Control", "no-store")
			if r.Header.Get("Cookie") != "sid=path-session" {
				resp.StatusCode = 403
			}
			return resp, nil
		default:
			return nil, fmt.Errorf("unexpected upstream URL %s", r.URL)
		}
	})
	jar, _ := cookiejar.New(nil)
	base, _ := url.Parse("https://alias.local:18099/account/page")
	mappingReviewBrowser(t, s, jar, "https://alias.local:18099/account/login")
	control := mappingReviewBrowser(t, s, jar, "https://alias.local:18099/account/asset")
	if control.Code != 200 {
		t.Fatalf("unversioned control failed: %d", control.Code)
	}
	page := mappingReviewBrowser(t, s, jar, base.String())
	src := audit267SRIAttribute(page.Body.String(), "src")
	if src == "" {
		t.Fatal("prefetch did not produce resource")
	}
	resource, err := base.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	got := mappingReviewBrowser(t, s, jar, resource.String())
	if got.Code != 200 {
		t.Fatalf("version URL lost path-scoped login cookie: src=%q status=%d body=%q", src, got.Code, got.Body.String())
	}
}
