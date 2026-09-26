package captcha

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func providerRelayFixture(t *testing.T, transport http.RoundTripper) (*ProviderHandler, *ProviderRoutes) {
	t.Helper()
	cfg, err := ParseConfig([]byte("version: 1\ncaptcha:\n  custom:\n    - name: fixture\n      resource_origins: [https://provider.test, https://other.test]\n      resource_url_regex: ['^https://(provider|other)\\.test/widget/']\n"))
	if err != nil {
		t.Fatal(err)
	}
	routes, err := NewProviderRoutes(cfg.Matcher, "https", "127.0.0.1:8099")
	if err != nil {
		t.Fatal(err)
	}
	return NewProviderHandler(ProviderRelayConfig{Routes: routes, Transport: transport, OperatorToken: "reserved-operator-secret"}), routes
}

func providerRelayRequest(t *testing.T, routes *ProviderRoutes, method, upstream, body string) *http.Request {
	t.Helper()
	local, ok := routes.RewriteURL(upstream, nil)
	if !ok {
		t.Fatalf("test resource is not mapped: %s", upstream)
	}
	r := httptest.NewRequest(method, local, strings.NewReader(body))
	r.TLS = &tls.ConnectionState{}
	return r
}

func providerRelayResponse(status int, headers http.Header, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

func TestProviderAliasRelayPreservesMethodsURLAndErrors(t *testing.T) {
	const target = "https://provider.test/widget/a%2Fb?x=%2f&x=two+words&bare&empty="
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "PROPFIND", "custom!Verb"} {
		t.Run(method, func(t *testing.T) {
			body := "opaque-token\x00unchanged"
			h, routes := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
				got, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				if r.Method != method || r.URL.String() != target || r.Host != "provider.test" || r.RequestURI != "" || string(got) != body || r.ContentLength != int64(len(body)) {
					t.Fatalf("request changed: method=%s URL=%s Host=%s RequestURI=%s body=%q length=%d", r.Method, r.URL, r.Host, r.RequestURI, got, r.ContentLength)
				}
				if r.Header.Get("X-App") != "opaque" || r.Header.Get("X-Hop") != "" || r.Header.Get("Connection") != "" {
					t.Fatalf("request headers: %v", r.Header)
				}
				return providerRelayResponse(422, http.Header{"Content-Type": {"application/json"}, "X-Upstream-Error": {"invalid response"}, "Connection": {"X-Internal"}, "X-Internal": {"strip me"}}, `{"error":"invalid response"}`), nil
			}))
			r := providerRelayRequest(t, routes, method, target, body)
			r.Header.Set("Connection", "X-Hop")
			r.Header.Set("X-Hop", "must disappear")
			r.Header.Set("X-App", "opaque")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 422 || w.Body.String() != `{"error":"invalid response"}` || w.Header().Get("X-Upstream-Error") != "invalid response" || w.Header().Get("X-Internal") != "" || w.Header().Get("Content-Length") != "28" {
				t.Fatalf("response changed: %d %s %v", w.Code, w.Body.String(), w.Header())
			}
		})
	}
}

func TestProviderAliasRelayCORSAndPreflightUseActualPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, origin, allow string
		status              int
	}{
		{"allowed", "https://127.0.0.1:8099", "https://target.test", 204},
		{"denied", "https://127.0.0.1:8099", "", 403},
		{"unrelated-grant-not-echoed", "https://127.0.0.1:8099", "https://unrelated.test", 204},
		{"wildcard-preserved", "https://127.0.0.1:8099", "*", 204},
		{"opaque-origin-preserved", "null", "null", 204},
		{"invalid-origin-grant-not-repaired", "https://127.0.0.1:8099", "https://target.test/", 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h, routes := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				wantOrigin := "https://target.test"
				if tc.origin == "null" {
					wantOrigin = "null"
				}
				if r.Method != "OPTIONS" || r.Header.Get("Origin") != wantOrigin || r.Header.Get("Access-Control-Request-Method") != "CUSTOM" || r.Header.Get("Access-Control-Request-Headers") != "x-provider-token" {
					t.Fatalf("preflight changed: %s %v", r.Method, r.Header)
				}
				headers := http.Header{"Vary": {"Origin", "Accept-Encoding"}}
				if tc.allow != "" {
					headers.Set("Access-Control-Allow-Origin", tc.allow)
					headers.Set("Access-Control-Allow-Methods", "CUSTOM")
					headers.Set("Access-Control-Allow-Headers", "x-provider-token")
				}
				return providerRelayResponse(tc.status, headers, ""), nil
			}))
			h.cfg.MapTargetOrigin = func(value string, toUpstream bool) string {
				if toUpstream && value == "https://127.0.0.1:8099" {
					return "https://target.test"
				}
				if !toUpstream && value == "https://target.test" {
					return "https://target-001.local:8099"
				}
				return value
			}
			r := providerRelayRequest(t, routes, "OPTIONS", "https://provider.test/widget/api", "")
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Access-Control-Request-Method", "CUSTOM")
			r.Header.Set("Access-Control-Request-Headers", "x-provider-token")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := tc.allow
			if tc.allow == "https://target.test" {
				want = tc.origin
			}
			if calls != 1 || w.Code != tc.status || w.Header().Get("Access-Control-Allow-Origin") != want || w.Header().Get("Access-Control-Allow-Credentials") != "" || !reflect.DeepEqual(w.Header().Values("Vary"), []string{"Origin", "Accept-Encoding"}) {
				t.Fatalf("CORS changed: calls=%d status=%d headers=%v", calls, w.Code, w.Header())
			}
		})
	}
}

func TestProviderAliasRelayPreservesDuplicateControls(t *testing.T) {
	policies := []string{"default-src 'none'", "script-src 'self'"}
	reports := []string{"connect-src 'none'", "object-src 'none'"}
	h, routes := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
		return providerRelayResponse(200, http.Header{"Content-Security-Policy": policies, "Content-Security-Policy-Report-Only": reports, "Access-Control-Allow-Origin": {"*", "null"}, "X-Frame-Options": {"DENY"}, "Content-Type": {"text/html"}}, "<p>unchanged</p>"), nil
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, providerRelayRequest(t, routes, "GET", "https://provider.test/widget/page", ""))
	if w.Code != 200 || w.Body.String() != "<p>unchanged</p>" || !reflect.DeepEqual(w.Header().Values("Content-Security-Policy"), policies) || !reflect.DeepEqual(w.Header().Values("Content-Security-Policy-Report-Only"), reports) || !reflect.DeepEqual(w.Header().Values("Access-Control-Allow-Origin"), []string{"*", "null"}) || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("controls changed: %v, %s", w.Header(), w.Body.String())
	}
	var seen []string
	h.cfg.RewriteCSP = func(policy string, _ *url.URL) string {
		seen = append(seen, policy)
		return policy + "; report-to translated"
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, providerRelayRequest(t, routes, "GET", "https://provider.test/widget/page", ""))
	if len(seen) != 4 || len(w.Header().Values("Content-Security-Policy")) != 2 || len(w.Header().Values("Content-Security-Policy-Report-Only")) != 2 {
		t.Fatalf("policies collapsed: seen=%v headers=%v", seen, w.Header())
	}
}

func TestProviderAliasRelayCookiesAndReservedCredentials(t *testing.T) {
	h, routes := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
		if !reflect.DeepEqual(r.Header.Values("Authorization"), []string{"Bearer provider-secret", "Basic cHJvdmlkZXI6c2VjcmV0"}) || strings.Contains(r.Header.Get("Cookie"), "operator") || r.Header.Get("Cookie") != "provider_session=opaque; another=provider" {
			t.Fatalf("credentials changed/leaked: %v", r.Header)
		}
		return providerRelayResponse(200, http.Header{"Set-Cookie": {
			"session=opaque; Domain=.provider.test; Path=/widget/; Secure; HttpOnly; SameSite=None; Priority=High",
			"host=only; Path=/; Secure; Partitioned",
			"parent=wide; Domain=test; Path=/",
			"other=wrong; Domain=other.test; Path=/",
			OperatorCookieName + "=reserved; Path=/; Secure",
			"__Host-invalid=repaired; Domain=provider.test; Path=/; Secure",
			"__Host-valid=opaque; Path=/; Secure",
		}}, "ok"), nil
	}))
	r := providerRelayRequest(t, routes, "POST", "https://provider.test/widget/api", "")
	r.Header.Add("Authorization", "Bearer reserved-operator-secret")
	r.Header.Add("Authorization", "Bearer provider-secret")
	r.Header.Add("Authorization", "bearer   reserved-operator-secret")
	r.Header.Add("Authorization", "Basic cHJvdmlkZXI6c2VjcmV0")
	r.Header.Set("Cookie", OperatorCookieName+"=operator; provider_session=opaque; __blinder_op=operator; another=provider")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	want := []string{"session=opaque; Path=/widget/; Secure; HttpOnly; SameSite=None; Priority=High", "host=only; Path=/; Secure; Partitioned", "__Host-valid=opaque; Path=/; Secure"}
	if !reflect.DeepEqual(w.Header().Values("Set-Cookie"), want) {
		t.Fatalf("cookies=%v want %v", w.Header().Values("Set-Cookie"), want)
	}
	if r.Header.Values("Authorization")[0] != "Bearer reserved-operator-secret" {
		t.Fatal("original request mutated")
	}
}

func TestProviderAliasRelayProviderOriginRefererAndRedirects(t *testing.T) {
	var routes *ProviderRoutes
	h, initial := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Origin") != "https://other.test" || r.Header.Get("Referer") != "https://other.test/widget/a%2Fb?x=1&x=2" {
			t.Fatalf("provider source not restored: %v", r.Header)
		}
		return providerRelayResponse(307, http.Header{"Location": {"https://other.test/widget/next?b=2&a=%2f&a=3"}, "Access-Control-Allow-Origin": {"https://other.test"}}, "redirect"), nil
	}))
	routes = initial
	other := routes.MapOrigin("https://other.test", false)
	r := providerRelayRequest(t, routes, "POST", "https://provider.test/widget/api", "body")
	r.Header.Set("Origin", other)
	r.Header.Set("Referer", other+"/widget/a%2Fb?x=1&x=2")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	want, _ := routes.RewriteURL("https://other.test/widget/next?b=2&a=%2f&a=3", nil)
	if w.Code != 307 || w.Header().Get("Location") != want || w.Header().Get("Access-Control-Allow-Origin") != other || w.Body.String() != "redirect" {
		t.Fatalf("redirect=%d %v %s", w.Code, w.Header(), w.Body.String())
	}
	for _, location := range []string{"https://unknown.test/widget/next", "https://provider.test/private", "http://provider.test/widget/next", "https://secret@provider.test/widget/next"} {
		h.cfg.Transport = relayTestTransport(func(r *http.Request) (*http.Response, error) {
			return providerRelayResponse(302, http.Header{"Location": {location}}, "redirect"), nil
		})
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 502 || w.Header().Get("Location") != "" {
			t.Fatalf("redirect escaped: %s: %d %v", location, w.Code, w.Header())
		}
	}
}

func TestProviderAliasRelayBodyRewriteValidatorsAndBodylessResponses(t *testing.T) {
	for _, change := range []bool{false, true} {
		h, routes := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
			return providerRelayResponse(200, http.Header{"ETag": {`"original"`}, "Content-Digest": {"original-digest"}, "Content-Length": {"8"}}, "original"), nil
		}))
		h.cfg.RewriteBody = func(body []byte, _ *url.URL, _ http.Header) ([]byte, error) {
			if change {
				copy(body, []byte("modified"))
			}
			return body, nil
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, providerRelayRequest(t, routes, "GET", "https://provider.test/widget/api", ""))
		if w.Header().Get("Content-Length") != "8" || (w.Header().Get("ETag") == "") != change || (w.Header().Get("Content-Digest") == "") != change {
			t.Fatalf("change=%v validators=%v", change, w.Header())
		}
	}
	for _, tc := range []struct {
		method     string
		status     int
		wantLength string
	}{{"HEAD", 200, "42"}, {"GET", 204, ""}, {"GET", 304, "42"}} {
		h, routes := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
			return providerRelayResponse(tc.status, http.Header{"Content-Length": {"42"}}, "must not be sent"), nil
		}))
		h.cfg.RewriteBody = func([]byte, *url.URL, http.Header) ([]byte, error) {
			t.Error("bodyless response was rewritten")
			return nil, nil
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, providerRelayRequest(t, routes, tc.method, "https://provider.test/widget/api", ""))
		if w.Code != tc.status || w.Body.Len() != 0 || w.Header().Get("Content-Length") != tc.wantLength {
			t.Fatalf("bodyless response=%d %q %v", w.Code, w.Body.String(), w.Header())
		}
	}
}

func TestProviderAliasRelayBodyReadsOriginalPolicyBeforeMapping(t *testing.T) {
	const policy = "base-uri https://provider.test; script-src 'self'"
	h, routes := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
		return providerRelayResponse(200, http.Header{"Content-Security-Policy": {policy}, "Content-Type": {"text/html"}}, "<p>opaque</p>"), nil
	}))
	h.cfg.RewriteBody = func(body []byte, upstream *url.URL, headers http.Header) ([]byte, error) {
		if upstream.String() != "https://provider.test/widget/page" || headers.Get("Content-Security-Policy") != policy {
			t.Fatalf("body callback did not receive original policy: %s %v", upstream, headers)
		}
		return body, nil
	}
	h.cfg.RewriteCSP = func(value string, _ *url.URL) string {
		return strings.ReplaceAll(value, "https://provider.test", routes.MapOrigin("https://provider.test", false))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, providerRelayRequest(t, routes, "GET", "https://provider.test/widget/page", ""))
	if w.Code != 200 || strings.Contains(w.Header().Get("Content-Security-Policy"), "https://provider.test") {
		t.Fatalf("policy not mapped after body callback: %d %v", w.Code, w.Header())
	}
}

func TestProviderAliasRelayLimitsScopeAndTransportFailure(t *testing.T) {
	calls := 0
	h, routes := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("private upstream error")
	}))
	r := providerRelayRequest(t, routes, "POST", "https://provider.test/widget/api", strings.Repeat("a", 2*1024*1024+1))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 413 || calls != 0 {
		t.Fatalf("oversized request contacted provider: %d calls=%d", w.Code, calls)
	}
	r = providerRelayRequest(t, routes, "GET", "https://provider.test/widget/api", "")
	r.URL.Path = "/private"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || calls != 0 {
		t.Fatalf("out-of-scope request contacted provider: %d calls=%d", w.Code, calls)
	}
	r = providerRelayRequest(t, routes, "GET", "https://provider.test/widget/api", "")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 502 || strings.Contains(w.Body.String(), "private upstream error") {
		t.Fatalf("transport error=%d %s", w.Code, w.Body.String())
	}
	h.cfg.Transport = relayTestTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{'a'}, 10*1024*1024+1)))}, nil
	})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 502 {
		t.Fatalf("oversized response accepted: %d", w.Code)
	}
	h.cfg.Timeout = 10 * time.Millisecond
	h.cfg.Transport = relayTestTransport(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	started := time.Now()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 502 || time.Since(started) > time.Second {
		t.Fatalf("deadline not applied: %d %v", w.Code, time.Since(started))
	}
}

func TestProviderAliasRelayRefreshNavigation(t *testing.T) {
	for _, tc := range []struct {
		name, refresh string
		rejected      bool
	}{
		{"semicolon", "0;url=https://other.test/widget/next?x=%2f&x=2", false},
		{"comma-and-quotes", " 1.9 , URL = 'https://other.test/widget/next?x=%2f&x=2' ", false},
		{"relative", "2;url=next?x=%2f&x=2", false},
		{"outside-origin", "0;url=https://unknown.test/widget/next", true},
		{"outside-regex", "0;url=https://provider.test/private", true},
		{"delay-only", "0", false},
		{"malformed-delay", "zero;url=https://unknown.test/a", false},
		{"malformed-url", "0;url=http://[bad", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, routes := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
				return providerRelayResponse(200, http.Header{"Refresh": {tc.refresh}, "Content-Type": {"text/plain"}}, "refresh response"), nil
			}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, providerRelayRequest(t, routes, "GET", "https://provider.test/widget/page", ""))
			if tc.rejected {
				if w.Code != 502 || w.Header().Get("Refresh") != "" {
					t.Fatalf("refresh escaped: %d %v", w.Code, w.Header())
				}
				return
			}
			want := tc.refresh
			switch tc.name {
			case "semicolon", "comma-and-quotes":
				want = strings.ReplaceAll(want, "https://other.test", routes.MapOrigin("https://other.test", false))
			case "relative":
				want = "2;url=" + routes.MapOrigin("https://provider.test", false) + "/widget/next?x=%2f&x=2"
			}
			if w.Code != 200 || w.Body.String() != "refresh response" || w.Header().Get("Refresh") != want {
				t.Fatalf("refresh changed status/body or mapped incorrectly: %d %s %v; want=%q", w.Code, w.Body.String(), w.Header(), want)
			}
		})
	}
}

func TestProviderAliasRelayKeepsRawEncodingNegotiationWithoutRewriter(t *testing.T) {
	const browserEncodings = "gzip, deflate, br, zstd"
	h, routes := providerRelayFixture(t, relayTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Accept-Encoding") != browserEncodings {
			t.Fatalf("raw relay changed encoding negotiation: %q", r.Header.Get("Accept-Encoding"))
		}
		return providerRelayResponse(200, http.Header{"Content-Type": {"application/octet-stream"}, "Content-Encoding": {"br"}}, "opaque encoded bytes"), nil
	}))
	r := providerRelayRequest(t, routes, "GET", "https://provider.test/widget/file", "")
	r.Header.Set("Accept-Encoding", browserEncodings)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "opaque encoded bytes" || w.Header().Get("Content-Encoding") != "br" {
		t.Fatalf("opaque encoding changed: %d %v %q", w.Code, w.Header(), w.Body.String())
	}
}
