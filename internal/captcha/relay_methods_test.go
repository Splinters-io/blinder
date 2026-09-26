package captcha

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestProviderRelayArbitraryMethodsOnWire(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "opaque-body" {
			t.Errorf("request body changed: %q, %v", body, err)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", r.Method)
		w.WriteHeader(204)
	}))
	defer provider.Close()
	u, _ := url.Parse(provider.URL)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	h, _, id := relayTestHandler(t, func(r *http.Request) (*http.Response, error) {
		copy := r.Clone(r.Context())
		copy.URL.Scheme, copy.URL.Host = u.Scheme, u.Host
		return transport.RoundTrip(copy)
	})
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "MKCOL", "PURGE", "vendor.sync", "X!#$%&'*+-.^_`|~09"} {
		t.Run(method, func(t *testing.T) {
			path := "http://local.test" + resourcePath + "?u=" + url.QueryEscape("https://provider.test/widget/api") + "&sid=" + id
			r, err := http.NewRequest(method, path, strings.NewReader("opaque-body"))
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 204 || w.Header().Get("ETag") != method {
				t.Fatalf("method was blocked/changed: status=%d method=%q body=%q", w.Code, w.Header().Get("ETag"), w.Body.String())
			}
		})
	}
}

func TestProviderRelayArbitraryPreflightMethods(t *testing.T) {
	h, _, id := relayTestHandler(t, func(r *http.Request) (*http.Response, error) {
		t.Fatal("CORS preflight reached the provider")
		return nil, nil
	})
	for _, method := range []string{"PUT", "PATCH", "DELETE", "OPTIONS", "PROPFIND", "vendor.sync", "X!#$%&'*+-.^_`|~09"} {
		t.Run(method, func(t *testing.T) {
			r := httptest.NewRequest("OPTIONS", resourcePath+"?u="+url.QueryEscape("https://provider.test/widget/api")+"&sid="+id, nil)
			r.Header.Set("Origin", "null")
			r.Header.Set("Access-Control-Request-Method", method)
			r.Header.Set("Access-Control-Request-Headers", "content-type")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 204 || w.Header().Get("Access-Control-Allow-Methods") != method {
				t.Fatalf("preflight changed method: status=%d headers=%v", w.Code, w.Header())
			}
		})
	}
	for _, value := range []string{"", "PATCH, DELETE", "BAD METHOD", "MÉTHODE", "METHOD\r\nInjected: yes"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			r := httptest.NewRequest("OPTIONS", resourcePath+"?u="+url.QueryEscape("https://provider.test/widget/api")+"&sid="+id, nil)
			r.Header.Set("Origin", "null")
			r.Header.Set("Access-Control-Request-Method", value)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 400 || w.Header().Get("Access-Control-Allow-Methods") != "" {
				t.Fatalf("invalid method accepted/reflected: status=%d headers=%v", w.Code, w.Header())
			}
		})
	}
}

func TestProviderRelayCustomMethodRequiresSession(t *testing.T) {
	h, q, id := relayTestHandler(t, func(r *http.Request) (*http.Response, error) {
		t.Fatal("unauthorised request reached provider")
		return nil, nil
	})
	q.Cancel(id)
	for _, session := range []string{"", id} {
		for _, method := range []string{"PUT", "PATCH", "DELETE", "OPTIONS", "PURGE", "vendor.sync"} {
			got := relayTestRequest(h, session, method, "https://provider.test/widget/api", "body")
			if got.Code != 403 {
				t.Errorf("method=%s session=%q: status=%d", method, session, got.Code)
			}
		}
	}
}
