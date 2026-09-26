package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyArbitraryMethodsPreserveRequest(t *testing.T) {
	for _, method := range []string{"PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "PROPFIND", "MKCOL", "PURGE", "vendor.sync", "X!#$%&'*+-.^_`|~09"} {
		t.Run(method, func(t *testing.T) {
			calls := 0
			s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
				calls++
				body, _ := io.ReadAll(r.Body)
				if r.Method != method || string(body) != "opaque-body" || r.URL.RequestURI() != "/resource?keep=one&keep=two" {
					t.Errorf("request changed: method=%q url=%q body=%q", r.Method, r.URL.RequestURI(), body)
				}
				return audit267SRIResponse("text/plain", "accepted"), nil
			})
			r := httptest.NewRequest(method, "https://127.0.0.1:18099/resource?keep=one&keep=two", strings.NewReader("opaque-body"))
			r.Header.Set("Content-Type", "application/octet-stream")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 200 || calls != 1 {
				t.Fatalf("method not forwarded: status=%d calls=%d body=%q", w.Code, calls, w.Body.String())
			}
		})
	}
}

func TestProxyCustomMutationInvalidatesCachedGET(t *testing.T) {
	for _, method := range []string{"PURGE", "vendor.sync", "get"} {
		t.Run(method, func(t *testing.T) {
			state := "before"
			reads := 0
			s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
				if r.Method == method {
					state = "after"
					return audit267SRIResponse("text/plain", "changed"), nil
				}
				reads++
				return audit267CacheResponse(state), nil
			})
			audit267CacheRequest(s, "GET", "/resource", nil)
			audit267CacheRequest(s, "GET", "/resource", nil)
			if reads != 1 {
				t.Fatal("fixture did not populate cache")
			}
			audit267CacheRequest(s, method, "/resource", nil)
			got := audit267CacheRequest(s, "GET", "/resource", nil)
			if got.Body.String() != "after" || reads != 2 {
				t.Fatalf("custom mutation left stale GET: body=%q reads=%d", got.Body.String(), reads)
			}
		})
	}
}
