package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCORSNegativeSurvivesCacheAndRevalidation(t *testing.T) {
	for _, stale := range []bool{false, true} {
		name, policy := "fresh", "max-age=600"
		if stale {
			name, policy = "revalidated", "max-age=0"
		}
		t.Run(name, func(t *testing.T) {
			calls := 0
			s := codexSRIServer(t, func(r *http.Request) (*http.Response, error) {
				calls++
				h := http.Header{"Cache-Control": {policy}, "Access-Control-Allow-Origin": {"https://main.example/"}, "Etag": {`"source-v1"`}, "Content-Type": {"text/plain"}}
				if calls > 1 {
					return &http.Response{StatusCode: 304, Status: "304 Not Modified", Header: h, Body: http.NoBody}, nil
				}
				return &http.Response{StatusCode: 200, Status: "200 OK", Header: h, Body: io.NopCloser(strings.NewReader("fixture"))}, nil
			})
			var etag string
			for i, origin := range []string{"https://127.0.0.1:18099", "https://localhost:18099"} {
				r := httptest.NewRequest("GET", "https://alias.local:18099/data", nil)
				r.Header.Set("Origin", origin)
				if i > 0 {
					r.Header.Set("If-None-Match", etag)
				}
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				wantStatus := 200
				if i > 0 {
					wantStatus = 304
				}
				if w.Code != wantStatus {
					t.Fatalf("response%d: status=%d body=%q", i, w.Code, w.Body.String())
				}
				acao := w.Header().Get("Access-Control-Allow-Origin")
				if !strings.HasSuffix(acao, "/") || acao == origin {
					t.Fatalf("response%d repaired invalid CORS permission: %q", i, acao)
				}
				etag = w.Header().Get("Etag")
				if etag == "" {
					t.Fatal("downstream validator missing")
				}
			}
			wantCalls := 1
			if stale {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("did not exercise intended cache path: calls=%d want=%d", calls, wantCalls)
			}
		})
	}
}
