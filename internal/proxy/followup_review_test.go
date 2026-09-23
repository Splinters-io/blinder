package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type followupBrokenBody struct{ sent bool }

func (b *followupBrokenBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, []byte("operation=partial")), nil
	}
	return 0, errors.New("synthetic request stream failure")
}
func (*followupBrokenBody) Close() error { return nil }

type followupTransport func(*http.Request) (*http.Response, error)

func (f followupTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFollowupRequestReadErrorStopsForwarding(t *testing.T) {
	srv, err := New(newTestConfig(t, "https://acmecorp.io"))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	srv.transport = followupTransport(func(r *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	req := httptest.NewRequest("POST", "/action", nil)
	req.Body = &followupBrokenBody{}
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if called {
		t.Fatalf("partially read request was sent upstream; client status=%d", rec.Code)
	}
	if rec.Code < 400 {
		t.Fatalf("expected request-read failure, got status=%d", rec.Code)
	}
}
