package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/Splinters-io/blinder/internal/har"
)

func TestWebSocketReviewRestoresMappedPathAndQuery(t *testing.T) {
	received := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.URL.RequestURI()
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "fixture refusal")
	}))
	defer upstream.Close()
	s := mappingReviewServer(t, upstream.URL, []string{"AcmeCorp"}, nil)
	defer s.transport.(*http.Transport).CloseIdleConnections()
	defer s.captchaQueue.Shutdown()
	alias := s.gate.Scrub("AcmeCorp", "fixture")
	target := "https://127.0.0.1:18099/socket/" + url.PathEscape(alias) + "?first=one%20two&tenant=" + url.QueryEscape(alias) + "&first=second"
	r := httptest.NewRequest("GET", target, nil)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	r.Header.Set("Sec-WebSocket-Version", "13")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("fixture refusal failed: %d %s", w.Code, w.Body.String())
	}
	if got, want := <-received, "/socket/AcmeCorp?first=one%20two&tenant=AcmeCorp&first=second"; got != want {
		t.Fatalf("WS upgrade bypasses normal reversible URL restoration:\n got %q\nwant %q", got, want)
	}
}

func TestWebSocketReviewFailedReadKeepsStatusLineEvidence(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(rw, "HTTP/1.0 503 Fixture maintenance\r\nContent-Type: text/plain\r\nContent-Length: 99\r\n\r\npartial")
		rw.Flush()
	}))
	defer upstream.Close()
	srv, addr := startTestProxy(t, newTestConfig(t, upstream.URL))
	path := filepath.Join(t.TempDir(), "evidence.har")
	srv.harWriter = har.NewWriter(path, 4096, 100)
	conn, _, response := evidenceUpgrade(t, addr)
	defer conn.Close()
	io.ReadAll(response.Body)
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("partial upstream response should produce downstream 502: %d", response.StatusCode)
	}
	waitWSManifest(t, srv)
	entries := fidelityHAR(t, srv, path).Log.Entries
	if len(entries) != 1 {
		t.Fatalf("unexpected capture count: %d", len(entries))
	}
	got := entries[0].Response
	if got.Status != 503 || got.HTTPVersion != "HTTP/1.0" || got.StatusText != "Fixture maintenance" || got.Content.Text != "partial" {
		t.Fatalf("failed-read HAR substitutes the upstream status line: %+v", got)
	}
}
