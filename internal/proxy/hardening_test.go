package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/config"
)

func TestResponseReadFailsClosed(t *testing.T) {
	for _, encoding := range []string{"br", "deflate", "gzip, br"} {
		t.Run(encoding, func(t *testing.T) {
			srv := &Server{}
			resp := &http.Response{Header: http.Header{"Content-Encoding": []string{encoding}}, Body: io.NopCloser(strings.NewReader("sensitive compressed bytes"))}
			if _, err := srv.readResponseBody(resp); err == nil {
				t.Fatalf("accepted unsupported encoding %q", encoding)
			}
		})
	}
	resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(io.LimitReader(zeroReviewReader{}, maxResponseBody+1))}
	if _, err := (&Server{}).readResponseBody(resp); err == nil {
		t.Fatal("silently accepted truncated oversized response")
	}
}

func TestGzipResponseScrubbed(t *testing.T) {
	var encoded bytes.Buffer
	gz := gzip.NewWriter(&encoded)
	io.WriteString(gz, "hello")
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{Header: http.Header{"Content-Encoding": []string{" GZip "}}, Body: io.NopCloser(&encoded)}
	body, err := (&Server{}).readResponseBody(resp)
	if err != nil || string(body) != "hello" {
		t.Fatalf("body=%q err=%v", body, err)
	}
}

func TestMetadataScrubsBeforeJSONEscaping(t *testing.T) {
	cfg := newTestConfig(t, "https://acmecorp.io")
	cfg.IdentityTokens = []string{"<Internal>"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.transport = followupTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/pdf"}}, Body: io.NopCloser(strings.NewReader("%PDF-1.7\n/Producer (<Internal>)\n%%EOF"))}, nil
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/doc.pdf", nil))
	if strings.Contains(rec.Header().Get("X-Blinder-Meta"), "Internal") {
		t.Fatalf("metadata leaks escaped identity: %s", rec.Header().Get("X-Blinder-Meta"))
	}
}

func TestUnsupportedResponseEncodingReturnsGenericError(t *testing.T) {
	srv, err := New(newTestConfig(t, "https://acmecorp.io"))
	if err != nil {
		t.Fatal(err)
	}
	srv.transport = followupTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}, "Content-Encoding": []string{"br"}}, Body: io.NopCloser(strings.NewReader("AcmeCorp"))}, nil
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "AcmeCorp") {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestTargetValidationRejectsHostlessURL(t *testing.T) {
	if _, err := config.New("https:///path", "127.0.0.1:0", "alias.local", nil, true, false, false, "", "", 0, "", "", 0, 0); err == nil {
		t.Fatal("accepted target without a hostname")
	}
}

func TestUpstreamTimeoutCoversResponseBody(t *testing.T) {
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	defer target.Close()
	cfg := newTestConfig(t, target.URL)
	cfg.UpstreamTimeout = 1
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	started := time.Now()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/slow", nil))
	if rec.Code != http.StatusBadGateway || time.Since(started) > 3*time.Second {
		t.Fatalf("status=%d elapsed=%s", rec.Code, time.Since(started))
	}
}
