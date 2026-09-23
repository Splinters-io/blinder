package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/har"
)

func TestReviewPDFProducerIsScrubbed(t *testing.T) {
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		io.WriteString(w, "%PDF-1.7\n/Producer (AcmeCorp https://acmecorp.io)\n%%EOF")
	})
	defer target.Close()
	srv, err := New(newTestConfig(t, target.URL))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/doc.pdf", nil))
	got := rec.Header().Get("X-Blinder-Meta")
	if strings.Contains(got, "AcmeCorp") || strings.Contains(got, "acmecorp.io") {
		t.Fatalf("metadata header leaks: %s", got)
	}
}

func TestReviewCookieRoundTrip(t *testing.T) {
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "abc123", Path: "/"})
			return
		}
		cookie, err := r.Cookie("session_id")
		if err != nil || cookie.Value != "abc123" {
			http.Error(w, "unauthenticated", 401)
			return
		}
		fmt.Fprint(w, "authenticated")
	})
	defer target.Close()
	srv, err := New(newTestConfig(t, target.URL))
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	srv.ServeHTTP(login, httptest.NewRequest("GET", "/login", nil))
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies: %v", cookies)
	}
	req := httptest.NewRequest("GET", "/private", nil)
	req.AddCookie(cookies[0])
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("upstream rejects round-trip cookie %q: status %d", cookies[0].Name, rec.Code)
	}
}

func TestReviewHARCapturesUpstreamPOST(t *testing.T) {
	var received string
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	})
	defer target.Close()
	cfg := newTestConfig(t, target.URL)
	cfg.HAR = &config.HARConfig{FilePath: filepath.Join(t.TempDir(), "evidence.har"), MaxBodySize: 1024}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/submit?q=1", strings.NewReader("x=secret"))
	req.Host = "alias.local"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 || received != "x=secret" {
		t.Fatalf("upstream request failed: %d %q", rec.Code, received)
	}
	if err := srv.FlushHAR(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cfg.HAR.FilePath)
	if err != nil {
		t.Fatal(err)
	}
	var file har.HARFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	entry := file.Log.Entries[0]
	if entry.Request.URL != target.URL+"/submit?q=1" {
		t.Errorf("HAR URL %q, want actual upstream URL %q", entry.Request.URL, target.URL+"/submit?q=1")
	}
	if entry.Request.PostData == nil || entry.Request.PostData.Text != "x=secret" {
		t.Errorf("HAR POST body lost: %+v", entry.Request.PostData)
	}
}

func TestReviewUnknownLengthUploadIsCapped(t *testing.T) {
	var received int64
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, "ok")
	})
	defer target.Close()
	srv, err := New(newTestConfig(t, target.URL))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/upload", io.LimitReader(zeroReviewReader{}, maxRequestBody+1))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if received > maxRequestBody {
		t.Fatalf("forwarded %d bytes despite %d-byte cap; returned %d", received, maxRequestBody, rec.Code)
	}
}

type zeroReviewReader struct{}

func (zeroReviewReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
