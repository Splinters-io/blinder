package proxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/sri"
)

func TestSRIPrefetchHARGzipSizesAndRefusalBody(t *testing.T) {
	const body = `console.log("fixture diagnostic fixture diagnostic fixture diagnostic");`
	for _, status := range []int{200, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var wire bytes.Buffer
			gz := gzip.NewWriter(&wire)
			_, _ = gz.Write([]byte(body))
			_ = gz.Close()
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/page" {
					w.Header().Set("Content-Type", "text/html")
					_, _ = fmt.Fprintf(w, `<script src="/asset.js" integrity="%s"></script>`, sri.ComputeIntegrity([]byte(body), "sha384"))
					return
				}
				w.Header().Set("Content-Type", "application/javascript")
				w.Header().Set("Content-Encoding", "gzip")
				w.WriteHeader(status)
				_, _ = w.Write(wire.Bytes())
			}))
			defer target.Close()
			path := filepath.Join(t.TempDir(), "gzip-sri.har")
			cfg := newTestConfig(t, target.URL)
			cfg.HAR = &config.HARConfig{FilePath: path, MaxBodySize: 4096}
			srv, _ := startTestProxy(t, cfg)
			srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "https://127.0.0.1:8099/page", nil))
			found := 0
			for _, entry := range fidelityHAR(t, srv, path).Log.Entries {
				if entry.Request.URL != target.URL+"/asset.js" {
					continue
				}
				found++
				response := entry.Response
				if response.Status != status || response.BodySize != wire.Len() || response.Content.Size != len(body) || response.Content.Text != body || (status != 200) != (response.Content.Comment != "") {
					t.Fatalf("SRI HAR sizes/body do not describe received representation: %+v", response)
				}
			}
			if found != 1 {
				t.Fatalf("SRI record count=%d", found)
			}
		})
	}
}

func TestHTTPFailedReadPreservesUpstreamStatusLine(t *testing.T) {
	for _, tc := range []struct {
		name, statusLine, reason string
		status                   int
	}{
		{"custom-reason", "503 Fixture maintenance", "Fixture maintenance", 503},
		{"nonstandard-status", "599 Fixture dependency failure", "Fixture dependency failure", 599},
		{"empty-reason", "503 ", "", 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const partial = "AcmeCorp partial diagnostic"
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = fmt.Fprintf(rw, "HTTP/1.0 %s\r\nContent-Type: text/plain\r\nContent-Length: 999\r\nX-Diagnostic: original-value\r\n\r\n%s", tc.statusLine, partial)
				_ = rw.Flush()
			}))
			defer target.Close()
			path := filepath.Join(t.TempDir(), "failure.har")
			cfg := newTestConfig(t, target.URL)
			cfg.HAR = &config.HARConfig{FilePath: path, MaxBodySize: 4096}
			srv, _ := startTestProxy(t, cfg)
			req := httptest.NewRequest("POST", "https://127.0.0.1:8099/error", strings.NewReader("input=value"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			got := httptest.NewRecorder()
			srv.ServeHTTP(got, req)
			if got.Code != 502 || strings.Contains(got.Body.String(), "AcmeCorp") {
				t.Fatalf("incorrect client failure: %d %s", got.Code, got.Body.String())
			}
			entries := fidelityHAR(t, srv, path).Log.Entries
			if len(entries) != 1 {
				t.Fatalf("capture count=%d", len(entries))
			}
			e := entries[0]
			if e.Response.Status != tc.status || e.Response.HTTPVersion != "HTTP/1.0" || e.Response.StatusText != tc.reason || e.Response.Content.Text != partial || e.Response.BodySize != len(partial) || e.Response.Content.Comment == "" {
				t.Fatalf("upstream failure facts replaced: %+v", e.Response)
			}
			if e.Request.PostData == nil || e.Request.PostData.Text != "input=value" {
				t.Fatalf("request evidence lost: %+v", e.Request)
			}
		})
	}
}

func TestSRIOnFetchPreservesActualProtocolAndStatusLine(t *testing.T) {
	const asset = `console.log("fixture");`
	for _, tc := range []struct {
		name, statusLine, body, encoding, reason string
		status, advertisedLength                 int
		failure                                  bool
	}{
		{name: "success", statusLine: "200 Fixture ready", status: 200, body: asset, advertisedLength: len(asset), reason: "Fixture ready"},
		{name: "status-refusal", statusLine: "503 Fixture unavailable", status: 503, body: "unavailable", advertisedLength: len("unavailable"), reason: "Fixture unavailable", failure: true},
		{name: "partial-read", statusLine: "200 Fixture interrupted", status: 200, body: "partial", advertisedLength: 999, reason: "Fixture interrupted", failure: true},
		{name: "bad-gzip", statusLine: "200 Fixture encoding", status: 200, body: "invalid", advertisedLength: len("invalid"), encoding: "gzip", reason: "Fixture encoding", failure: true},
		{name: "transport", status: 0, failure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			integrity := sri.ComputeIntegrity([]byte(asset), "sha384")
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/page" {
					w.Header().Set("Content-Type", "text/html")
					_, _ = fmt.Fprintf(w, `<script src="/asset.js" integrity="%s"></script>`, integrity)
					return
				}
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				if tc.name == "transport" {
					return
				}
				_, _ = fmt.Fprintf(rw, "HTTP/1.0 %s\r\nContent-Type: application/javascript\r\nContent-Length: %d\r\nX-Resource-Diagnostic: original\r\n", tc.statusLine, tc.advertisedLength)
				if tc.encoding != "" {
					_, _ = fmt.Fprintf(rw, "Content-Encoding: %s\r\n", tc.encoding)
				}
				_, _ = fmt.Fprintf(rw, "\r\n%s", tc.body)
				_ = rw.Flush()
			}))
			defer target.Close()
			path := filepath.Join(t.TempDir(), "sri.har")
			cfg := newTestConfig(t, target.URL)
			cfg.HAR = &config.HARConfig{FilePath: path, MaxBodySize: 4096}
			srv, _ := startTestProxy(t, cfg)
			got := httptest.NewRecorder()
			srv.ServeHTTP(got, httptest.NewRequest("GET", "https://127.0.0.1:8099/page", nil))
			if got.Code != 200 {
				t.Fatalf("document status=%d", got.Code)
			}
			entries := fidelityHAR(t, srv, path).Log.Entries
			found := 0
			for _, entry := range entries {
				if entry.Request.URL != target.URL+"/asset.js" {
					continue
				}
				found++
				response := entry.Response
				protocol := "HTTP/1.0"
				if tc.name == "transport" {
					protocol = ""
				}
				if response.Status != tc.status || response.HTTPVersion != protocol || response.StatusText != tc.reason {
					t.Fatalf("SRI OnFetch replaced actual status line: %+v", response)
				}
				if tc.failure != (response.Content.Comment != "") {
					t.Fatalf("SRI failure annotation changed: %+v", response)
				}
				if (tc.name == "success" || tc.name == "partial-read") && response.Content.Text != tc.body {
					t.Fatalf("SRI response bytes lost: %+v", response)
				}
				if tc.name == "transport" && (response.Content.Text != "" || len(response.Headers) != 0) {
					t.Fatalf("SRI invented transport response: %+v", response)
				}
			}
			if found != 1 {
				t.Fatalf("expected exactly one SRI fetch record; got %d in %+v", found, entries)
			}
		})
	}
}
