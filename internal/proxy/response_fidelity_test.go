package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Splinters-io/blinder/internal/har"
	"github.com/Splinters-io/blinder/internal/manifest"
	"github.com/Splinters-io/blinder/internal/sri"
)

func lastResponseMetrics(t *testing.T, s *Server) manifest.ResponseMetrics {
	t.Helper()
	entries := s.Manifest().Requests()
	if len(entries) == 0 || entries[len(entries)-1].Response == nil {
		t.Fatal("response measurements missing")
	}
	return *entries[len(entries)-1].Response
}

func fidelityHAR(t *testing.T, s *Server, path string) har.HARFile {
	t.Helper()
	if err := s.FlushHAR(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result har.HARFile
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestResponseFidelityPreservesDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, mime, body, diagnostic string
		status                       int
	}{
		{"html", "text/html", `<h1>AcmeCorp service error</h1><pre>E_TIMEOUT: dependency unavailable; retry in 30 seconds</pre>`, "E_TIMEOUT: dependency unavailable", 503},
		{"html200alert", "text/html", `<p>ordinary content</p><div role="alert">INVALID_INPUT: <strong>AcmeCorp: invalid résumé</strong><br>Try again</div><p>ordinary content</p>`, "INVALID_INPUT:", 200},
		{"html200pre", "text/html", `<pre>E_TIMEOUT: AcmeCorp dependency unavailable</pre>`, "E_TIMEOUT:", 200},
		{"json200", "application/json", `{"error":{"code":"INVALID_INPUT","message":"AcmeCorp: invalid résumé","request_id":900719925474099312345}}`, "INVALID_INPUT", 200},
		{"json422", "application/problem+json", `{"status":422,"detail":"AcmeCorp: invalid résumé","code":"INVALID_INPUT","amount":0.1234567890123456789}`, "INVALID_INPUT", 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := mappingReviewServer(t, "https://main.example", []string{"AcmeCorp"}, func(r *http.Request) (*http.Response, error) {
				resp := audit267SRIResponse(tc.mime, tc.body)
				resp.StatusCode = tc.status
				resp.Header.Set("Retry-After", "30")
				return resp, nil
			})
			s.cfg.Paranoid = true
			got := audit267CacheRequest(s, "GET", "/error", nil)
			if got.Code != tc.status || !strings.Contains(got.Body.String(), tc.diagnostic) || strings.Contains(got.Body.String(), "AcmeCorp") || !utf8.Valid(got.Body.Bytes()) {
				t.Fatalf("diagnostic changed/lost: status=%d body=%s", got.Code, got.Body.String())
			}
			if got.Header().Get("Retry-After") != "30" || got.Header().Get("X-Blinder-View") != "redacted" {
				t.Fatal("missing diagnostic metadata or explicit redaction label")
			}
			if tc.name == "html200alert" && strings.Contains(got.Body.String(), "ordinary content") {
				t.Fatal("diagnostic preservation escaped its marked region")
			}
			if strings.Contains(tc.name, "json") {
				var parsed any
				if json.Unmarshal(got.Body.Bytes(), &parsed) != nil {
					t.Fatal("invalid JSON")
				}
				for _, number := range []string{"900719925474099312345", "0.1234567890123456789"} {
					if strings.Contains(tc.body, number) && !strings.Contains(got.Body.String(), number) {
						t.Fatal("diagnostic number precision lost")
					}
				}
			}
			m := lastResponseMetrics(t, s)
			if m.OriginalBodyBytes != int64(len(tc.body)) || m.RewrittenBodyBytes != int64(got.Body.Len()) || m.DownstreamBytes != int64(got.Body.Len()) || m.RewriteDeltaBytes == nil || *m.RewriteDeltaBytes != int64(got.Body.Len()-len(tc.body)) {
				t.Fatalf("incorrect sizes: %+v", m)
			}
		})
	}
}

func TestResponseFidelityMeasuresCompressedAndChunkedBytes(t *testing.T) {
	const original = `{"message":"AcmeCorp café 日本語","code":"INVALID_INPUT"}`
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprint(compressed), func(t *testing.T) {
			encoded := []byte(original)
			if compressed {
				var buf bytes.Buffer
				gz := gzip.NewWriter(&buf)
				gz.Write(encoded)
				gz.Close()
				encoded = buf.Bytes()
			}
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Accept-Encoding") != "gzip, identity" {
					t.Error("automatic decompression can hide original bytes")
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Blinder-Original-Body-Bytes", "999999")
				if compressed {
					w.Header().Set("Content-Encoding", "gzip")
				}
				w.WriteHeader(422)
				w.(http.Flusher).Flush()
				w.Write(encoded[:len(encoded)/2])
				w.(http.Flusher).Flush()
				w.Write(encoded[len(encoded)/2:])
			}))
			defer target.Close()
			s := mappingReviewServer(t, target.URL, []string{"AcmeCorp"}, nil)
			defer s.transport.(*http.Transport).CloseIdleConnections()
			path := filepath.Join(t.TempDir(), "capture.har")
			s.harWriter = har.NewWriter(path, 1024, 100)
			got := audit267CacheRequest(s, "GET", "/error", nil)
			m := lastResponseMetrics(t, s)
			if got.Code != 422 || len(m.Upstream) != 1 {
				t.Fatalf("missing upstream response: %+v", m)
			}
			u := m.Upstream[0]
			if u.EncodedBytes != int64(len(encoded)) || u.DecodedBytes != int64(len(original)) || !u.Complete {
				t.Fatalf("wrong measured bytes: %+v", u)
			}
			if got.Header().Get("Content-Length") != strconv.Itoa(got.Body.Len()) || got.Header().Get("Content-Encoding") != "" || got.Header().Get("X-Blinder-Original-Body-Bytes") != strconv.Itoa(len(original)) {
				t.Fatalf("incorrect downstream headers: %v", got.Header())
			}
			evidence := fidelityHAR(t, s, path).Log.Entries[0]
			if evidence.Response.BodySize != len(encoded) || evidence.Response.Content.Size != len(original) || evidence.Response.Content.Text != original {
				t.Fatalf("HAR confused encoded/decoded sizes: %+v", evidence.Response)
			}
		})
	}
}

func TestResponseFidelityCacheHeadAndConditionalSizes(t *testing.T) {
	const original = "AcmeCorp café"
	calls := 0
	s := mappingReviewServer(t, "https://main.example", []string{"AcmeCorp"}, func(r *http.Request) (*http.Response, error) { calls++; return audit267CacheResponse(original), nil })
	first := audit267CacheRequest(s, "GET", "/cached", nil)
	for _, tc := range []struct {
		method      string
		conditional bool
	}{{"GET", false}, {"HEAD", false}, {"GET", true}, {"HEAD", true}} {
		header := http.Header{}
		if tc.conditional {
			header.Set("If-None-Match", first.Header().Get("ETag"))
		}
		got := audit267CacheRequest(s, tc.method, "/cached", header)
		m := lastResponseMetrics(t, s)
		if m.Source != "cache" || len(m.Upstream) != 0 || m.OriginalBodyBytes != int64(len(original)) || m.RewrittenBodyBytes != int64(first.Body.Len()) || m.DownstreamBytes != int64(got.Body.Len()) {
			t.Fatalf("cache measurements wrong: %+v", m)
		}
		if (tc.method == "HEAD" || tc.conditional) && got.Body.Len() != 0 {
			t.Fatal("body emitted for HEAD/304")
		}
	}
	if calls != 1 {
		t.Fatalf("cache unexpectedly fetched: %d", calls)
	}
}

func TestResponseFidelityUncachedHEADDoesNotInventRepresentation(t *testing.T) {
	s := mappingReviewEphemeralServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
		resp := audit267SRIResponse("text/html", "")
		resp.Header.Set("Content-Encoding", "gzip")
		resp.Header.Set("Content-Length", "9876")
		return resp, nil
	})
	got := audit267CacheRequest(s, "HEAD", "/unknown", nil)
	m := lastResponseMetrics(t, s)
	if got.Code != 200 || got.Body.Len() != 0 || got.Header().Get("Content-Length") != "" || got.Header().Get("ETag") != "" {
		t.Fatalf("invented HEAD representation: status=%d headers=%v", got.Code, got.Header())
	}
	if m.OriginalBodyBytes != -1 || m.RewrittenBodyBytes != -1 || m.DownstreamBytes != 0 || m.RewriteDeltaBytes != nil || len(m.Upstream) != 1 || m.Upstream[0].EncodedBytes != 0 || !m.Upstream[0].Complete {
		t.Fatalf("unknown HEAD length not explicit: %+v", m)
	}
	server := httptest.NewServer(s)
	defer server.Close()
	response, err := server.Client().Head(server.URL + "/unknown")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.Header.Get("Content-Length") != "" || response.Header.Get("ETag") != "" {
		t.Fatalf("HTTP server invented HEAD representation metadata: %v", response.Header)
	}
}

type fidelityReadFailure struct{}

func (fidelityReadFailure) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestResponseFidelityFailureEvidence(t *testing.T) {
	for _, transportFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(transportFailure), func(t *testing.T) {
			const partial = "partial AcmeCorp diagnostic"
			s := mappingReviewServer(t, "https://main.example", []string{"AcmeCorp"}, func(r *http.Request) (*http.Response, error) {
				if transportFailure {
					return nil, fmt.Errorf("fixture dial failure for main.example")
				}
				resp := audit267SRIResponse("text/plain", "")
				resp.StatusCode = 503
				resp.Header.Set("Retry-After", "15")
				resp.Body = io.NopCloser(io.MultiReader(strings.NewReader(partial), fidelityReadFailure{}))
				return resp, nil
			})
			path := filepath.Join(t.TempDir(), "capture.har")
			s.harWriter = har.NewWriter(path, 1024, 100)
			r := httptest.NewRequest("POST", "https://127.0.0.1:18099/error", strings.NewReader("input=value"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			got := httptest.NewRecorder()
			s.ServeHTTP(got, r)
			m := lastResponseMetrics(t, s)
			if got.Code != 502 || m.Source != "proxy" || m.OriginalBodyBytes != -1 || m.RewriteDeltaBytes != nil || m.DownstreamBytes != int64(got.Body.Len()) || strings.Contains(got.Body.String(), "AcmeCorp") {
				t.Fatalf("proxy failure confused with upstream: %+v", m)
			}
			e := fidelityHAR(t, s, path).Log.Entries[0]
			if e.Request.PostData == nil || e.Request.PostData.Text != "input=value" || e.Response.Content.Comment == "" || len(m.Upstream) != 1 || m.Upstream[0].Complete {
				t.Fatalf("lost failed transaction evidence: %+v %+v", e, m)
			}
			if transportFailure {
				if e.Response.Status != 0 || e.Response.Content.Text != "" || m.Upstream[0].StatusCode != 0 {
					t.Fatal("invented upstream status or body")
				}
			} else if e.Response.Status != 503 || e.Response.Content.Text != partial || m.Upstream[0].DecodedBytes != int64(len(partial)) || m.Upstream[0].EncodedBytes != int64(len(partial)) {
				t.Fatalf("partial bytes/status lost: %+v %+v", e.Response, m)
			}
		})
	}
}

func TestResponseFidelitySRIAndUnknownTransportSizes(t *testing.T) {
	s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) { t.Fatal("cached SRI fetched upstream"); return nil, nil })
	s.sriCache.Put("https://main.example/script", &sri.CacheEntry{ScrubbedBody: []byte("modified"), ContentType: "text/javascript", OriginalBodyBytes: 12, OriginalBodyKnown: true})
	got := audit267CacheRequest(s, "GET", "/script", nil)
	m := lastResponseMetrics(t, s)
	if got.Code != 200 || m.Source != "sri-cache" || len(m.Upstream) != 0 || m.OriginalBodyBytes != 12 || m.DownstreamBytes != 8 {
		t.Fatalf("SRI sizes missing: %+v", m)
	}
	resp := audit267SRIResponse("text/plain", "decoded")
	resp.Uncompressed = true
	_, read, err := readMeasuredResponse(resp, "GET")
	if err != nil || read.EncodedBytes != -1 || read.DecodedBytes != 7 || !read.Complete {
		t.Fatalf("invented encoded length after transport decompression: %+v", read)
	}
}

func TestResponseFidelityRevalidationKeepsRepresentationSizes(t *testing.T) {
	const original = "AcmeCorp original representation"
	calls := 0
	s := mappingReviewServer(t, "https://main.example", []string{"AcmeCorp"}, func(r *http.Request) (*http.Response, error) {
		calls++
		resp := audit267CacheResponse(original)
		resp.Header.Set("Cache-Control", "max-age=0")
		resp.Header.Set("ETag", `"origin"`)
		if calls > 1 {
			resp.StatusCode = 304
			resp.Body = io.NopCloser(strings.NewReader(""))
		}
		return resp, nil
	})
	first := audit267CacheRequest(s, "GET", "/stale", nil)
	for _, conditional := range []bool{false, true} {
		h := http.Header{}
		if conditional {
			h.Set("If-None-Match", first.Header().Get("ETag"))
		}
		got := audit267CacheRequest(s, "GET", "/stale", h)
		m := lastResponseMetrics(t, s)
		if m.Source != "cache" || m.OriginalBodyBytes != int64(len(original)) || m.RewrittenBodyBytes != int64(first.Body.Len()) || m.DownstreamBytes != int64(got.Body.Len()) || len(m.Upstream) != 1 || m.Upstream[0].StatusCode != 304 || m.Upstream[0].EncodedBytes != 0 || !m.Upstream[0].Complete {
			t.Fatalf("304 size provenance lost: %+v", m)
		}
	}
}

func TestResponseFidelityCacheRevalidationHARInterop(t *testing.T) {
	const original = "AcmeCorp cached representation for HAR"
	calls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "max-age=0")
		w.Header().Set("ETag", `"fixture-etag"`)
		if calls > 1 && r.Header.Get("If-None-Match") == `"fixture-etag"` {
			w.WriteHeader(304)
			return
		}
		io.WriteString(w, original)
	}))
	defer target.Close()
	path := filepath.Join(t.TempDir(), "revalidation.har")
	s := mappingReviewServer(t, target.URL, []string{"AcmeCorp"}, nil)
	defer s.transport.(*http.Transport).CloseIdleConnections()
	s.harWriter = har.NewWriter(path, 4096, 100)

	first := audit267CacheRequest(s, "GET", "/cached", nil)
	if first.Code != 200 {
		t.Fatalf("initial fetch: %d", first.Code)
	}

	revalidated := audit267CacheRequest(s, "GET", "/cached", nil)
	if revalidated.Code != 200 {
		t.Fatalf("revalidated fetch: %d", revalidated.Code)
	}
	if calls != 2 {
		t.Fatalf("expected exactly 2 upstream calls, got %d", calls)
	}

	entries := fidelityHAR(t, s, path).Log.Entries
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 HAR entries, got %d", len(entries))
	}

	initialEntry := entries[0]
	if initialEntry.Response.Status != 200 || initialEntry.Response.Content.Size != len(original) {
		t.Fatalf("initial HAR entry should show 200 with full body: %+v", initialEntry.Response)
	}

	revalEntry := entries[1]
	if revalEntry.Response.Status != 304 {
		t.Fatalf("revalidation HAR entry should show upstream 304, got %d", revalEntry.Response.Status)
	}
}

func TestResponseFidelityTwoOriginRouting(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Access-Control-Allow-Origin", "https://primary.example.com")
		io.WriteString(w, `<html><body>Primary AcmeCorp content</body></html>`)
	}))
	defer primary.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "https://api.example.com")
		io.WriteString(w, `{"name":"AcmeCorp","endpoint":"api"}`)
	}))
	defer api.Close()

	s := mappingReviewServer(t, primary.URL, []string{"AcmeCorp"}, nil, api.URL)
	defer s.transport.(*http.Transport).CloseIdleConnections()

	primaryGot := audit267CacheRequest(s, "GET", "/page", nil)
	if primaryGot.Code != 200 {
		t.Fatalf("primary origin: %d", primaryGot.Code)
	}
	if strings.Contains(primaryGot.Body.String(), "AcmeCorp") {
		t.Error("primary response should scrub AcmeCorp")
	}

	aliases := s.origins.RouteAliases()
	if len(aliases) < 2 {
		t.Fatalf("expected at least 2 route aliases, got %d", len(aliases))
	}

	m := lastResponseMetrics(t, s)
	if m.Source != "upstream" || m.OriginalBodyBytes <= 0 {
		t.Fatalf("primary metrics missing: %+v", m)
	}
}

func TestResponseFidelityBodylessStatusDoesNotCreateJSONNull(t *testing.T) {
	for _, status := range []int{204, 304} {
		s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
			resp := audit267SRIResponse("application/json", "")
			resp.StatusCode = status
			return resp, nil
		})
		got := audit267CacheRequest(s, "GET", "/bodyless", nil)
		m := lastResponseMetrics(t, s)
		if got.Code != status || got.Body.Len() != 0 || m.DownstreamBytes != 0 || got.Header().Get("Content-Length") != "" || got.Header().Get("ETag") != "" {
			t.Fatalf("body invented for %d: body=%q headers=%v metrics=%+v", status, got.Body.String(), got.Header(), m)
		}
	}
}
