package proxy

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/manifest"
)

func deltaCaptureSHA(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func TestDeltaCaptureRequestTagsSeparateInputsAndContexts(t *testing.T) {
	s := mappingReviewServer(t, "https://main.example", nil, nil)
	upstream, _ := url.Parse("https://main.example")
	base := func() *http.Request {
		r := httptest.NewRequest("POST", "https://127.0.0.1:18099/result?value=one", strings.NewReader("input=one"))
		r.Header["Cookie"] = []string{"session=private-one", "other=private-two"}
		r.Header["Authorization"] = []string{"Bearer private-three", "Bearer private-four"}
		r.Header.Set("X-Mode", "first")
		return r
	}
	capture := func(r *http.Request, target *url.URL, body string) manifest.RequestEntry {
		e := newRequestEvidence(s.manifest, s.gate, r)
		e.observeContext(s.gate, r, target)
		e.observeBody(s.gate, []byte(body))
		return e.entry
	}
	first := capture(base(), upstream, "input=one")
	repeat := capture(base(), upstream, "input=one")
	if first.RequestID == repeat.RequestID || first.RequestTag != repeat.RequestTag || first.ContextTag != repeat.ContextTag {
		t.Fatal("repeated requests lost stable equality or unique identity")
	}
	for _, tc := range []struct {
		name       string
		mutate     func(*http.Request, *url.URL)
		body       string
		newRequest bool
		newContext bool
	}{
		{"query", func(r *http.Request, _ *url.URL) { r.URL.RawQuery = "value=two" }, "input=one", true, false},
		{"body", func(*http.Request, *url.URL) {}, "input=two", true, false},
		{"header", func(r *http.Request, _ *url.URL) { r.Header.Set("X-Mode", "second") }, "input=one", true, false},
		{"method_case", func(r *http.Request, _ *url.URL) { r.Method = "post" }, "input=one", true, true},
		{"second_cookie", func(r *http.Request, _ *url.URL) { r.Header["Cookie"][1] = "other=changed" }, "input=one", true, true},
		{"second_authorization", func(r *http.Request, _ *url.URL) { r.Header["Authorization"][1] = "Bearer changed" }, "input=one", true, true},
		{"local_authority", func(r *http.Request, _ *url.URL) { r.Host = "alias.local:18099" }, "input=one", true, true},
		{"local_scheme", func(r *http.Request, _ *url.URL) { r.TLS = nil }, "input=one", false, true},
		{"upstream_scheme", func(_ *http.Request, u *url.URL) { u.Scheme = "http" }, "input=one", false, true},
		{"upstream_port", func(_ *http.Request, u *url.URL) { u.Host = "main.example:8443" }, "input=one", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, target := base(), *upstream
			tc.mutate(r, &target)
			got := capture(r, &target, tc.body)
			if (got.RequestTag != first.RequestTag) != tc.newRequest || (got.ContextTag != first.ContextTag) != tc.newContext {
				t.Fatalf("incorrect equality boundaries: %+v", got)
			}
			for _, tag := range []string{got.RequestTag, got.ContextTag} {
				if raw, err := hex.DecodeString(tag); err != nil || len(raw) != sha256.Size || strings.Contains(tag, "private") {
					t.Fatalf("unkeyed/plaintext tag: %q", tag)
				}
			}
		})
	}
}

func TestDeltaCaptureRawBytesAndFieldBoundaries(t *testing.T) {
	s := mappingReviewServer(t, "https://main.example", nil, nil)
	upstream, _ := url.Parse("https://main.example")
	capture := func(r *http.Request) manifest.RequestEntry {
		e := newRequestEvidence(s.manifest, s.gate, r)
		e.observeContext(s.gate, r, upstream)
		e.observeBody(s.gate, nil)
		return e.entry
	}
	for _, tc := range []struct {
		name       string
		mutate     func(a, b *http.Request)
		newContext bool
	}{
		{"invalid_header_bytes", func(a, b *http.Request) {
			a.Header["X-Raw"] = []string{string([]byte{0xff})}
			b.Header["X-Raw"] = []string{string([]byte{0xfe})}
		}, false},
		{"invalid_query_bytes", func(a, b *http.Request) {
			a.URL.RawQuery = "q=" + string([]byte{0xff})
			b.URL.RawQuery = "q=" + string([]byte{0xfe})
		}, false},
		{"duplicate_raw_cookies", func(a, b *http.Request) {
			a.Header["Cookie"] = []string{"session=same", "other=" + string([]byte{0xff})}
			b.Header["Cookie"] = []string{"session=same", "other=" + string([]byte{0xfe})}
		}, true},
		{"nul_between_values", func(a, b *http.Request) {
			a.Header["X-Raw"] = []string{"left\x00middle", "right"}
			b.Header["X-Raw"] = []string{"left", "middle\x00right"}
		}, false},
		{"nul_between_credentials", func(a, b *http.Request) {
			a.Header["Cookie"], a.Header["Authorization"] = []string{"left\x00middle"}, []string{"right"}
			b.Header["Cookie"], b.Header["Authorization"] = []string{"left"}, []string{"middle\x00right"}
		}, true},
		{"value_count", func(a, b *http.Request) {
			a.Header["Cookie"] = []string{"first", "second"}
			b.Header["Cookie"] = []string{"first\x00second"}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Helpers deliberately exercise byte strings beyond HTTP wire-parser
			// validation: evidence framing must not silently normalize them.
			a := httptest.NewRequest("GET", "https://127.0.0.1:18099/", nil)
			b := httptest.NewRequest("GET", "https://127.0.0.1:18099/", nil)
			tc.mutate(a, b)
			first, second := capture(a), capture(b)
			if first.RequestTag == second.RequestTag || (first.ContextTag != second.ContextTag) != tc.newContext {
				t.Fatal("distinct bytes or field boundaries collapsed into the same evidence")
			}
		})
	}
	t.Run("header_insertion_order", func(t *testing.T) {
		a := httptest.NewRequest("GET", "https://127.0.0.1:18099/", nil)
		b := httptest.NewRequest("GET", "https://127.0.0.1:18099/", nil)
		for _, name := range []string{"X-First", "X-Second", "X-Third"} {
			a.Header[name] = []string{name + "-value", "duplicate"}
		}
		for _, name := range []string{"X-Third", "X-Second", "X-First"} {
			b.Header[name] = []string{name + "-value", "duplicate"}
		}
		first := capture(a)
		for range 20 {
			if next := capture(b); first.RequestTag != next.RequestTag || first.ContextTag != next.ContextTag {
				t.Fatal("map insertion or iteration order introduced request variation")
			}
		}
	})
}

func TestDeltaCaptureTagsBeforeFormAndQueryRestoration(t *testing.T) {
	var received []string
	s := mappingReviewServer(t, "https://main.example", []string{"AcmeCorp"}, func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		received = append(received, r.URL.RequestURI()+" "+string(body))
		return audit267SRIResponse("text/plain", "accepted"), nil
	})
	alias := s.gate.Scrub("AcmeCorp", "fixture")
	if alias == "AcmeCorp" {
		t.Fatal("fixture alias unchanged")
	}
	for _, value := range []string{alias, "AcmeCorp"} {
		encoded := url.Values{"name": {value}}.Encode()
		r := httptest.NewRequest("POST", "https://127.0.0.1:18099/submit?"+encoded, strings.NewReader(encoded))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Blinder-Request-ID", "forged-input")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		entries := s.manifest.Requests()
		if w.Code != 200 || w.Header().Get("X-Blinder-Request-ID") != entries[len(entries)-1].RequestID {
			t.Fatal("response did not expose its own captured identity")
		}
	}
	entries := s.manifest.Requests()
	if len(received) != 2 || received[0] != received[1] || !strings.Contains(received[0], "name=AcmeCorp") {
		t.Fatalf("fixture did not restore equivalent upstream requests: %q", received)
	}
	if entries[0].RequestTag == entries[1].RequestTag || entries[0].ContextTag != entries[1].ContextTag {
		t.Fatal("tag captured restored input instead of distinct submitted bytes")
	}
}

func TestDeltaCaptureCompletedBodyHash(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		gzip       bool
	}{{"empty", "", 200, false}, {"gzip_error", "AcmeCorp invalid value", 422, true}, {"error", "AcmeCorp unavailable", 503, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := mappingReviewServer(t, "https://main.example", []string{"AcmeCorp"}, func(r *http.Request) (*http.Response, error) {
				resp := audit267SRIResponse("text/plain", tc.body)
				resp.StatusCode = tc.status
				resp.Header.Set("Cache-Control", "no-store")
				resp.Header.Set("X-Blinder-Request-ID", "forged-upstream")
				if tc.gzip {
					var data bytes.Buffer
					gz := gzip.NewWriter(&data)
					_, _ = io.WriteString(gz, tc.body)
					_ = gz.Close()
					resp.Body = io.NopCloser(&data)
					resp.Header.Set("Content-Encoding", "gzip")
				}
				return resp, nil
			})
			got := audit267CacheRequest(s, "GET", "/result", nil)
			m := lastResponseMetrics(t, s)
			if got.Code != tc.status || !m.BodyComplete || m.Source != "upstream" || m.RewrittenBodyTag != deltaCaptureSHA(got.Body.Bytes()) || m.OriginalBodyTag != s.gate.ContentTag([]byte(tc.body)) || m.DownstreamBytes != int64(got.Body.Len()) {
				t.Fatalf("completed output mismeasured: status=%d metrics=%+v", got.Code, m)
			}
			if got.Header().Get("X-Blinder-Request-ID") != s.manifest.Requests()[0].RequestID || m.Upstream[0].DecodedBytes != int64(len(tc.body)) || !m.Upstream[0].Complete {
				t.Fatal("request identity or decoded measurement lost")
			}
		})
	}
}

type deltaCaptureShortWriter struct {
	header http.Header
	n      int
	err    error
}

func (w *deltaCaptureShortWriter) Header() http.Header       { return w.header }
func (w *deltaCaptureShortWriter) WriteHeader(int)           {}
func (w *deltaCaptureShortWriter) Write([]byte) (int, error) { return w.n, w.err }

func TestDeltaCaptureShortWritesNeverComplete(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		err  error
	}{{"short", 2, nil}, {"short_error", 2, io.ErrUnexpectedEOF}, {"full_error", 6, io.ErrClosedPipe}} {
		t.Run(tc.name, func(t *testing.T) {
			writer := &deltaCaptureShortWriter{header: http.Header{}, n: tc.n, err: tc.err}
			observed := newResponseObserver(writer, "GET")
			observed.representation("upstream", 6, 6, "known-original")
			_, _ = observed.Write([]byte("abcdef"))
			observed.finish()
			if observed.metrics.BodyComplete || observed.metrics.RewrittenBodyTag != "" || observed.metrics.DownstreamBytes != int64(tc.n) {
				t.Fatalf("incomplete write presented as full body: %+v", observed.metrics)
			}
			if hex.EncodeToString(observed.bodyHash.Sum(nil)) != deltaCaptureSHA([]byte("abcdef")[:tc.n]) {
				t.Fatal("observer hashed bytes not accepted by writer")
			}
		})
	}
}

func TestDeltaCaptureCacheAndNoBodyProvenance(t *testing.T) {
	calls := 0
	s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
		calls++
		return audit267CacheResponse("unchanged representation"), nil
	})
	first := audit267CacheRequest(s, "GET", "/cached", nil)
	for _, tc := range []struct {
		name, method string
		headers      http.Header
		source       string
		complete     bool
	}{
		{"cached", "GET", nil, "cache", true},
		{"head", "HEAD", nil, "cache", false},
		{"conditional_cached", "GET", http.Header{"If-None-Match": {first.Header().Get("ETag")}}, "cache", false},
		{"conditional_fresh", "GET", http.Header{"Cache-Control": {"no-cache"}, "If-None-Match": {first.Header().Get("ETag")}}, "upstream", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audit267CacheRequest(s, tc.method, "/cached", tc.headers)
			m := lastResponseMetrics(t, s)
			if m.Source != tc.source || m.BodyComplete != tc.complete || (!tc.complete && m.RewrittenBodyTag != "") {
				t.Fatalf("fresh evidence confused with cached/no-body response: %+v", m)
			}
		})
	}
	if calls != 2 {
		t.Fatalf("expected fresh and no-cache fetches: %d", calls)
	}
}

func TestDeltaCapturePartialAndTransportFailureNotComplete(t *testing.T) {
	for _, transport := range []bool{false, true} {
		s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
			if transport {
				return nil, errors.New("synthetic transport failure")
			}
			resp := audit267SRIResponse("text/plain", "")
			resp.Body = io.NopCloser(io.MultiReader(strings.NewReader("partial"), fidelityReadFailure{}))
			return resp, nil
		})
		got := audit267CacheRequest(s, "GET", "/incomplete", nil)
		m := lastResponseMetrics(t, s)
		if got.Code != 502 || m.Source != "proxy" || m.BodyComplete || m.RewrittenBodyTag != "" || m.OriginalBodyTag != "" || len(m.Upstream) != 1 || m.Upstream[0].Complete {
			t.Fatalf("failure presented as complete fresh body: %+v", m)
		}
	}
}

// The local transport scheme is part of context even when URL.Scheme is empty,
// as it is for requests accepted by an actual HTTP server.
func TestDeltaCaptureLocalSchemeUsesTransport(t *testing.T) {
	s := mappingReviewServer(t, "https://main.example", nil, nil)
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "127.0.0.1:18099"
	upstream, _ := url.Parse("https://main.example")
	plain := newRequestEvidence(s.manifest, s.gate, r)
	plain.observeContext(s.gate, r, upstream)
	r.TLS = &tls.ConnectionState{}
	secure := newRequestEvidence(s.manifest, s.gate, r)
	secure.observeContext(s.gate, r, upstream)
	if plain.entry.ContextTag == secure.entry.ContextTag {
		t.Fatal("HTTP and HTTPS collapsed into one comparison context")
	}
}
