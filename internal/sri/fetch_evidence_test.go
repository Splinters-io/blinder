package sri

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func compressedEvidence(t *testing.T, body []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	if _, err := gz.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestFetchEvidencePreservesBoundedErrorBodiesAndSizes(t *testing.T) {
	body := []byte(strings.Repeat("fixture diagnostic\n", 32))
	gz := compressedEvidence(t, body)
	corrupt := append([]byte(nil), gz...)
	corrupt[len(corrupt)-8] ^= 1 // Decoded bytes exist even though CRC validation fails.
	for _, tc := range []struct {
		name, encoding  string
		status          int
		wire, observed  []byte
		decoded         int64
		complete, valid bool
	}{
		{"success-gzip", "gzip", 200, gz, body, int64(len(body)), true, true},
		{"refusal-gzip", "gzip", 503, gz, body, int64(len(body)), true, false},
		{"checksum-failure", "gzip", 503, corrupt, body, int64(len(body)), false, false},
		{"invalid-gzip-header", "gzip", 503, []byte("invalid"), nil, -1, false, false},
		{"unsupported-encoding", "br", 503, []byte("opaque"), nil, -1, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/javascript")
				w.Header().Set("Content-Encoding", tc.encoding)
				w.Header().Set("Content-Length", strconv.Itoa(len(tc.wire)))
				w.WriteHeader(tc.status)
				_, _ = w.Write(tc.wire)
			}))
			defer server.Close()
			var records []FetchRecord
			cache := NewCache(10)
			pipeline := NewPipeline(PipelineConfig{Transport: server.Client().Transport, Cache: cache, ScrubFn: func(body []byte, _, _ string) []byte { return body }, OnFetch: func(record FetchRecord) { records = append(records, record) }})
			origin, _ := url.Parse(server.URL)
			req := httptest.NewRequest("GET", server.URL+"/page", nil)
			resource := server.URL + "/asset"
			result := pipeline.Process(resource, ComputeIntegrity(body, "sha384"), "application/javascript", "", origin, req)
			if result == nil || result.UpstreamValid != tc.valid || len(records) != 1 {
				t.Fatalf("result=%+v records=%d", result, len(records))
			}
			record := records[0]
			encoded := int64(len(tc.wire))
			if tc.encoding == "br" {
				encoded = 0
			}
			if record.Status != tc.status || record.EncodedBytes != encoded || record.DecodedBytes != tc.decoded || record.BodyComplete != tc.complete || !bytes.Equal(record.Body, tc.observed) {
				t.Fatalf("incorrect fetch evidence: %+v; body=%q", record, record.Body)
			}
			if !tc.valid {
				entry, ok := cache.Get(CacheKey(resource, req))
				h := sha256.Sum256(body)
				if !ok || entry.FetchError == "" || len(entry.ScrubbedBody) != 0 || cache.HasDigest(CacheKey(resource, req)+"\x01"+fmt.Sprintf("bl%x", h[:8])) {
					t.Fatalf("error body became a valid SRI resource: %+v", entry)
				}
			}
		})
	}
}

type evidenceTransport func(*http.Request) (*http.Response, error)

func (f evidenceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchEvidenceAlreadyDecompressedSizeIsUnknown(t *testing.T) {
	const body = "decoded bytes"
	var record FetchRecord
	pipeline := NewPipeline(PipelineConfig{Transport: evidenceTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Status: "200 OK", Proto: "HTTP/2.0", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Uncompressed: true}, nil
	}), OnFetch: func(rec FetchRecord) { record = rec }})
	_, _, _, err := pipeline.fetch("https://fixture.invalid/asset", false, httptest.NewRequest("GET", "https://fixture.invalid/page", nil), "")
	if err != nil || record.EncodedBytes != -1 || record.DecodedBytes != int64(len(body)) || !record.BodyComplete || record.HTTPVersion != "HTTP/2.0" {
		t.Fatalf("invented encoded length: error=%v record=%+v", err, record)
	}
}

func TestFetchEvidenceBodyLimitPreservesPartialAndObservedCounts(t *testing.T) {
	wire := compressedEvidence(t, []byte(strings.Repeat("x", maxFetchSize+1)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(503)
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	var record FetchRecord
	pipeline := NewPipeline(PipelineConfig{Transport: server.Client().Transport, OnFetch: func(rec FetchRecord) { record = rec }})
	body, _, _, err := pipeline.fetch(server.URL+"/asset", false, httptest.NewRequest("GET", server.URL+"/page", nil), "")
	if err == nil || len(body) != 0 || !strings.Contains(err.Error(), "resource too large") || len(record.Body) != maxFetchSize || record.DecodedBytes != maxFetchSize+1 || record.EncodedBytes <= 0 || record.EncodedBytes > int64(len(wire)) || record.BodyComplete {
		t.Fatalf("limit evidence incorrect: err=%v validBody=%d captured=%d encoded=%d decoded=%d complete=%t", err, len(body), len(record.Body), record.EncodedBytes, record.DecodedBytes, record.BodyComplete)
	}
}

func TestFetchEvidenceTimeoutKeepsPartialNon200Body(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "999")
		w.WriteHeader(503)
		_, _ = io.WriteString(w, "partial")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer func() { close(release); server.Close() }()
	var record FetchRecord
	pipeline := NewPipeline(PipelineConfig{Transport: server.Client().Transport, FetchTimeout: 100 * time.Millisecond, OnFetch: func(rec FetchRecord) { record = rec }})
	start := time.Now()
	body, _, _, err := pipeline.fetch(server.URL+"/asset", false, httptest.NewRequest("GET", server.URL+"/page", nil), "")
	if err == nil || len(body) != 0 || time.Since(start) > 2*time.Second || record.Status != 503 || string(record.Body) != "partial" || record.EncodedBytes != 7 || record.DecodedBytes != 7 || record.BodyComplete {
		t.Fatalf("timeout lost partial response: err=%v record=%+v", err, record)
	}
}
