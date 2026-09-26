package sri

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
)

func TestPipelineOriginalBodyTagRetainsDecodedSourceAcrossCacheVersions(t *testing.T) {
	original, rewritten := []byte("/* original private source */"), []byte("/* transformed source */")
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(original); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	var tagged [][]byte
	fetches := 0
	const wantTag = "opaque-session-source-tag"
	p := NewPipeline(PipelineConfig{
		Transport: evidenceTransport(func(*http.Request) (*http.Response, error) {
			fetches++
			return &http.Response{StatusCode: 200, Header: http.Header{
				"Content-Type": {"application/javascript"}, "Content-Encoding": {"gzip"},
			}, Body: io.NopCloser(bytes.NewReader(compressed.Bytes()))}, nil
		}),
		ContentTag: func(body []byte) string {
			tagged = append(tagged, append([]byte(nil), body...))
			return wantTag
		},
		ScrubFn: func([]byte, string, string) []byte { return append([]byte(nil), rewritten...) },
		Cache:   NewCache(10),
	})
	page, _ := url.Parse("https://example.test/page")
	req := httptest.NewRequest("GET", page.String(), nil)
	const resource = "https://example.test/code.js"
	key := CacheKey(resource, req)
	process := func(reserved ...map[string]string) *ProcessResult {
		result := p.Process(resource, ComputeIntegrity(original, "sha384"), "application/javascript", "", page, req, reserved...)
		if result == nil || !result.UpstreamValid {
			t.Fatalf("processing failed: %+v", result)
		}
		return result
	}
	initial := process()
	published, ok := p.cache.Get(key)
	if !ok || published.OriginalBodyTag != wantTag || !bytes.Equal(published.ScrubbedBody, rewritten) {
		t.Fatalf("source tag missing from transformed cache entry: %+v", published)
	}
	if !reflect.DeepEqual(tagged, [][]byte{original}) {
		t.Fatalf("callback received encoded/rewritten bytes: %q", tagged)
	}
	cachedResult := process()
	if cachedResult.BodyVersion != initial.BodyVersion {
		t.Fatal("ordinary cache hit changed the resource version")
	}
	foreign := base64.StdEncoding.EncodeToString(computeDigest([]byte("another original"), "sha256"))
	versioned := process(map[string]string{initial.RewrittenSHA256: foreign})
	variant, ok := p.cache.Get(key)
	if !ok || variant == published || variant.BodyVersion == initial.BodyVersion || !strings.Contains(variant.BodyVersion, ".c") {
		t.Fatalf("fixture did not exercise cache-version cloning: %+v", variant)
	}
	if variant.OriginalBodyTag != wantTag || published.OriginalBodyTag != wantTag {
		t.Fatalf("version selection changed source tag: original=%q variant=%q", published.OriginalBodyTag, variant.OriginalBodyTag)
	}
	if !bytes.Equal(ApplyBodyVersion(original, rewritten, versioned.BodyVersion), variant.ScrubbedBody) {
		t.Fatal("selected body version cannot be retrieved reproducibly")
	}
	for _, version := range []string{initial.BodyVersion, versioned.BodyVersion} {
		if !p.cache.HasDigest(key+"\x01"+version) || !p.cache.CheckBodyIntegrity(key+"\x01"+version, original) {
			t.Fatalf("original source constraint missing for %s", version)
		}
	}
	if fetches != 1 || len(tagged) != 1 {
		t.Fatalf("cache/version reads retagged transformed bytes: fetches=%d tags=%d", fetches, len(tagged))
	}
}

func TestPipelineOriginalBodyTagAbsentWithoutCallback(t *testing.T) {
	original := []byte("/* source */")
	p, _ := referencePipeline(original, []byte("/* different */"))
	result := processReference(p, ComputeIntegrity(original, "sha256"))
	entry, ok := p.cache.Get("https://example.test/code.js")
	if result == nil || !result.UpstreamValid || !ok || entry.OriginalBodyTag != "" {
		t.Fatalf("absent callback gained a public tag: result=%+v entry=%+v", result, entry)
	}
}

func TestPipelineOriginalBodyTagNotComputedForIncompleteOrFailedFetch(t *testing.T) {
	for _, tc := range []struct {
		name, body, encoding string
		status               int
		incomplete           bool
	}{
		{"upstream-error", "private error body", "", 503, false},
		{"invalid-gzip", "not a gzip stream", "gzip", 200, false},
		{"partial-body", "private partial body", "", 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			p := NewPipeline(PipelineConfig{
				Transport: evidenceTransport(func(*http.Request) (*http.Response, error) {
					var body io.Reader = strings.NewReader(tc.body)
					if tc.incomplete {
						body = io.MultiReader(body, iotest.ErrReader(io.ErrUnexpectedEOF))
					}
					return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Encoding": {tc.encoding}}, Body: io.NopCloser(body)}, nil
				}),
				ContentTag: func([]byte) string { calls++; return "must-not-be-emitted" },
				ScrubFn:    func(body []byte, _, _ string) []byte { return body },
				Cache:      NewCache(10),
			})
			result := processReference(p, ComputeIntegrity([]byte(tc.body), "sha256"))
			entry, ok := p.cache.Get("https://example.test/code.js")
			if result == nil || result.UpstreamError == "" || !ok || entry.OriginalBodyTag != "" || calls != 0 {
				t.Fatalf("failed fetch emitted a source tag: result=%+v entry=%+v calls=%d", result, entry, calls)
			}
		})
	}
}
