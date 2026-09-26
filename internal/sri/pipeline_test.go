package sri

import (
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func testGate() *scrub.Gate {
	return scrub.NewGate([]string{"example.com"}, []string{"AcmeCorp"}, "alias.local")
}

func testScrubFn(gate *scrub.Gate) ScrubFunc {
	return func(body []byte, contentType, path string) []byte {
		return gate.ScrubBytes(body, "sri:"+path)
	}
}

func sha384b64(data []byte) string {
	h := sha512.Sum384(data)
	return base64.StdEncoding.EncodeToString(h[:])
}

func sha256b64(data []byte) string {
	h := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(h[:])
}

func TestPipeline_ValidOriginalChangedBytes(t *testing.T) {
	jsBody := []byte(`var company = "AcmeCorp"; console.log(company);`)
	integrity := "sha384-" + sha384b64(jsBody)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(jsBody)
	}))
	defer srv.Close()

	gate := testGate()
	cache := NewCache(100)
	pipeline := NewPipeline(PipelineConfig{
		Transport: srv.Client().Transport,
		ScrubFn:   testScrubFn(gate),
		Cache:     cache,
	})

	pageOrigin, _ := url.Parse(srv.URL)
	baseReq := httptest.NewRequest("GET", srv.URL+"/page", nil)
	result := pipeline.Process(srv.URL+"/bundle.js", integrity, "application/javascript", "", pageOrigin, baseReq)

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.UpstreamValid {
		t.Errorf("upstream should be valid, error: %s", result.UpstreamError)
	}
	if result.ReplacementHash == "" {
		t.Error("replacement hash should be set")
	}
	if result.ReplacementHash == integrity {
		t.Error("replacement hash should differ from original (content was scrubbed)")
	}

	// Check cached entry has scrubbed body
	cacheKey := CacheKey(srv.URL+"/bundle.js", baseReq)
	cached, ok := cache.Get(cacheKey)
	if !ok {
		t.Fatal("expected cached entry")
	}
	if strings.Contains(string(cached.ScrubbedBody), "AcmeCorp") {
		t.Error("scrubbed body should not contain identity token")
	}

	// Verify the replacement hash actually validates the scrubbed content
	replacementEntries := ParseIntegrity(result.ReplacementHash)
	ok2, _ := Verify(cached.ScrubbedBody, replacementEntries)
	if !ok2 {
		t.Error("replacement hash should verify against scrubbed bytes")
	}

	// Check findings were recorded
	findings := pipeline.Findings()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !findings[0].UpstreamValid {
		t.Error("finding should record upstream as valid")
	}
	if !findings[0].Transformed {
		t.Error("finding should record transformation")
	}
}

func TestPipeline_ValidOriginalUnchangedBytes(t *testing.T) {
	jsBody := []byte(`var x = 42; console.log(x);`)
	integrity := "sha384-" + sha384b64(jsBody)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(jsBody)
	}))
	defer srv.Close()

	gate := scrub.NewGate(nil, nil, "alias.local")
	cache := NewCache(100)
	pipeline := NewPipeline(PipelineConfig{
		Transport: srv.Client().Transport,
		ScrubFn:   testScrubFn(gate),
		Cache:     cache,
	})

	pageOrigin, _ := url.Parse(srv.URL)
	baseReq := httptest.NewRequest("GET", srv.URL+"/page", nil)
	result := pipeline.Process(srv.URL+"/clean.js", integrity, "application/javascript", "", pageOrigin, baseReq)

	if !result.UpstreamValid {
		t.Errorf("upstream should be valid, error: %s", result.UpstreamError)
	}

	// When content is unchanged by scrubbing, replacement hash should verify
	cacheKey := CacheKey(srv.URL+"/clean.js", baseReq)
	cached, ok := cache.Get(cacheKey)
	if !ok {
		t.Fatal("expected cached entry")
	}
	replacementEntries := ParseIntegrity(result.ReplacementHash)
	ok2, _ := Verify(cached.ScrubbedBody, replacementEntries)
	if !ok2 {
		t.Error("replacement hash should still verify even when content unchanged")
	}
}

func TestPipeline_InvalidOriginal(t *testing.T) {
	jsBody := []byte(`console.log("hello");`)
	wrongIntegrity := "sha384-" + sha384b64([]byte("wrong content entirely"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(jsBody)
	}))
	defer srv.Close()

	gate := testGate()
	cache := NewCache(100)
	pipeline := NewPipeline(PipelineConfig{
		Transport: srv.Client().Transport,
		ScrubFn:   testScrubFn(gate),
		Cache:     cache,
	})

	pageOrigin, _ := url.Parse(srv.URL)
	baseReq := httptest.NewRequest("GET", srv.URL+"/page", nil)
	result := pipeline.Process(srv.URL+"/tampered.js", wrongIntegrity, "application/javascript", "", pageOrigin, baseReq)

	if result.UpstreamValid {
		t.Error("upstream should be invalid (integrity mismatch)")
	}
	if result.ReplacementHash != "" {
		t.Error("no replacement hash should be generated for failed verification")
	}

	findings := pipeline.Findings()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].UpstreamValid {
		t.Error("finding should record upstream as invalid")
	}
	if findings[0].UpstreamError == "" {
		t.Error("finding should have error message")
	}
}

func TestPipeline_FetchError(t *testing.T) {
	gate := testGate()
	cache := NewCache(100)
	pipeline := NewPipeline(PipelineConfig{
		Transport: http.DefaultTransport,
		ScrubFn:   testScrubFn(gate),
		Cache:     cache,
	})

	validHash := "sha384-" + sha384b64([]byte("will never match"))
	pageOrigin, _ := url.Parse("http://127.0.0.1:1")
	baseReq := httptest.NewRequest("GET", "http://127.0.0.1:1/page", nil)
	result := pipeline.Process("http://127.0.0.1:1/fail.js", validHash, "application/javascript", "", pageOrigin, baseReq)

	if result.UpstreamValid {
		t.Error("should fail on fetch error")
	}
	if result.UpstreamError == "" {
		t.Error("should have error message")
	}
}

func TestPipeline_GzipResponse(t *testing.T) {
	jsBody := []byte(`var org = "AcmeCorp"; alert(org);`)
	integrity := "sha384-" + sha384b64(jsBody)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		gz.Write(jsBody)
		gz.Close()
	}))
	defer srv.Close()

	gate := testGate()
	cache := NewCache(100)
	pipeline := NewPipeline(PipelineConfig{
		Transport: srv.Client().Transport,
		ScrubFn:   testScrubFn(gate),
		Cache:     cache,
	})

	pageOrigin, _ := url.Parse(srv.URL)
	baseReq := httptest.NewRequest("GET", srv.URL+"/page", nil)
	result := pipeline.Process(srv.URL+"/gzipped.js", integrity, "application/javascript", "", pageOrigin, baseReq)

	if !result.UpstreamValid {
		t.Errorf("gzipped resource should verify against uncompressed hash, error: %s", result.UpstreamError)
	}

	cacheKey := CacheKey(srv.URL+"/gzipped.js", baseReq)
	cached, ok := cache.Get(cacheKey)
	if !ok {
		t.Fatal("expected cached entry")
	}
	if strings.Contains(string(cached.ScrubbedBody), "AcmeCorp") {
		t.Error("scrubbed gzipped content should not contain identity")
	}
}

func TestPipeline_MultipleHashesStrongestWins(t *testing.T) {
	jsBody := []byte(`var data = "test";`)
	correctSHA384 := "sha384-" + sha384b64(jsBody)
	wrongSHA256 := "sha256-" + sha256b64([]byte("wrong content padding"))
	integrity := wrongSHA256 + " " + correctSHA384

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(jsBody)
	}))
	defer srv.Close()

	gate := scrub.NewGate(nil, nil, "alias.local")
	cache := NewCache(100)
	pipeline := NewPipeline(PipelineConfig{
		Transport: srv.Client().Transport,
		ScrubFn:   testScrubFn(gate),
		Cache:     cache,
	})

	pageOrigin, _ := url.Parse(srv.URL)
	baseReq := httptest.NewRequest("GET", srv.URL+"/page", nil)
	result := pipeline.Process(srv.URL+"/multi.js", integrity, "application/javascript", "", pageOrigin, baseReq)

	if !result.UpstreamValid {
		t.Errorf("strongest algorithm (sha384) matches, should be valid, error: %s", result.UpstreamError)
	}
	if result.ReplacementHash != integrity {
		t.Errorf("verification uses the strongest algorithm, but metadata membership must retain the weaker entry: got %q, want %q", result.ReplacementHash, integrity)
	}
}

func TestPipeline_CacheHit(t *testing.T) {
	fetchCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`var x = 1;`))
	}))
	defer srv.Close()

	jsBody := []byte(`var x = 1;`)
	integrity := "sha384-" + sha384b64(jsBody)

	gate := scrub.NewGate(nil, nil, "alias.local")
	cache := NewCache(100)
	pipeline := NewPipeline(PipelineConfig{
		Transport: srv.Client().Transport,
		ScrubFn:   testScrubFn(gate),
		Cache:     cache,
	})

	pageOrigin, _ := url.Parse(srv.URL)
	baseReq := httptest.NewRequest("GET", srv.URL+"/page", nil)
	pipeline.Process(srv.URL+"/cached.js", integrity, "application/javascript", "", pageOrigin, baseReq)
	pipeline.Process(srv.URL+"/cached.js", integrity, "application/javascript", "", pageOrigin, baseReq)

	if fetchCount != 1 {
		t.Errorf("second call should use cache, got %d fetches", fetchCount)
	}
}

func TestPipeline_CredentialIsolation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		if r.Header.Get("Cookie") != "" {
			w.Write([]byte(`var user = "admin";`))
		} else {
			w.Write([]byte(`var user = "anon";`))
		}
	}))
	defer srv.Close()

	gate := scrub.NewGate(nil, nil, "alias.local")
	cache := NewCache(100)
	pipeline := NewPipeline(PipelineConfig{
		Transport: srv.Client().Transport,
		ScrubFn:   testScrubFn(gate),
		Cache:     cache,
	})

	pageOrigin, _ := url.Parse(srv.URL)

	body1 := []byte(`var user = "admin";`)
	integrity1 := "sha384-" + sha384b64(body1)
	req1 := httptest.NewRequest("GET", srv.URL+"/page", nil)
	req1.Header.Set("Cookie", "session=abc")
	result1 := pipeline.Process(srv.URL+"/user.js", integrity1, "application/javascript", "", pageOrigin, req1)

	body2 := []byte(`var user = "anon";`)
	integrity2 := "sha384-" + sha384b64(body2)
	req2 := httptest.NewRequest("GET", srv.URL+"/page", nil)
	result2 := pipeline.Process(srv.URL+"/user.js", integrity2, "application/javascript", "", pageOrigin, req2)

	if !result1.UpstreamValid {
		t.Errorf("first session should verify, error: %s", result1.UpstreamError)
	}
	if !result2.UpstreamValid {
		t.Errorf("second session should verify independently, error: %s", result2.UpstreamError)
	}

	// Credential-aware cache keys mean both entries coexist without manual clearing
	if cache.Len() != 2 {
		t.Errorf("expected 2 cache entries (one per credential context), got %d", cache.Len())
	}
}
