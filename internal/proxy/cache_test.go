package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Splinters-io/blinder/internal/cache"
)

// cacheTarget wraps a test server that counts requests and supports conditional responses.
type cacheTarget struct {
	srv      *httptest.Server
	hits     atomic.Int64
	body     string
	etag     string
	modified string
	cc       string
	vary     string
}

func newCacheTarget(body, etag, cc string) *cacheTarget {
	ct := &cacheTarget{body: body, etag: etag, cc: cc}
	ct.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct.hits.Add(1)

		// Conditional request handling
		if ct.etag != "" {
			inm := r.Header.Get("If-None-Match")
			if inm == ct.etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		if ct.modified != "" {
			ims := r.Header.Get("If-Modified-Since")
			if ims == ct.modified {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}

		w.Header().Set("Content-Type", "text/plain")
		if ct.etag != "" {
			w.Header().Set("ETag", ct.etag)
		}
		if ct.modified != "" {
			w.Header().Set("Last-Modified", ct.modified)
		}
		if ct.cc != "" {
			w.Header().Set("Cache-Control", ct.cc)
		}
		if ct.vary != "" {
			w.Header().Set("Vary", ct.vary)
		}
		fmt.Fprint(w, ct.body)
	}))
	return ct
}

func (ct *cacheTarget) close() { ct.srv.Close() }
func (ct *cacheTarget) url() string { return ct.srv.URL }
func (ct *cacheTarget) hitCount() int64 { return ct.hits.Load() }

// --- Tests ---

func TestCache_DownstreamETagDiffersFromUpstream(t *testing.T) {
	ct := newCacheTarget("hello world", `"upstream-1"`, "max-age=3600")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/page")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("response must have an ETag")
	}
	if etag == `"upstream-1"` {
		t.Error("downstream ETag must differ from upstream ETag")
	}
	if !strings.Contains(etag, "bl-") {
		t.Errorf("downstream ETag should contain bl- prefix, got: %s", etag)
	}
}

func TestCache_ETagDescribesRewrittenBytes(t *testing.T) {
	ct := newCacheTarget("Visit AcmeCorp today", `"up-1"`, "max-age=3600")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/page")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	etag := resp.Header.Get("ETag")
	expected := cache.ComputeETag(body)
	if etag != expected {
		t.Errorf("ETag should match rewritten body: got %s, want %s", etag, expected)
	}
}

func TestCache_ConditionalGET304OnMatch(t *testing.T) {
	ct := newCacheTarget("stable content", `"up-v1"`, "max-age=3600")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	resp1, err := client.Get("https://" + addr + "/page")
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	resp1.Body.Close()
	etag := resp1.Header.Get("ETag")
	if etag == "" {
		t.Fatal("first response must have ETag")
	}

	req, _ := http.NewRequest("GET", "https://"+addr+"/page", nil)
	req.Header.Set("If-None-Match", etag)
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("conditional request: %v", err)
	}
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusNotModified {
		t.Errorf("expected 304, got %d", resp2.StatusCode)
	}
	if resp2.Header.Get("ETag") != etag {
		t.Errorf("304 should echo ETag: got %s, want %s", resp2.Header.Get("ETag"), etag)
	}
}

func TestCache_ConditionalGET200OnMismatch(t *testing.T) {
	ct := newCacheTarget("body v1", `"up-v1"`, "max-age=3600")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	resp1, _ := client.Get("https://" + addr + "/page")
	resp1.Body.Close()

	req, _ := http.NewRequest("GET", "https://"+addr+"/page", nil)
	req.Header.Set("If-None-Match", `"stale-etag"`)
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("conditional request: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	if len(body) == 0 {
		t.Error("200 response must include body")
	}
}

func TestCache_FreshHitNoUpstreamRequest(t *testing.T) {
	ct := newCacheTarget("cached body", `"up-v1"`, "max-age=3600")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	resp1, _ := client.Get("https://" + addr + "/page")
	resp1.Body.Close()
	hitsAfterFirst := ct.hitCount()

	resp2, err := client.Get("https://" + addr + "/page")
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if ct.hitCount() != hitsAfterFirst {
		t.Errorf("fresh cache hit should not contact upstream: hits before=%d after=%d",
			hitsAfterFirst, ct.hitCount())
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	if len(body) == 0 {
		t.Error("cached response should have body")
	}
}

func TestCache_Upstream304RevalidatesStaleEntry(t *testing.T) {
	ct := newCacheTarget("revalidated body", `"up-v1"`, "max-age=0")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	resp1, _ := client.Get("https://" + addr + "/page")
	resp1.Body.Close()
	etag := resp1.Header.Get("ETag")

	resp2, err := client.Get("https://" + addr + "/page")
	if err != nil {
		t.Fatalf("revalidation request: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if ct.hitCount() != 2 {
		t.Errorf("expected 2 upstream hits (initial + revalidation), got %d", ct.hitCount())
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	if resp2.Header.Get("ETag") != etag {
		t.Error("revalidated response should have same ETag (content unchanged)")
	}
	if len(body) == 0 {
		t.Error("revalidated response should have body")
	}
}

func TestCache_Upstream304WithClientConditional(t *testing.T) {
	ct := newCacheTarget("stable", `"up-v1"`, "max-age=0")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	resp1, _ := client.Get("https://" + addr + "/page")
	resp1.Body.Close()
	etag := resp1.Header.Get("ETag")

	req, _ := http.NewRequest("GET", "https://"+addr+"/page", nil)
	req.Header.Set("If-None-Match", etag)
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("conditional revalidation: %v", err)
	}
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusNotModified {
		t.Errorf("expected 304, got %d", resp2.StatusCode)
	}
}

func TestCache_ColdCacheFullFetch(t *testing.T) {
	ct := newCacheTarget("brand new", "", "")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/page")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "brand new") {
		t.Error("cold cache should return full body")
	}
	if resp.Header.Get("ETag") == "" {
		t.Error("response should have downstream ETag even without upstream ETag")
	}
}

func TestCache_ChangedContentNewETag(t *testing.T) {
	ct := newCacheTarget("version 1", `"up-v1"`, "max-age=0")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	resp1, _ := client.Get("https://" + addr + "/page")
	resp1.Body.Close()
	etag1 := resp1.Header.Get("ETag")

	// Change upstream content and ETag (simulating content change)
	ct.body = "version 2"
	ct.etag = `"up-v2"`

	resp2, err := client.Get("https://" + addr + "/page")
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	etag2 := resp2.Header.Get("ETag")

	if etag1 == etag2 {
		t.Error("changed content must produce different ETag")
	}
	if !strings.Contains(string(body2), "version 2") {
		t.Errorf("expected new body, got: %s", body2)
	}
}

func TestCache_NoStoreNotCached(t *testing.T) {
	ct := newCacheTarget("secret data", `"up-v1"`, "no-store")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	srv, addr := startTestProxy(t, cfg)
	client := testClient()

	resp1, _ := client.Get("https://" + addr + "/page")
	resp1.Body.Close()

	if srv.ResponseCache().Len() != 0 {
		t.Error("no-store response should not be cached")
	}

	resp2, _ := client.Get("https://" + addr + "/page")
	resp2.Body.Close()

	if ct.hitCount() != 2 {
		t.Errorf("no-store should cause upstream hit every time, got %d", ct.hitCount())
	}
}

func TestCache_NoCacheAlwaysRevalidates(t *testing.T) {
	ct := newCacheTarget("revalidate me", `"up-v1"`, "no-cache")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	resp1, _ := client.Get("https://" + addr + "/page")
	resp1.Body.Close()

	resp2, _ := client.Get("https://" + addr + "/page")
	resp2.Body.Close()

	if ct.hitCount() != 2 {
		t.Errorf("no-cache should revalidate every time, got %d upstream hits", ct.hitCount())
	}
}

func TestCache_CredentialIsolation(t *testing.T) {
	ct := newCacheTarget("shared page", `"up-v1"`, "max-age=3600")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	// Anonymous request
	resp1, _ := client.Get("https://" + addr + "/page")
	resp1.Body.Close()
	hitsAfterAnon := ct.hitCount()

	// Authenticated request
	req, _ := http.NewRequest("GET", "https://"+addr+"/page", nil)
	req.Header.Set("Cookie", "session=abc123")
	resp2, _ := client.Do(req)
	resp2.Body.Close()

	if ct.hitCount() == hitsAfterAnon {
		t.Error("authenticated request should not serve from anonymous cache entry")
	}
}

func TestCache_VaryDimensions(t *testing.T) {
	ct := newCacheTarget("lang content", `"up-v1"`, "max-age=3600")
	ct.vary = "Accept-Language"
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	req1, _ := http.NewRequest("GET", "https://"+addr+"/page", nil)
	req1.Header.Set("Accept-Language", "en")
	resp1, _ := client.Do(req1)
	resp1.Body.Close()
	hitsAfterEN := ct.hitCount()

	req2, _ := http.NewRequest("GET", "https://"+addr+"/page", nil)
	req2.Header.Set("Accept-Language", "fr")
	resp2, _ := client.Do(req2)
	resp2.Body.Close()

	if ct.hitCount() == hitsAfterEN {
		t.Error("different Vary dimension values should not share cache entries")
	}
}

func TestCache_HEADConditional304(t *testing.T) {
	ct := newCacheTarget("head content", `"up-v1"`, "max-age=3600")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	resp1, _ := client.Get("https://" + addr + "/page")
	resp1.Body.Close()
	etag := resp1.Header.Get("ETag")

	req, _ := http.NewRequest("HEAD", "https://"+addr+"/page", nil)
	req.Header.Set("If-None-Match", etag)
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("HEAD conditional: %v", err)
	}
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusNotModified {
		t.Errorf("HEAD with matching If-None-Match should return 304, got %d", resp2.StatusCode)
	}
}

func TestCache_HEADNoBody(t *testing.T) {
	ct := newCacheTarget("head content", `"up-v1"`, "max-age=3600")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	resp1, _ := client.Get("https://" + addr + "/page")
	resp1.Body.Close()

	req, _ := http.NewRequest("HEAD", "https://"+addr+"/page", nil)
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("HEAD request: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("HEAD should return 200, got %d", resp2.StatusCode)
	}
	if len(body) != 0 {
		t.Errorf("HEAD response should have no body, got %d bytes", len(body))
	}
	if resp2.Header.Get("ETag") == "" {
		t.Error("HEAD response should include ETag")
	}
}

func TestCache_POSTNotCached(t *testing.T) {
	ct := newCacheTarget("post response", `"up-v1"`, "max-age=3600")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	srv, addr := startTestProxy(t, cfg)
	client := testClient()

	resp, err := client.Post("https://"+addr+"/submit", "text/plain", strings.NewReader("data"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	if srv.ResponseCache().Len() != 0 {
		t.Error("POST responses should not be cached")
	}
}

func TestCache_ETagConsistentAcrossRequests(t *testing.T) {
	ct := newCacheTarget("consistent", `"up-v1"`, "max-age=3600")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	resp1, _ := client.Get("https://" + addr + "/page")
	resp1.Body.Close()
	etag1 := resp1.Header.Get("ETag")

	resp2, _ := client.Get("https://" + addr + "/page")
	resp2.Body.Close()
	etag2 := resp2.Header.Get("ETag")

	if etag1 != etag2 {
		t.Errorf("same content should produce same ETag: %s vs %s", etag1, etag2)
	}
}

func TestCache_UpstreamETagNotExposed(t *testing.T) {
	ct := newCacheTarget("hidden etag", `"upstream-secret-v1"`, "max-age=3600")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)

	resp, _ := testClient().Get("https://" + addr + "/page")
	resp.Body.Close()

	etag := resp.Header.Get("ETag")
	if strings.Contains(etag, "upstream") {
		t.Errorf("upstream ETag should not be exposed downstream, got: %s", etag)
	}
}

func TestCache_VaryStarNotCached(t *testing.T) {
	ct := newCacheTarget("vary star", `"up-v1"`, "max-age=3600")
	ct.vary = "*"
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	srv, addr := startTestProxy(t, cfg)
	client := testClient()

	resp, _ := client.Get("https://" + addr + "/page")
	resp.Body.Close()

	if srv.ResponseCache().Len() != 0 {
		t.Error("Vary: * responses should not be cached")
	}

	resp2, _ := client.Get("https://" + addr + "/page")
	resp2.Body.Close()

	if ct.hitCount() != 2 {
		t.Errorf("Vary: * should hit upstream every time, got %d", ct.hitCount())
	}
}

func TestCache_MustRevalidateAlwaysChecksUpstream(t *testing.T) {
	ct := newCacheTarget("must reval", `"up-v1"`, "max-age=3600, must-revalidate")
	defer ct.close()

	cfg := newTestConfig(t, ct.url())
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	resp1, _ := client.Get("https://" + addr + "/page")
	resp1.Body.Close()

	resp2, _ := client.Get("https://" + addr + "/page")
	resp2.Body.Close()

	if ct.hitCount() != 2 {
		t.Errorf("must-revalidate should check upstream every time, got %d", ct.hitCount())
	}
}
