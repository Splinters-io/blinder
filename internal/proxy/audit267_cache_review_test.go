package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/cache"
	"github.com/Splinters-io/blinder/internal/sri"
)

func audit267CacheResponse(body string) *http.Response {
	r := audit267SRIResponse("text/plain", body)
	r.Header.Set("Cache-Control", "max-age=3600")
	return r
}

func audit267CacheRequest(s *Server, method, path string, headers http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://127.0.0.1:18099"+path, nil)
	r.Header = headers.Clone()
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestAudit267CacheSeparatesAuthenticatedUsers(t *testing.T) {
	for _, field := range []string{"Cookie", "Authorization"} {
		t.Run(field, func(t *testing.T) {
			calls := 0
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				calls++
				who := "bob"
				if strings.Contains(r.Header.Get(field), "alice") {
					who = "alice"
				}
				resp := audit267CacheResponse("private profile for " + who)
				resp.Header.Set("Cache-Control", "private, max-age=3600")
				return resp, nil
			})
			audit267CacheRequest(s, "GET", "/profile", http.Header{field: {"session=alice"}})
			bob := audit267CacheRequest(s, "GET", "/profile", http.Header{field: {"session=bob"}})
			if strings.Contains(bob.Body.String(), "alice") {
				t.Fatalf("Bob received Alice's cached response: status=%d body=%q upstream calls=%d", bob.Code, bob.Body.String(), calls)
			}
		})
	}
}

func TestAudit267CacheHEADCannotPopulateEmptyGET(t *testing.T) {
	calls := 0
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		calls++
		body := "actual representation"
		resp := audit267CacheResponse(body)
		if r.Method == "HEAD" {
			resp = audit267CacheResponse("")
			resp.Header.Set("Content-Length", fmt.Sprint(len(body)))
		}
		return resp, nil
	})
	head := audit267CacheRequest(s, "HEAD", "/resource", nil)
	get := audit267CacheRequest(s, "GET", "/resource", nil)
	if get.Body.String() != "actual representation" {
		t.Fatalf("HEAD populated empty cached GET: HEAD ETag=%s GET status=%d body=%q upstream calls=%d", head.Header().Get("ETag"), get.Code, get.Body.String(), calls)
	}
}

func TestAudit267CacheVaryEntriesCanBeReused(t *testing.T) {
	calls := 0
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		calls++
		resp := audit267CacheResponse("language " + r.Header.Get("Accept-Language"))
		resp.Header.Set("Vary", "Accept-Language")
		return resp, nil
	})
	for _, lang := range []string{"en", "fr", "en"} {
		got := audit267CacheRequest(s, "GET", "/language", http.Header{"Accept-Language": {lang}})
		if got.Body.String() != "language "+lang {
			t.Fatalf("wrong language: %q", got.Body.String())
		}
	}
	if calls != 2 {
		t.Fatalf("en/fr/en should fetch two variants, got %d upstream requests; variant entries cannot be discovered", calls)
	}
}

func TestAudit267CacheRevalidationMerges304Metadata(t *testing.T) {
	calls := 0
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		calls++
		resp := audit267CacheResponse("stable body")
		resp.Header.Set("ETag", `"upstream-v1"`)
		if calls == 1 {
			resp.Header.Set("Cache-Control", "max-age=0")
			return resp, nil
		}
		resp = audit267SRIResponse("text/plain", "")
		resp.StatusCode = 304
		resp.Header.Set("Cache-Control", "max-age=3600")
		resp.Header.Set("ETag", `"upstream-v1"`)
		return resp, nil
	})
	audit267CacheRequest(s, "GET", "/resource", nil)
	second := audit267CacheRequest(s, "GET", "/resource", nil)
	audit267CacheRequest(s, "GET", "/resource", nil)
	if second.Header().Get("Cache-Control") != "max-age=3600" || calls != 2 {
		t.Fatalf("304 metadata ignored: returned cache-control=%q upstream calls=%d; want refreshed max-age and two calls", second.Header().Get("Cache-Control"), calls)
	}
}

func TestAudit267CacheHonorsFreshnessInputs(t *testing.T) {
	for _, scenario := range []string{"request_no_cache", "response_age", "fresh_must_revalidate"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				calls++
				resp := audit267CacheResponse("body")
				if scenario == "response_age" {
					resp.Header.Set("Cache-Control", "max-age=60")
					resp.Header.Set("Age", "120")
				}
				if scenario == "fresh_must_revalidate" {
					resp.Header.Set("Cache-Control", "max-age=3600, must-revalidate")
				}
				return resp, nil
			})
			audit267CacheRequest(s, "GET", "/resource", nil)
			headers := make(http.Header)
			if scenario == "request_no_cache" {
				headers.Set("Cache-Control", "no-cache")
			}
			audit267CacheRequest(s, "GET", "/resource", headers)
			want := 2
			if scenario == "fresh_must_revalidate" {
				want = 1
			}
			if calls != want {
				t.Fatalf("%s: upstream calls=%d want=%d", scenario, calls, want)
			}
		})
	}
}

func TestAudit267CacheConditionalDoesNotMaskErrors(t *testing.T) {
	for _, code := range []int{404, 500} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				resp := audit267CacheResponse("upstream error")
				resp.StatusCode = code
				return resp, nil
			})
			got := audit267CacheRequest(s, "GET", "/resource", http.Header{"If-None-Match": {"*"}})
			if got.Code != code {
				t.Fatalf("If-None-Match:* changed upstream %d into %d", code, got.Code)
			}
		})
	}
}

func TestAudit267CacheColdFetchDoesNotForwardLocalValidator(t *testing.T) {
	var seen string
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		seen = r.Header.Get("If-None-Match")
		if seen != "" {
			resp := audit267SRIResponse("text/plain", "")
			resp.StatusCode = 304
			return resp, nil
		}
		return audit267CacheResponse("current bytes"), nil
	})
	got := audit267CacheRequest(s, "GET", "/resource", http.Header{"If-None-Match": {`"bl-old-local-validator"`}})
	if seen != "" || got.Code != 200 || got.Body.String() != "current bytes" {
		t.Fatalf("cold cache forwarded downstream validator=%q, returned status=%d body=%q without a stored representation", seen, got.Code, got.Body.String())
	}
}

func TestAudit267CacheMutationInvalidatesStoredResponse(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			version := 1
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				if r.Method == method {
					version = 2
					resp := audit267SRIResponse("text/plain", "")
					resp.StatusCode = 204
					return resp, nil
				}
				return audit267CacheResponse(fmt.Sprintf("version %d", version)), nil
			})
			audit267CacheRequest(s, "GET", "/resource", nil)
			audit267CacheRequest(s, method, "/resource", nil)
			got := audit267CacheRequest(s, "GET", "/resource", nil)
			if got.Body.String() != "version 2" {
				t.Fatalf("successful %s left stale GET cached: %q", method, got.Body.String())
			}
		})
	}
}

func TestAudit267CachePreservesSRIReferenceAcrossEviction(t *testing.T) {
	version := 1
	assetFor := func(v int) string { return fmt.Sprintf(`var version=%d;var company="AcmeCorp";`, v) }
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			resp := audit267SRIResponse("text/html", audit267SRIPage("/asset.js", assetFor(version)))
			resp.Header.Set("Cache-Control", "max-age=3600")
			return resp, nil
		}
		return audit267SRIResponse("application/javascript", assetFor(version)), nil
	})
	first := audit267CacheRequest(s, "GET", "/page", nil)
	hash := audit267SRIAttribute(first.Body.String(), "integrity")
	base := httptest.NewRequest("GET", "https://127.0.0.1:18099/page", nil)
	if _, ok := s.sriCache.Get(sri.CacheKeyForAuthority("https://main.example/asset.js", base, base.Host)); !ok {
		t.Fatal("fixture never cached original SRI resource")
	}
	for i := 0; i < 256; i++ {
		result := s.sriPipeline.Process(fmt.Sprintf("https://main.example/filler-%d.js", i), sri.ComputeIntegrity([]byte(assetFor(1)), "sha384"), "application/javascript", "", s.cfg.TargetURL, base)
		if result == nil || !result.UpstreamValid {
			t.Fatalf("filler prefetch failed: %+v", result)
		}
	}
	if _, ok := s.sriCache.Get(sri.CacheKeyForAuthority("https://main.example/asset.js", base, base.Host)); ok {
		t.Fatal("fixture failed to evict original SRI resource")
	}
	version = 2
	page := audit267CacheRequest(s, "GET", "/page", nil)
	asset := audit267CacheRequest(s, "GET", "/asset.js", nil)
	pageHash := audit267SRIAttribute(page.Body.String(), "integrity")
	valid, _ := sri.Verify(asset.Body.Bytes(), sri.ParseIntegrity(pageHash))
	if asset.Code == 200 && !valid {
		t.Fatalf("SRI drift: page promises %s but asset bytes don't match: %q (original hash was %s)", pageHash, asset.Body.String(), hash)
	}
}

func TestAudit267CacheSRINoStoreIsNotReusableHTTPEntry(t *testing.T) {
	calls := 0
	body := `var x=1;`
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset.js", body)), nil
		}
		calls++
		resp := audit267SRIResponse("application/javascript", body)
		resp.Header.Set("Cache-Control", "no-store")
		return resp, nil
	})
	audit267CacheRequest(s, "GET", "/page", nil)
	audit267CacheRequest(s, "GET", "/asset.js", nil)
	audit267CacheRequest(s, "GET", "/asset.js", nil)
	if calls == 1 {
		t.Fatalf("no-store SRI resource became an indefinitely reusable cache entry; prefetch plus two requests made %d upstream call", calls)
	}
}

func TestAudit267CacheRewritesCORSForCurrentRequest(t *testing.T) {
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		resp := audit267CacheResponse("body")
		resp.Header.Set("Access-Control-Allow-Origin", "https://main.example")
		return resp, nil
	})
	audit267CacheRequest(s, "GET", "/resource", http.Header{"Origin": {"https://localhost:18099"}})
	got := audit267CacheRequest(s, "GET", "/resource", http.Header{"Origin": {"https://127.0.0.1:18099"}})
	if got.Header().Get("Access-Control-Allow-Origin") != "https://127.0.0.1:18099" {
		t.Fatalf("cached request-relative CORS origin replayed for another request: %q", got.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestAudit267CacheLookupUpdatesLRURecency(t *testing.T) {
	c := cache.New(2)
	entry := cache.Entry{Body: []byte("body"), Directives: cache.Directives{MaxAge: 3600}, StoredAt: time.Now()}
	c.Store("A", entry)
	c.Store("B", entry)
	c.Lookup("A")
	c.Store("C", entry)
	if _, ok := c.Lookup("A"); !ok {
		t.Fatal("recently read A was evicted; implementation is insertion-order FIFO rather than LRU")
	}
	if _, ok := c.Lookup("B"); ok {
		t.Fatal("least recently used B was retained")
	}
}
