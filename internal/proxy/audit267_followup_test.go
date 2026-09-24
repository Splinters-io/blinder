package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/sri"
)

func TestAudit267FollowupCreateOnlyWriteKeepsPrecondition(t *testing.T) {
	writes := 0
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		resp := audit267SRIResponse("text/plain", "")
		if r.Header.Get("If-None-Match") == "*" {
			resp.StatusCode = 412
			return resp, nil
		}
		writes++
		resp.StatusCode = 200
		return resp, nil
	})
	got := audit267CacheRequest(s, "PUT", "/exists", http.Header{"If-None-Match": {"*"}})
	if writes != 0 || got.Code != 412 {
		t.Fatalf("create-only precondition removed: upstream writes=%d response=%d; expected no write and 412", writes, got.Code)
	}
}

func TestAudit267FollowupPATCHInvalidates(t *testing.T) {
	version := 1
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.Method == "PATCH" {
			version = 2
			resp := audit267SRIResponse("text/plain", "")
			resp.StatusCode = 204
			return resp, nil
		}
		return audit267CacheResponse(fmt.Sprintf("version %d", version)), nil
	})
	audit267CacheRequest(s, "GET", "/resource", nil)
	audit267CacheRequest(s, "PATCH", "/resource", nil)
	got := audit267CacheRequest(s, "GET", "/resource", nil)
	if got.Body.String() != "version 2" {
		t.Fatalf("successful PATCH left stale cached response: %q", got.Body.String())
	}
}

func TestAudit267Followup304NoStoreIsEnforced(t *testing.T) {
	calls := 0
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		calls++
		resp := audit267CacheResponse("sensitive body")
		resp.Header.Set("ETag", `"upstream-v1"`)
		if calls == 1 {
			resp.Header.Set("Cache-Control", "max-age=0")
			return resp, nil
		}
		if calls == 2 {
			resp.StatusCode = 304
			resp.Body = http.NoBody
			resp.Header.Set("Cache-Control", "no-store, max-age=3600")
			return resp, nil
		}
		return resp, nil
	})
	audit267CacheRequest(s, "GET", "/resource", nil)
	audit267CacheRequest(s, "GET", "/resource", nil)
	audit267CacheRequest(s, "GET", "/resource", nil)
	if calls != 3 {
		t.Fatalf("304 no-store entry reused as fresh: upstream calls=%d want=3", calls)
	}
}

func TestAudit267Followup304UpdatesVaryAndSecurityHeaders(t *testing.T) {
	calls := 0
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			resp := audit267CacheResponse("language en")
			resp.Header.Set("Cache-Control", "max-age=0")
			resp.Header.Set("ETag", `"en-v1"`)
			resp.Header.Set("Content-Security-Policy", "script-src 'self'")
			return resp, nil
		}
		if r.Header.Get("Accept-Language") == "en" && r.Header.Get("If-None-Match") == `"en-v1"` {
			resp := audit267SRIResponse("text/plain", "")
			resp.StatusCode = 304
			resp.Header.Set("ETag", `"en-v1"`)
			resp.Header.Set("Cache-Control", "max-age=3600")
			resp.Header.Set("Vary", "Accept-Language")
			resp.Header.Set("Content-Security-Policy", "script-src 'none'")
			return resp, nil
		}
		resp := audit267CacheResponse("language " + r.Header.Get("Accept-Language"))
		resp.Header.Set("Vary", "Accept-Language")
		return resp, nil
	})
	en := http.Header{"Accept-Language": {"en"}}
	audit267CacheRequest(s, "GET", "/resource", en)
	refreshed := audit267CacheRequest(s, "GET", "/resource", en)
	fr := audit267CacheRequest(s, "GET", "/resource", http.Header{"Accept-Language": {"fr"}})
	if refreshed.Header().Get("Content-Security-Policy") != "script-src 'none'" {
		t.Errorf("304 security metadata ignored: CSP=%q", refreshed.Header().Get("Content-Security-Policy"))
	}
	if fr.Body.String() != "language fr" {
		t.Errorf("304 Vary ignored: French request received %q, upstream calls=%d", fr.Body.String(), calls)
	}
}

func TestAudit267FollowupInvalidationDuringRevalidationDoesNotPanic(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			resp := audit267SRIResponse("text/plain", "")
			resp.StatusCode = 204
			return resp, nil
		}
		resp := audit267CacheResponse("version one")
		resp.Header.Set("ETag", `"up-v1"`)
		resp.Header.Set("Cache-Control", "max-age=0")
		if r.Header.Get("If-None-Match") != "" {
			close(started)
			<-release
			resp.StatusCode = 304
			resp.Body = http.NoBody
		}
		return resp, nil
	})
	audit267CacheRequest(s, "GET", "/resource", nil)
	done := make(chan any, 1)
	go func() { defer func() { done <- recover() }(); audit267CacheRequest(s, "GET", "/resource", nil) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("revalidation did not start")
	}
	audit267CacheRequest(s, "POST", "/resource", nil)
	close(release)
	select {
	case panicValue := <-done:
		if panicValue != nil {
			t.Fatalf("concurrent invalidation made 304 handler panic: %v", panicValue)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revalidation hung")
	}
}

func TestAudit267FollowupIssuedSRIPageKeepsMatchingResource(t *testing.T) {
	for _, scenario := range []string{"eviction", "no_store", "mutation"} {
		t.Run(scenario, func(t *testing.T) {
			version := 1
			assetFor := func(v int) string { return fmt.Sprintf(`var version=%d;var company="AcmeCorp";`, v) }
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				if r.Method == "PUT" {
					version = 2
					resp := audit267SRIResponse("text/plain", "")
					resp.StatusCode = 204
					return resp, nil
				}
				if r.URL.Path == "/page" {
					return audit267SRIResponse("text/html", audit267SRIPage("/asset.js", assetFor(version))), nil
				}
				resp := audit267SRIResponse("application/javascript", assetFor(version))
				if scenario == "no_store" {
					resp.Header.Set("Cache-Control", "no-store")
				}
				return resp, nil
			})
			page := audit267CacheRequest(s, "GET", "/page", nil)
			integrity := audit267SRIAttribute(page.Body.String(), "integrity")
			if integrity == "" {
				t.Fatal("fixture did not emit integrity")
			}
			if scenario == "eviction" {
				base := httptest.NewRequest("GET", "https://main.example/page", nil)
				for i := 0; i < 256; i++ {
					result := s.sriPipeline.Process(fmt.Sprintf("https://main.example/filler-%d.js", i), sri.ComputeIntegrity([]byte(assetFor(1)), "sha384"), "application/javascript", "", s.cfg.TargetURL, base)
					if result == nil || !result.UpstreamValid {
						t.Fatal("filler failed")
					}
				}
			}
			if scenario == "mutation" {
				audit267CacheRequest(s, "PUT", "/asset.js", nil)
				got := audit267CacheRequest(s, "GET", "/asset.js", http.Header{"Cache-Control": {"no-cache"}})
				if strings.Contains(got.Body.String(), "version=1") {
					t.Fatalf("SRI cache bypassed mutation invalidation and request no-cache: %q", got.Body.String())
				}
				return
			}
			version = 2
			// No second HTML request: the browser already holds the issued page.
			resourcePath := audit267SRIAttribute(page.Body.String(), "src")
			asset := audit267CacheRequest(s, "GET", resourcePath, nil)
			valid, _ := sri.Verify(asset.Body.Bytes(), sri.ParseIntegrity(integrity))
			if asset.Code == 200 && !valid {
				t.Fatalf("issued page SRI no longer matches served resource after %s: integrity=%s body=%q", scenario, integrity, asset.Body.String())
			}
		})
	}
}

func TestAudit267FollowupNoStoreNotReusedBySRIPipeline(t *testing.T) {
	version := 1
	assetFor := func(v int) string { return fmt.Sprintf(`var version=%d;`, v) }
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset.js", assetFor(version))), nil
		}
		resp := audit267SRIResponse("application/javascript", assetFor(version))
		resp.Header.Set("Cache-Control", "no-store")
		return resp, nil
	})
	audit267CacheRequest(s, "GET", "/page", nil)
	audit267CacheRequest(s, "GET", "/asset.js", nil)
	version = 2
	second := audit267CacheRequest(s, "GET", "/page", nil)
	if audit267SRIAttribute(second.Body.String(), "src") == "" {
		t.Fatalf("valid updated resource blocked because pipeline reused no-store original digests: %q", second.Body.String())
	}
}

func TestAudit267FollowupNoStoreReplacementRemovesOldEntry(t *testing.T) {
	calls := 0
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		calls++
		resp := audit267CacheResponse(fmt.Sprintf("version %d", calls))
		if calls == 2 {
			resp.Header.Set("Cache-Control", "no-store")
		}
		return resp, nil
	})
	audit267CacheRequest(s, "GET", "/resource", nil)
	audit267CacheRequest(s, "GET", "/resource", http.Header{"Cache-Control": {"no-cache"}})
	got := audit267CacheRequest(s, "GET", "/resource", nil)
	if got.Body.String() == "version 1" {
		t.Fatalf("no-store replacement left previous fresh response reusable: %q", got.Body.String())
	}
}

// Do not store a shared anonymous private response for another anonymous user.
func TestAudit267FollowupPrivateAnonymousResponseIsNotShared(t *testing.T) {
	calls := 0
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		calls++
		resp := audit267CacheResponse(fmt.Sprintf("visitor %d", calls))
		resp.Header.Set("Set-Cookie", fmt.Sprintf("session=visitor-%d; Path=/; HttpOnly", calls))
		resp.Header.Set("Cache-Control", "private, max-age=3600")
		return resp, nil
	})
	audit267CacheRequest(s, "GET", "/resource", nil)
	audit267CacheRequest(s, "GET", "/resource", nil)
	if calls != 2 {
		t.Fatalf("private response stored in shared anonymous cache, upstream calls=%d", calls)
	}
}
