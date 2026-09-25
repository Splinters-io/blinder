package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/sri"
)

// Browser requests omit fragments; follow the emitted URL, not its source text.
func audit750BrowserPath(t *testing.T, src string) string {
	t.Helper()
	u, err := url.Parse(src)
	if err != nil || src == "" {
		t.Fatalf("bad emitted URL %q: %v", src, err)
	}
	return u.RequestURI()
}

func TestAudit750IssuedVersionSurvivesCachePolicyTransitions(t *testing.T) {
	for _, mode := range []string{"no_store_control", "no_store_to_sri_cache", "no_store_to_response_cache", "public_after_eviction"} {
		t.Run(mode, func(t *testing.T) {
			version := 1
			body := func() string { return fmt.Sprintf(`var version=%d;var company="AcmeCorp";`, version) }
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/page" {
					return audit267SRIResponse("text/html", audit267SRIPage("/asset", body())), nil
				}
				resp := audit267SRIResponse("application/javascript", body())
				policy := "public, max-age=3600"
				if mode == "no_store_control" || (version == 1 && mode != "public_after_eviction") {
					policy = "no-store"
				}
				resp.Header.Set("Cache-Control", policy)
				return resp, nil
			})
			first := audit267CacheRequest(s, "GET", "/page", nil)
			firstPath := audit750BrowserPath(t, audit267SRIAttribute(first.Body.String(), "src"))
			firstHash := audit267SRIAttribute(first.Body.String(), "integrity")
			if firstHash == "" {
				t.Fatal("first page has no integrity")
			}
			version = 2
			if mode == "public_after_eviction" {
				for i := 0; i < 256; i++ {
					s.sriCache.Put(fmt.Sprintf("unused-%d", i), &sri.CacheEntry{})
				}
			}
			if mode == "no_store_to_response_cache" {
				// An ordinary consumer first populates the response cache with v2.
				current := audit267CacheRequest(s, "GET", "/asset", nil)
				if current.Code != 200 || !strings.Contains(current.Body.String(), "version=2") {
					t.Fatalf("current resource cannot load: status=%d body=%q", current.Code, current.Body.String())
				}
			} else {
				second := audit267CacheRequest(s, "GET", "/page", nil)
				secondHash := audit267SRIAttribute(second.Body.String(), "integrity")
				if secondHash == "" || secondHash == firstHash {
					t.Fatal("second page not verified as a distinct version")
				}
				current := audit267CacheRequest(s, "GET", audit750BrowserPath(t, audit267SRIAttribute(second.Body.String(), "src")), nil)
				valid, _ := sri.Verify(current.Body.Bytes(), sri.ParseIntegrity(secondHash))
				if current.Code != 200 || !valid {
					t.Fatalf("newly verified current resource fails: status=%d valid=%v", current.Code, valid)
				}
			}
			old := audit267CacheRequest(s, "GET", firstPath, nil)
			valid, _ := sri.Verify(old.Body.Bytes(), sri.ParseIntegrity(firstHash))
			if old.Code == 200 && !valid {
				t.Fatalf("issued reference bypassed version check via %s: path=%q status=%d body=%q", mode, firstPath, old.Code, old.Body.String())
			}
		})
	}
}

func TestAudit750VersionBindingSurvivesURLFragment(t *testing.T) {
	version := 1
	body := func() string { return fmt.Sprintf("var version=%d;", version) }
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset#section", body())), nil
		}
		resp := audit267SRIResponse("application/javascript", body())
		resp.Header.Set("Cache-Control", "no-store")
		return resp, nil
	})
	first := audit267CacheRequest(s, "GET", "/page", nil)
	src := audit267SRIAttribute(first.Body.String(), "src")
	firstHash := audit267SRIAttribute(first.Body.String(), "integrity")
	if firstHash == "" {
		t.Fatal("missing first integrity")
	}
	path := audit750BrowserPath(t, src)
	control := audit267CacheRequest(s, "GET", path, nil)
	valid, _ := sri.Verify(control.Body.Bytes(), sri.ParseIntegrity(firstHash))
	if control.Code != 200 || !valid {
		t.Fatal("unchanged resource control failed")
	}
	version = 2
	second := audit267CacheRequest(s, "GET", "/page", nil)
	secondHash := audit267SRIAttribute(second.Body.String(), "integrity")
	if secondHash == "" || secondHash == firstHash {
		t.Fatal("fixture did not verify new version")
	}
	current := audit267CacheRequest(s, "GET", audit750BrowserPath(t, audit267SRIAttribute(second.Body.String(), "src")), nil)
	valid, _ = sri.Verify(current.Body.Bytes(), sri.ParseIntegrity(secondHash))
	if current.Code != 200 || !valid {
		t.Fatal("newly verified resource with fragment must still load")
	}
	old := audit267CacheRequest(s, "GET", path, nil)
	valid, _ = sri.Verify(old.Body.Bytes(), sri.ParseIntegrity(firstHash))
	if old.Code == 200 && !valid {
		t.Fatalf("fragment swallowed version binding: emitted=%q browser requests=%q status=%d body=%q", src, path, old.Code, old.Body.String())
	}
}

func TestAudit750ApplicationQueryParametersArePreserved(t *testing.T) {
	for _, path := range []string{"/api?_bv=app", "/api?_bv=app&q=2", "/api?q=2&_bv=app"} {
		t.Run(path, func(t *testing.T) {
			var actual string
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				actual = r.URL.RequestURI()
				return audit267SRIResponse("text/plain", "ok"), nil
			})
			audit267CacheRequest(s, "GET", path, nil)
			if actual != path {
				t.Fatalf("ordinary non-SRI request changed: requested=%q forwarded=%q", path, actual)
			}
		})
	}
}

func TestAudit750RevalidationUpdatesOtherSecurityHeaders(t *testing.T) {
	for _, mode := range []string{"retained", "evicted"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				calls++
				resp := audit267CacheResponse("body")
				resp.Header.Set("ETag", `"up-v1"`)
				if calls == 1 {
					resp.Header.Set("Cache-Control", "max-age=0")
					resp.Header.Set("Access-Control-Allow-Origin", "*")
					resp.Header.Set("Cross-Origin-Resource-Policy", "cross-origin")
					resp.Header.Set("X-Frame-Options", "SAMEORIGIN")
				} else {
					resp.StatusCode = 304
					resp.Body = http.NoBody
					resp.Header.Set("Access-Control-Allow-Origin", "null")
					resp.Header.Set("Cross-Origin-Resource-Policy", "same-origin")
					resp.Header.Set("X-Frame-Options", "DENY")
					if mode == "evicted" {
						resp.Header.Set("Cache-Control", "no-store")
					}
				}
				return resp, nil
			})
			audit267CacheRequest(s, "GET", "/resource", nil)
			got := audit267CacheRequest(s, "GET", "/resource", nil)
			for name, want := range map[string]string{"Access-Control-Allow-Origin": "null", "Cross-Origin-Resource-Policy": "same-origin", "X-Frame-Options": "DENY"} {
				if actual := got.Header().Get(name); actual != want {
					t.Errorf("304 metadata update ignored: %s=%q want=%q", name, actual, want)
				}
			}
		})
	}
}

func TestAudit750FreshConditionalHitCarriesUpdatedPolicy(t *testing.T) {
	calls := 0
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		calls++
		resp := audit267CacheResponse("body")
		resp.Header.Set("ETag", `"up-v1"`)
		if calls == 1 {
			resp.Header.Set("Cache-Control", "max-age=0")
			resp.Header.Set("Content-Security-Policy", "script-src 'self'")
		} else {
			resp.StatusCode = 304
			resp.Body = http.NoBody
			resp.Header.Set("Content-Security-Policy", "script-src 'none'")
		}
		return resp, nil
	})
	old := audit267CacheRequest(s, "GET", "/resource", nil)
	updated := audit267CacheRequest(s, "GET", "/resource", nil)
	if updated.Header().Get("Content-Security-Policy") != "script-src 'none'" {
		t.Fatal("control revalidation did not update policy")
	}
	// Another client now validates its old representation against the fresh cache.
	got := audit267CacheRequest(s, "GET", "/resource", http.Header{"If-None-Match": {old.Header().Get("ETag")}})
	if calls != 2 || got.Code != 304 {
		t.Fatalf("fixture did not use fresh conditional hit: calls=%d status=%d", calls, got.Code)
	}
	if got.Header().Get("Content-Security-Policy") != "script-src 'none'" || got.Header().Get("Cache-Control") != "max-age=3600" {
		t.Fatalf("fresh 304 omits updated metadata: CSP=%q Cache-Control=%q", got.Header().Get("Content-Security-Policy"), got.Header().Get("Cache-Control"))
	}
}
