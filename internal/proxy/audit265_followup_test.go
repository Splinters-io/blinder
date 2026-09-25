package proxy

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/sri"
)

func TestAudit265StableSRIResourceUsesRealUpstreamPath(t *testing.T) {
	for _, mode := range []string{"warm_cache", "no_store", "eviction", "request_no_cache"} {
		t.Run(mode, func(t *testing.T) {
			const body = `var company="AcmeCorp";`
			var paths []string
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				paths = append(paths, r.URL.Path)
				switch r.URL.Path {
				case "/page":
					return audit267SRIResponse("text/html", audit267SRIPage("/asset.js", body)), nil
				case "/asset.js":
					resp := audit267SRIResponse("application/javascript", body)
					if mode == "no_store" {
						resp.Header.Set("Cache-Control", "no-store")
					}
					return resp, nil
				default:
					resp := audit267SRIResponse("text/plain", "not found")
					resp.StatusCode = 404
					return resp, nil
				}
			})
			page := audit267CacheRequest(s, "GET", "/page", nil)
			src, integrity := audit267SRIAttribute(page.Body.String(), "src"), audit267SRIAttribute(page.Body.String(), "integrity")
			if src == "" || integrity == "" {
				t.Fatalf("missing resource reference: %s", page.Body.String())
			}
			if mode == "eviction" {
				for i := 0; i < 256; i++ {
					s.sriCache.Put(fmt.Sprintf("unused-%d", i), &sri.CacheEntry{})
				}
			}
			headers := make(http.Header)
			if mode == "request_no_cache" {
				headers.Set("Cache-Control", "no-cache")
			}
			got := audit267CacheRequest(s, "GET", src, headers)
			valid, _ := sri.Verify(got.Body.Bytes(), sri.ParseIntegrity(integrity))
			if got.Code != 200 || !valid {
				t.Fatalf("unchanged valid asset broke: emitted src=%q upstream paths=%q status=%d body=%q SRI valid=%v", src, paths, got.Code, got.Body.String(), valid)
			}
		})
	}
}

func TestAudit265SRISecondPageCannotOverwriteFirstReference(t *testing.T) {
	version := 1
	body := func() string { return fmt.Sprintf("var version=%d;", version) }
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset", body())), nil
		}
		resp := audit267SRIResponse("application/javascript", body())
		resp.Header.Set("Cache-Control", "no-store")
		return resp, nil
	})
	first := audit267CacheRequest(s, "GET", "/page", nil)
	firstHash := audit267SRIAttribute(first.Body.String(), "integrity")
	version = 2
	second := audit267CacheRequest(s, "GET", "/page", nil)
	secondHash := audit267SRIAttribute(second.Body.String(), "integrity")
	if firstHash == "" || secondHash == "" || firstHash == secondHash {
		t.Fatal("fixture requires two successfully verified versions")
	}
	got := audit267CacheRequest(s, "GET", audit267SRIAttribute(first.Body.String(), "src"), nil)
	validFirst, _ := sri.Verify(got.Body.Bytes(), sri.ParseIntegrity(firstHash))
	validSecond, _ := sri.Verify(got.Body.Bytes(), sri.ParseIntegrity(secondHash))
	if got.Code == 200 && !validFirst {
		t.Fatalf("second page replaced first page's resource identity: first src=%q second src=%q status=%d first SRI=%v second SRI=%v body=%q", audit267SRIAttribute(first.Body.String(), "src"), audit267SRIAttribute(second.Body.String(), "src"), got.Code, validFirst, validSecond, got.Body.String())
	}
}

func TestAudit265RevalidationHeadersRemainScrubbed(t *testing.T) {
	calls := 0
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		calls++
		resp := audit267CacheResponse("body")
		resp.Header.Set("ETag", `"up-v1"`)
		resp.Header.Set("Content-Security-Policy", "connect-src https://main.example; report-uri https://main.example/AcmeCorp")
		if calls == 1 {
			resp.Header.Set("Cache-Control", "max-age=0")
		} else {
			resp.StatusCode = 304
			resp.Body = http.NoBody
		}
		return resp, nil
	})
	first := audit267CacheRequest(s, "GET", "/resource", nil)
	if strings.Contains(first.Header().Get("Content-Security-Policy"), "main.example") {
		t.Fatal("control 200 already leaks")
	}
	for i := 0; i < 2; i++ {
		got := audit267CacheRequest(s, "GET", "/resource", nil)
		csp := got.Header().Get("Content-Security-Policy")
		if strings.Contains(csp, "main.example") || strings.Contains(csp, "AcmeCorp") {
			t.Errorf("revalidation bypassed header scrubbing: upstream calls=%d CSP=%q", calls, csp)
		}
	}
}

func TestAudit265NoStore304PreservesNewResponsePolicy(t *testing.T) {
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
			resp.Header.Set("Cache-Control", "no-store")
			resp.Header.Set("Content-Security-Policy", "script-src 'none'")
		}
		return resp, nil
	})
	audit267CacheRequest(s, "GET", "/resource", nil)
	got := audit267CacheRequest(s, "GET", "/resource", nil)
	if got.Header().Get("Cache-Control") != "no-store" || got.Header().Get("Content-Security-Policy") != "script-src 'none'" {
		t.Fatalf("eviction discarded 304 policy: downstream status=%d Cache-Control=%q CSP=%q", got.Code, got.Header().Get("Cache-Control"), got.Header().Get("Content-Security-Policy"))
	}
}

func TestAudit265ExistingVaryCanChangeOn304(t *testing.T) {
	for _, mode := range []string{"add_dimension", "wildcard"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				calls++
				resp := audit267CacheResponse("mode " + r.Header.Get("X-Mode"))
				resp.Header.Set("ETag", `"up-v1"`)
				resp.Header.Set("Vary", "Accept-Language")
				if calls == 1 {
					resp.Header.Set("Cache-Control", "max-age=0")
				}
				if calls == 2 {
					resp.StatusCode = 304
					resp.Body = http.NoBody
					if mode == "wildcard" {
						resp.Header.Set("Vary", "*")
					} else {
						resp.Header.Set("Vary", "Accept-Language, X-Mode")
					}
				}
				return resp, nil
			})
			h := http.Header{"Accept-Language": {"en"}, "X-Mode": {"a"}}
			audit267CacheRequest(s, "GET", "/resource", h)
			audit267CacheRequest(s, "GET", "/resource", h)
			h.Set("X-Mode", "b")
			got := audit267CacheRequest(s, "GET", "/resource", h)
			if calls != 3 || got.Body.String() != "mode b" {
				t.Fatalf("304 %s selected old variant: calls=%d body=%q Vary=%q", mode, calls, got.Body.String(), got.Header().Get("Vary"))
			}
		})
	}
}

func TestAudit265PrivatePolicyReplacesSharedEntry(t *testing.T) {
	for _, mode := range []string{"replacement_200", "revalidation_304"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				calls++
				resp := audit267CacheResponse(fmt.Sprintf("version %d", calls))
				resp.Header.Set("ETag", `"up-v1"`)
				if calls == 1 && mode == "revalidation_304" {
					resp.Header.Set("Cache-Control", "max-age=0")
				}
				if calls == 2 {
					resp.Header.Set("Cache-Control", "private, max-age=3600")
					if mode == "revalidation_304" {
						resp.StatusCode = 304
						resp.Body = http.NoBody
					}
				}
				return resp, nil
			})
			audit267CacheRequest(s, "GET", "/resource", nil)
			h := make(http.Header)
			if mode == "replacement_200" {
				h.Set("Cache-Control", "no-cache")
			}
			audit267CacheRequest(s, "GET", "/resource", h)
			got := audit267CacheRequest(s, "GET", "/resource", nil)
			if calls != 3 {
				t.Fatalf("private policy left shared cache usable: calls=%d body=%q Cache-Control=%q", calls, got.Body.String(), got.Header().Get("Cache-Control"))
			}
		})
	}
}
