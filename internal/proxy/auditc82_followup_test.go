package proxy

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/sri"
)

func TestAuditC82LatestVerifiedNoStorePageCanLoad(t *testing.T) {
	version := 1
	asset := func() string { return fmt.Sprintf(`var version=%d;var company="AcmeCorp";`, version) }
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset", asset())), nil
		}
		resp := audit267SRIResponse("application/javascript", asset())
		resp.Header.Set("Cache-Control", "no-store")
		return resp, nil
	})
	for version = 1; version <= 2; version++ {
		page := audit267CacheRequest(s, "GET", "/page", nil)
		src := audit267SRIAttribute(page.Body.String(), "src")
		integrity := audit267SRIAttribute(page.Body.String(), "integrity")
		if src == "" || integrity == "" {
			t.Fatalf("v%d valid page lost its resource: %s", version, page.Body.String())
		}
		got := audit267CacheRequest(s, "GET", src, nil)
		valid, _ := sri.Verify(got.Body.Bytes(), sri.ParseIntegrity(integrity))
		if got.Code != 200 || !valid {
			t.Fatalf("newly verified v%d resource cannot load: status=%d body=%q matches newly issued SRI=%v", version, got.Code, got.Body.String(), valid)
		}
	}
}

func TestAuditC82AliasRoundtripPreservesCompleteURI(t *testing.T) {
	for _, resource := range []string{"/asset.js/asset.js", "/assets%2Fbundle/asset.js", "/asset.js?next=/asset.js"} {
		t.Run(resource, func(t *testing.T) {
			const body = `var company="AcmeCorp";`
			var requests []string
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				requests = append(requests, r.URL.RequestURI())
				if r.URL.Path == "/page" {
					return audit267SRIResponse("text/html", audit267SRIPage(resource, body)), nil
				}
				if r.URL.RequestURI() == resource {
					resp := audit267SRIResponse("application/javascript", body)
					resp.Header.Set("Cache-Control", "no-store")
					return resp, nil
				}
				resp := audit267SRIResponse("text/plain", "not found")
				resp.StatusCode = 404
				return resp, nil
			})
			page := audit267CacheRequest(s, "GET", "/page", nil)
			src := audit267SRIAttribute(page.Body.String(), "src")
			integrity := audit267SRIAttribute(page.Body.String(), "integrity")
			if src == "" || integrity == "" {
				t.Fatalf("valid page has no reference: %s", page.Body.String())
			}
			got := audit267CacheRequest(s, "GET", src, nil)
			valid, _ := sri.Verify(got.Body.Bytes(), sri.ParseIntegrity(integrity))
			if got.Code != 200 || !valid {
				t.Fatalf("URI roundtrip failed: want=%q emitted=%q actual requests=%q status=%d body=%q", resource, src, requests, got.Code, got.Body.String())
			}
		})
	}
}

func TestAuditC82RevalidationMergesAllPolicyHeaderValues(t *testing.T) {
	for _, mode := range []string{"retained", "evicted", "conditional"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				calls++
				resp := audit267CacheResponse("same body")
				resp.Header.Set("ETag", `"up-v1"`)
				if calls == 1 {
					resp.Header.Set("Cache-Control", "max-age=0")
					resp.Header.Set("Content-Security-Policy", "script-src 'self'")
					resp.Header.Set("Referrer-Policy", "unsafe-url")
				} else {
					resp.StatusCode = 304
					resp.Body = http.NoBody
					resp.Header["Content-Security-Policy"] = []string{"script-src 'self'", "script-src 'none'"}
					resp.Header.Set("Referrer-Policy", "no-referrer")
					if mode == "evicted" {
						resp.Header.Set("Cache-Control", "no-store")
					}
				}
				return resp, nil
			})
			first := audit267CacheRequest(s, "GET", "/resource", nil)
			headers := make(http.Header)
			if mode == "conditional" {
				headers.Set("If-None-Match", first.Header().Get("ETag"))
			}
			got := audit267CacheRequest(s, "GET", "/resource", headers)
			check := func(phase string, h http.Header) {
				policies := h.Values("Content-Security-Policy")
				if len(policies) != 2 || !strings.Contains(strings.Join(policies, ";"), "script-src 'none'") {
					t.Errorf("%s lost 304 CSP policy values: values=%q", phase, policies)
				}
				if h.Get("Referrer-Policy") != "no-referrer" {
					t.Errorf("%s ignored 304 Referrer-Policy: got=%q want=no-referrer", phase, h.Get("Referrer-Policy"))
				}
			}
			check("revalidated response", got.Header())
			if mode != "evicted" {
				cached := audit267CacheRequest(s, "GET", "/resource", nil)
				if calls != 2 {
					t.Fatalf("control did not get fresh cached response: calls=%d", calls)
				}
				check("fresh cached response", cached.Header())
			}
		})
	}
}

func TestAuditC82ChangedVaryRemainsReachableFromBaseKey(t *testing.T) {
	calls := 0
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		calls++
		resp := audit267CacheResponse("mode a")
		resp.Header.Set("ETag", `"up-v1"`)
		resp.Header.Set("Vary", "Accept-Language")
		if calls == 1 {
			resp.Header.Set("Cache-Control", "max-age=0")
		}
		if calls == 2 {
			resp.StatusCode = 304
			resp.Body = http.NoBody
			resp.Header.Set("Vary", "Accept-Language, X-Mode")
		}
		if calls > 2 {
			resp.StatusCode = 503
			resp.Header.Set("Cache-Control", "no-store")
		}
		return resp, nil
	})
	headers := http.Header{"Accept-Language": {"en"}, "X-Mode": {"a"}}
	audit267CacheRequest(s, "GET", "/resource", headers)
	revalidated := audit267CacheRequest(s, "GET", "/resource", headers)
	if revalidated.Code != 200 || revalidated.Header().Get("Cache-Control") != "max-age=3600" {
		t.Fatal("fixture did not revalidate as fresh")
	}
	got := audit267CacheRequest(s, "GET", "/resource", headers)
	if calls != 2 || got.Code != 200 || got.Body.String() != "mode a" {
		t.Fatalf("fresh re-keyed variant unreachable: calls=%d status=%d body=%q", calls, got.Code, got.Body.String())
	}
}
