package proxy

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/Splinters-io/blinder/internal/sri"
)

func TestAudit2EApplicationVersionQueryIsNotProxyMetadata(t *testing.T) {
	for _, path := range []string{"/api?_bv=0123456789abcdef", "/api?q=2&_bv=0123456789abcdef"} {
		t.Run(path, func(t *testing.T) {
			var forwarded string
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				forwarded = r.URL.RequestURI()
				return audit267SRIResponse("text/plain", "ok"), nil
			})
			audit267CacheRequest(s, "GET", path, nil)
			if forwarded != path {
				t.Fatalf("application build ID consumed as proxy metadata: requested=%q forwarded=%q", path, forwarded)
			}
		})
	}
}

func TestAudit2ESRIResourceKeepsExistingVersionQuery(t *testing.T) {
	for _, appVersion := range []string{"app", "0123456789abcdef"} {
		t.Run(appVersion, func(t *testing.T) {
			resource := "/asset?_bv=" + appVersion
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
				resp := audit267SRIResponse("text/plain", "incorrect application query")
				resp.StatusCode = 404
				return resp, nil
			})
			page := audit267CacheRequest(s, "GET", "/page", nil)
			src := audit267SRIAttribute(page.Body.String(), "src")
			integrity := audit267SRIAttribute(page.Body.String(), "integrity")
			if src == "" || integrity == "" {
				t.Fatal("valid page lost its reference")
			}
			got := audit267CacheRequest(s, "GET", audit750BrowserPath(t, src), nil)
			valid, _ := sri.Verify(got.Body.Bytes(), sri.ParseIntegrity(integrity))
			if got.Code != 200 || !valid {
				t.Fatalf("valid SRI resource query corrupted: emitted=%q requests=%q status=%d body=%q", src, requests, got.Code, got.Body.String())
			}
		})
	}
}

func TestAudit2EIssuedReferenceSurvivesLossOfVersionIndex(t *testing.T) {
	for _, mode := range []string{"cache_clear", "restart"} {
		t.Run(mode, func(t *testing.T) {
			keyDir := t.TempDir()
			version := 1
			body := func() string { return fmt.Sprintf("var version=%d;", version) }
			transport := func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/page" {
					return audit267SRIResponse("text/html", audit267SRIPage("/asset", body())), nil
				}
				resp := audit267SRIResponse("application/javascript", body())
				resp.Header.Set("Cache-Control", "public, max-age=3600")
				return resp, nil
			}
			s := audit267SRIServer(t, transport, keyDir)
			first := audit267CacheRequest(s, "GET", "/page", nil)
			oldPath := audit750BrowserPath(t, audit267SRIAttribute(first.Body.String(), "src"))
			oldHash := audit267SRIAttribute(first.Body.String(), "integrity")
			control := audit267CacheRequest(s, "GET", oldPath, nil)
			valid, _ := sri.Verify(control.Body.Bytes(), sri.ParseIntegrity(oldHash))
			if control.Code != 200 || !valid {
				t.Fatal("initial valid reference cannot load")
			}
			if mode == "restart" {
				s = audit267SRIServer(t, transport, keyDir)
			} else {
				s.ClearSRICache()
			}
			version = 2
			currentPage := audit267CacheRequest(s, "GET", "/page", nil)
			currentHash := audit267SRIAttribute(currentPage.Body.String(), "integrity")
			current := audit267CacheRequest(s, "GET", audit750BrowserPath(t, audit267SRIAttribute(currentPage.Body.String(), "src")), nil)
			valid, _ = sri.Verify(current.Body.Bytes(), sri.ParseIntegrity(currentHash))
			if currentHash == oldHash || current.Code != 200 || !valid {
				t.Fatal("newly verified reference must load after index reset")
			}
			old := audit267CacheRequest(s, "GET", oldPath, nil)
			valid, _ = sri.Verify(old.Body.Bytes(), sri.ParseIntegrity(oldHash))
			if mode == "restart" {
				if old.Code < 400 {
					t.Fatalf("restart failed to block retired version token: status=%d body=%q", old.Code, old.Body.String())
				}
			} else if old.Code == 200 && !valid {
				t.Fatalf("missing version index accepted incompatible bytes after %s: old URL=%q status=%d body=%q", mode, oldPath, old.Code, old.Body.String())
			}
		})
	}
}

func TestAudit2EConditionalPathsPreserveResponseMetadata(t *testing.T) {
	const frontOrigin = "https://127.0.0.1:18099"
	for _, mode := range []string{"fresh_response_cache", "revalidated_response_cache", "sri_cache"} {
		t.Run(mode, func(t *testing.T) {
			const body = "var value=1;"
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/page" {
					return audit267SRIResponse("text/html", audit267SRIPage("/resource", body)), nil
				}
				resp := audit267SRIResponse("application/javascript", body)
				resp.Header.Set("ETag", `"up-v1"`)
				resp.Header.Set("Cache-Control", "max-age=3600")
				resp.Header.Set("Vary", "Origin")
				resp.Header.Set("Expires", "Thu, 01 Jan 2037 00:00:00 GMT")
				resp.Header.Set("Content-Location", "/resource-version")
				resp.Header.Set("Access-Control-Allow-Origin", "https://main.example")
				if mode == "revalidated_response_cache" {
					if r.Header.Get("If-None-Match") != "" {
						resp.StatusCode = 304
						resp.Body = http.NoBody
					} else {
						resp.Header.Set("Cache-Control", "max-age=0")
					}
				}
				return resp, nil
			})
			path := "/resource"
			if mode == "sri_cache" {
				page := audit267CacheRequest(s, "GET", "/page", nil)
				path = audit750BrowserPath(t, audit267SRIAttribute(page.Body.String(), "src"))
			}
			headers := http.Header{"Origin": {frontOrigin}}
			first := audit267CacheRequest(s, "GET", path, headers)
			if first.Code != 200 || first.Header().Get("Vary") != "Origin" || first.Header().Get("Access-Control-Allow-Origin") != frontOrigin {
				t.Fatalf("200 metadata control failed: status=%d headers=%v", first.Code, first.Header())
			}
			headers.Set("If-None-Match", first.Header().Get("ETag"))
			got := audit267CacheRequest(s, "GET", path, headers)
			if got.Code != 304 {
				t.Fatalf("expected conditional 304, got %d", got.Code)
			}
			for name, want := range map[string]string{"Vary": "Origin", "Expires": "Thu, 01 Jan 2037 00:00:00 GMT", "Content-Location": "/resource-version", "Access-Control-Allow-Origin": frontOrigin, "Cache-Control": "max-age=3600"} {
				if actual := got.Header().Get(name); actual != want {
					t.Errorf("%s omitted response metadata: %s=%q want=%q", mode, name, actual, want)
				}
			}
		})
	}
}

func TestAudit2E304UpdatesBrowserIsolationHeaders(t *testing.T) {
	calls := 0
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		calls++
		resp := audit267CacheResponse("body")
		resp.Header.Set("ETag", `"up-v1"`)
		if calls == 1 {
			resp.Header.Set("Cache-Control", "max-age=0")
			resp.Header.Set("Cross-Origin-Opener-Policy", "unsafe-none")
			resp.Header.Set("Cross-Origin-Embedder-Policy", "unsafe-none")
		} else {
			resp.StatusCode = 304
			resp.Body = http.NoBody
			resp.Header.Set("Cross-Origin-Opener-Policy", "same-origin")
			resp.Header.Set("Cross-Origin-Embedder-Policy", "require-corp")
		}
		return resp, nil
	})
	audit267CacheRequest(s, "GET", "/resource", nil)
	for i := 0; i < 2; i++ {
		got := audit267CacheRequest(s, "GET", "/resource", nil)
		if got.Header().Get("Cross-Origin-Opener-Policy") != "same-origin" || got.Header().Get("Cross-Origin-Embedder-Policy") != "require-corp" {
			t.Errorf("304 isolation policy ignored: upstream calls=%d COOP=%q COEP=%q", calls, got.Header().Get("Cross-Origin-Opener-Policy"), got.Header().Get("Cross-Origin-Embedder-Policy"))
		}
	}
}
