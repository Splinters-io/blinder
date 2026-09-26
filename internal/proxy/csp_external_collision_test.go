package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/sri"
)

// A valid version must reproduce the exact representation after a required
// upstream read. Caching the original body is not permission to ignore no-store.
func TestExternalSRIConvergenceAfterRefetch(t *testing.T) {
	for _, mode := range []string{"no-store", "request-no-cache", "evicted"} {
		t.Run(mode, func(t *testing.T) {
			originals := map[string]string{
				"/first":  `window.exampleURL="https://main.example/value";`,
				"/second": `window.exampleURL="HTTPS://main.example/value";`,
			}
			calls := make(map[string]int)
			s := codexSRIServer(t, func(r *http.Request) (*http.Response, error) {
				if body, ok := originals[r.URL.Path]; ok {
					calls[r.URL.Path]++
					resp := codexSRIResponse("application/javascript", body)
					if mode == "no-store" {
						resp.Header.Set("Cache-Control", "no-store")
					}
					return resp, nil
				}
				return codexSRIResponse("text/html", codexSRIPage("/first", originals["/first"])+codexSRIPage("/second", originals["/second"])), nil
			})
			page := codexSRIRequest(s, "GET", "/", "", "")
			refs, _ := externalControlReferences(page.Body.Bytes())
			if len(refs) != 2 {
				t.Fatalf("references=%v body=%s", refs, page.Body.String())
			}
			refURL, err := url.Parse(refs[1].src)
			if err != nil {
				t.Fatal(err)
			}
			token := refURL.Query().Get("__blv")
			version, issued, found := s.versionRefs.VerifyAndLookup(token)
			if !issued || !found || !strings.Contains(version.BodyVersion, ".c") {
				t.Fatalf("collision representation not pinned: %+v", version)
			}
			if mode == "evicted" {
				// Evict body entries without deleting the independent version digest.
				for i := 0; i < 300; i++ {
					s.sriCache.Put(fmt.Sprintf("unrelated-%d", i), &sri.CacheEntry{})
				}
			}
			headers := make(http.Header)
			if mode == "request-no-cache" {
				headers.Set("Cache-Control", "no-cache")
			}
			response := codexCacheRequest(s, "GET", refURL.RequestURI(), headers)
			if response.Code != 200 {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			valid, _ := sri.Verify(response.Body.Bytes(), sri.ParseIntegrity(refs[1].integrity))
			if !valid {
				t.Errorf("refetched transformed bytes no longer match emitted integrity")
			}
			if calls["/second"] != 2 {
				t.Errorf("upstream second requests=%d want2", calls["/second"])
			}
			if response.Header().Get("Content-Length") != strconv.Itoa(response.Body.Len()) {
				t.Errorf("wrong actual response size")
			}
		})
	}
}
