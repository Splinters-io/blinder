package rewriter

import (
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
	"github.com/Splinters-io/blinder/internal/sri"
)

func sha384hash(data []byte) string {
	h := sha512.Sum384(data)
	return base64.StdEncoding.EncodeToString(h[:])
}

func sriTestSetup(t *testing.T, jsBody []byte, handler http.HandlerFunc) (*sri.Pipeline, *sri.Cache, *httptest.Server, *scrub.Gate, *OriginMapper) {
	t.Helper()
	srv := httptest.NewServer(handler)
	gate := scrub.NewGate([]string{"target.example.com"}, []string{"AcmeCorp"}, "target-001.local")
	origins := mustMapper(t,
		&url.URL{Scheme: "http", Host: srv.Listener.Addr().String()},
		"127.0.0.1:8099", "target-001.local",
	)
	cache := sri.NewCache(100)
	pipeline := sri.NewPipeline(sri.PipelineConfig{
		Transport: srv.Client().Transport,
		ScrubFn: func(body []byte, contentType, path string) []byte {
			return gate.ScrubBytes(body, "sri:"+path)
		},
		Cache: cache,
	})
	return pipeline, cache, srv, gate, origins
}

func TestSRIIntegration_ValidOriginalChangedBytes(t *testing.T) {
	jsBody := []byte(`var company = "AcmeCorp"; console.log(company);`)
	integrity := "sha384-" + sha384hash(jsBody)

	pipeline, cache, srv, gate, origins := sriTestSetup(t,jsBody, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(jsBody)
	})
	defer srv.Close()

	upstreamBase, _ := url.Parse("http://" + srv.Listener.Addr().String())
	htmlBody := []byte(`<html><script src="/bundle.js" integrity="` + integrity + `" crossorigin="anonymous"></script></html>`)
	baseReq := httptest.NewRequest("GET", "https://target-001.local:8099/", nil)

	result := RewriteBody(htmlBody, "text/html", "/", gate, false, RewriteOpts{
		Origins:      origins,
		SRIPipeline:  pipeline,
		UpstreamBase: upstreamBase,
		BaseRequest:  baseReq,
	})
	resultStr := string(result.Body)

	if strings.Contains(resultStr, integrity) {
		t.Error("original integrity should be replaced (content changed by scrubbing)")
	}
	if !strings.Contains(resultStr, `integrity="sha384-`) {
		t.Error("replacement integrity should be present")
	}
	if !strings.Contains(resultStr, `crossorigin="anonymous"`) {
		t.Error("crossorigin should be preserved")
	}

	cacheKey := sri.CacheKey(upstreamBase.String()+"/bundle.js", baseReq)
	entry, ok := cache.Get(cacheKey)
	if !ok {
		t.Fatal("resource should be cached after pipeline processing")
	}
	if entry.FetchError != "" {
		t.Errorf("cached entry should have no fetch error, got: %s", entry.FetchError)
	}
	if strings.Contains(string(entry.ScrubbedBody), "AcmeCorp") {
		t.Error("cached scrubbed body should not contain identity")
	}

	replacementEntries := sri.ParseIntegrity(entry.ReplacementHash)
	ok2, _ := sri.Verify(entry.ScrubbedBody, replacementEntries)
	if !ok2 {
		t.Error("replacement hash should verify against cached scrubbed bytes")
	}
}

func TestSRIIntegration_ValidOriginalUnchangedBytes(t *testing.T) {
	jsBody := []byte(`var x = 42; alert(x);`)
	integrity := "sha384-" + sha384hash(jsBody)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(jsBody)
	}))
	defer srv.Close()

	gate := scrub.NewGate(nil, nil, "target-001.local")
	origins := mustMapper(t,
		&url.URL{Scheme: "http", Host: srv.Listener.Addr().String()},
		"127.0.0.1:8099", "target-001.local",
	)
	cache := sri.NewCache(100)
	pipeline := sri.NewPipeline(sri.PipelineConfig{
		Transport: srv.Client().Transport,
		ScrubFn: func(body []byte, contentType, path string) []byte {
			return gate.ScrubBytes(body, "sri:"+path)
		},
		Cache: cache,
	})

	upstreamBase, _ := url.Parse("http://" + srv.Listener.Addr().String())
	htmlBody := []byte(`<html><script src="/data" integrity="` + integrity + `" crossorigin="anonymous"></script></html>`)
	baseReq := httptest.NewRequest("GET", "https://target-001.local:8099/", nil)

	result := RewriteBody(htmlBody, "text/html", "/", gate, false, RewriteOpts{
		Origins:      origins,
		SRIPipeline:  pipeline,
		UpstreamBase: upstreamBase,
		BaseRequest:  baseReq,
	})
	resultStr := string(result.Body)

	if !strings.Contains(resultStr, `integrity="`+integrity+`"`) {
		t.Errorf("original integrity should remain when bytes unchanged, got: %s", resultStr)
	}
}

func TestSRIIntegration_InvalidOriginalBlocked(t *testing.T) {
	realBody := []byte(`console.log("real");`)
	wrongIntegrity := "sha384-" + sha384hash([]byte("attacker controlled content"))

	pipeline, cache, srv, gate, origins := sriTestSetup(t,realBody, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(realBody)
	})
	defer srv.Close()

	upstreamBase, _ := url.Parse("http://" + srv.Listener.Addr().String())
	htmlBody := []byte(`<html><script src="/tampered.js" integrity="` + wrongIntegrity + `" crossorigin="anonymous"></script></html>`)
	baseReq := httptest.NewRequest("GET", "https://target-001.local:8099/", nil)

	result := RewriteBody(htmlBody, "text/html", "/", gate, false, RewriteOpts{
		Origins:      origins,
		SRIPipeline:  pipeline,
		UpstreamBase: upstreamBase,
		BaseRequest:  baseReq,
	})
	resultStr := string(result.Body)

	if strings.Contains(resultStr, `<script`) {
		t.Errorf("entire script element must be omitted for failed verification, got: %s", resultStr)
	}

	cacheKey := sri.CacheKey(upstreamBase.String()+"/tampered.js", baseReq)
	entry, ok := cache.Get(cacheKey)
	if !ok {
		t.Fatal("resource should still be cached after failed verification")
	}
	if entry.FetchError != "" {
		t.Errorf("fetch should succeed even if verification fails, got error: %s", entry.FetchError)
	}
	if len(entry.ScrubbedBody) == 0 {
		t.Error("cached entry should have scrubbed body (resource was fetched successfully)")
	}
}

func TestSRIIntegration_NoSRIPreserved(t *testing.T) {
	pipeline, _, srv, gate, origins := sriTestSetup(t,nil, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`var x = 1;`))
	})
	defer srv.Close()

	upstreamBase, _ := url.Parse("http://" + srv.Listener.Addr().String())
	htmlBody := []byte(`<html><script src="/plain.js"></script></html>`)
	baseReq := httptest.NewRequest("GET", "https://target-001.local:8099/", nil)

	result := RewriteBody(htmlBody, "text/html", "/", gate, false, RewriteOpts{
		Origins:      origins,
		SRIPipeline:  pipeline,
		UpstreamBase: upstreamBase,
		BaseRequest:  baseReq,
	})
	resultStr := string(result.Body)

	if strings.Contains(resultStr, "integrity") {
		t.Error("no integrity should be added when original has none")
	}
}

func TestSRIIntegration_ExternalCDNPreserved(t *testing.T) {
	pipeline, _, srv, gate, origins := sriTestSetup(t,nil, func(w http.ResponseWriter, r *http.Request) {})
	defer srv.Close()

	upstreamBase, _ := url.Parse("http://" + srv.Listener.Addr().String())
	htmlBody := []byte(`<html><script src="https://cdn.example.org/lib.js" integrity="sha384-externalHash" crossorigin="anonymous"></script></html>`)
	baseReq := httptest.NewRequest("GET", "https://target-001.local:8099/", nil)

	result := RewriteBody(htmlBody, "text/html", "/", gate, false, RewriteOpts{
		Origins:      origins,
		SRIPipeline:  pipeline,
		UpstreamBase: upstreamBase,
		BaseRequest:  baseReq,
	})
	resultStr := string(result.Body)

	if !strings.Contains(resultStr, `integrity="sha384-externalHash"`) {
		t.Error("external CDN integrity should be preserved unchanged")
	}
	if !strings.Contains(resultStr, `crossorigin="anonymous"`) {
		t.Error("external CDN crossorigin should be preserved")
	}
}

func TestSRIIntegration_LinkStylesheet(t *testing.T) {
	cssBody := []byte(`body { color: red; font-family: "AcmeCorp Sans"; }`)
	integrity := "sha384-" + sha384hash(cssBody)

	pipeline, _, srv, gate, origins := sriTestSetup(t,cssBody, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Write(cssBody)
	})
	defer srv.Close()

	upstreamBase, _ := url.Parse("http://" + srv.Listener.Addr().String())
	htmlBody := []byte(`<html><link rel="stylesheet" href="/style.css" integrity="` + integrity + `" crossorigin="anonymous"></html>`)
	baseReq := httptest.NewRequest("GET", "https://target-001.local:8099/", nil)

	result := RewriteBody(htmlBody, "text/html", "/", gate, false, RewriteOpts{
		Origins:      origins,
		SRIPipeline:  pipeline,
		UpstreamBase: upstreamBase,
		BaseRequest:  baseReq,
	})
	resultStr := string(result.Body)

	if strings.Contains(resultStr, integrity) {
		t.Error("link stylesheet integrity should be replaced (CSS was scrubbed)")
	}
	if !strings.Contains(resultStr, `integrity="sha384-`) {
		t.Error("replacement integrity should be present on link")
	}
}

func TestSRIIntegration_FindingsRecorded(t *testing.T) {
	jsBody := []byte(`var org = "AcmeCorp";`)
	integrity := "sha384-" + sha384hash(jsBody)

	pipeline, _, srv, gate, origins := sriTestSetup(t,jsBody, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(jsBody)
	})
	defer srv.Close()

	upstreamBase, _ := url.Parse("http://" + srv.Listener.Addr().String())
	htmlBody := []byte(`<html><script src="/app.js" integrity="` + integrity + `"></script></html>`)
	baseReq := httptest.NewRequest("GET", "https://target-001.local:8099/", nil)

	RewriteBody(htmlBody, "text/html", "/", gate, false, RewriteOpts{
		Origins:      origins,
		SRIPipeline:  pipeline,
		UpstreamBase: upstreamBase,
		BaseRequest:  baseReq,
	})

	findings := pipeline.Findings()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !findings[0].UpstreamValid {
		t.Error("finding should show upstream valid")
	}
	if findings[0].OriginalIntegrity != integrity {
		t.Error("finding should record original integrity")
	}
	if findings[0].ReplacementHash == "" {
		t.Error("finding should record replacement hash")
	}
}

func TestSRIIntegration_NoPipelineFallsBackToStrip(t *testing.T) {
	gate := newTestGate()
	origins := mustMapper(t,
		&url.URL{Scheme: "https", Host: "target.example.com"},
		"127.0.0.1:8099", "target-001.local",
	)

	htmlBody := []byte(`<html><script src="/bundle.js" integrity="sha384-abc" crossorigin="anonymous"></script></html>`)
	result := RewriteBody(htmlBody, "text/html", "/", gate, false, RewriteOpts{Origins: origins})
	resultStr := string(result.Body)

	if strings.Contains(resultStr, "integrity") {
		t.Error("without SRI pipeline, integrity should be stripped for proxied resources")
	}
	if strings.Contains(resultStr, "crossorigin") {
		t.Error("without SRI pipeline, crossorigin should be stripped for proxied resources")
	}
}
