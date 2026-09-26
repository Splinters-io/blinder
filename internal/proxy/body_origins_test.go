package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/cache"
	"github.com/Splinters-io/blinder/internal/sri"
	"golang.org/x/net/html"
)

func TestBodyOriginResponseCacheIsolation(t *testing.T) {
	calls := 0
	s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
		calls++
		response := audit267CacheResponse(`window.endpoint="https://main.example/account/data";window.asset="https://assets.example/theme";`)
		response.Header.Set("Content-Type", "application/javascript")
		return response, nil
	}, "https://assets.example")
	extra := s.origins.RewriteUpstreamURL("https://assets.example/theme")
	etags := map[string]string{}
	for _, host := range []string{"127.0.0.1:18099", "localhost:18099", "127.0.0.1:18099", "localhost:18099"} {
		req := httptest.NewRequest("GET", "https://"+host+"/script", nil)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "https://"+host+"/account/data") || !strings.Contains(w.Body.String(), extra) {
			t.Fatalf("host %s: status=%d body=%s", host, w.Code, w.Body.String())
		}
		if got := w.Header().Get("ETag"); got != cache.ComputeETag(w.Body.Bytes()) {
			t.Fatalf("ETag does not describe emitted bytes: %q", got)
		}
		etags[host] = w.Header().Get("ETag")
	}
	if calls != 2 {
		t.Fatalf("separate representations should each be cached, calls=%d", calls)
	}
	if etags["127.0.0.1:18099"] == etags["localhost:18099"] {
		t.Fatal("authority-dependent bodies share an ETag")
	}
	for _, matchOwn := range []bool{false, true} {
		r := httptest.NewRequest("GET", "https://localhost:18099/script", nil)
		r.Header.Set("If-None-Match", etags["127.0.0.1:18099"])
		want := 200
		if matchOwn {
			r.Header.Set("If-None-Match", etags["localhost:18099"])
			want = 304
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("own=%v status=%d want=%d", matchOwn, w.Code, want)
		}
	}
	for _, host := range []string{"unknown.invalid:18099", "127.0.0.1:18098"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", "https://"+host+"/script", nil))
		if w.Code != 421 {
			t.Fatalf("untrusted host %q status=%d", host, w.Code)
		}
	}
	if calls != 2 {
		t.Fatalf("conditional/unknown-host requests reached upstream: %d", calls)
	}
	// A successful write invalidates every entry-authority representation.
	write := httptest.NewRecorder()
	s.ServeHTTP(write, httptest.NewRequest("PATCH", "https://127.0.0.1:18099/script", nil))
	for _, host := range []string{"127.0.0.1:18099", "localhost:18099"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", "https://"+host+"/script", nil))
		if w.Code != 200 {
			t.Fatalf("after write: %d", w.Code)
		}
	}
	if calls != 5 {
		t.Fatalf("write left a cached representation, calls=%d", calls)
	}
}

func TestBodyOriginSRIBytesAndCredentialsFollowResourceAuthority(t *testing.T) {
	const script = `window.endpoint="https://main.example/account/data";window.asset="https://assets.example/theme";`
	resourceCalls := map[string]int{}
	s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/account/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("https://main.example/account/script", script)+audit267SRIPage("https://assets.example/account/script", script)), nil
		}
		if r.URL.Path != "/account/script" {
			t.Fatalf("resource path changed: %s", r.URL)
		}
		resourceCalls[r.URL.Host]++
		wantCookie := ""
		if r.URL.Host == "main.example" {
			wantCookie = "session=path-scoped"
		}
		if r.Header.Get("Cookie") != wantCookie {
			t.Fatalf("resource %s Cookie=%q want=%q", r.URL, r.Header.Get("Cookie"), wantCookie)
		}
		return audit267SRIResponse("application/javascript", script), nil
	}, "https://assets.example")
	extraURL, _ := url.Parse(s.origins.RewriteUpstreamURL("https://assets.example/account/script"))
	for _, entryHost := range []string{"127.0.0.1:18099", "localhost:18099"} {
		pageReq := httptest.NewRequest("GET", "https://"+entryHost+"/account/page", nil)
		pageReq.Header.Set("Cookie", "session=path-scoped")
		page := httptest.NewRecorder()
		s.ServeHTTP(page, pageReq)
		if page.Code != 200 {
			t.Fatalf("page: %d %s", page.Code, page.Body.String())
		}
		tags := bodyOriginScripts(page.Body.String())
		if len(tags) != 2 {
			t.Fatalf("lost SRI references: %s", page.Body.String())
		}
		for i, attrs := range tags {
			resource, err := url.Parse(attrs["src"])
			if err != nil {
				t.Fatal(err)
			}
			wantHost := entryHost
			if i == 1 {
				wantHost = extraURL.Host
			}
			if resource.Host != wantHost || resource.Path != "/account/script" || resource.Query().Get("__blv") == "" {
				t.Fatalf("resource route/path/version: %s", resource)
			}
			for _, noCache := range []bool{false, true} {
				r := httptest.NewRequest("GET", resource.String(), nil)
				if i == 0 {
					r.Header.Set("Cookie", "session=path-scoped")
				}
				if noCache {
					r.Header.Set("Cache-Control", "no-cache")
				}
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatalf("resource no-cache=%v: %d %s", noCache, w.Code, w.Body.String())
				}
				if got := sri.ComputeIntegrity(w.Body.Bytes(), "sha384"); got != attrs["integrity"] {
					t.Fatalf("SRI not tied to served bytes (host=%s no-cache=%v): %s want=%s body=%s", entryHost, noCache, got, attrs["integrity"], w.Body.String())
				}
				if got := w.Header().Get("ETag"); got != cache.ComputeETag(w.Body.Bytes()) {
					t.Fatalf("resource ETag=%s", got)
				}
				wantEndpoint := "https://" + entryHost + "/account/data"
				if i == 1 {
					wantEndpoint = s.origins.RewriteUpstreamURL("https://main.example/account/data")
				}
				if !strings.Contains(w.Body.String(), wantEndpoint) {
					t.Fatalf("resource route mapping: %s want=%s", w.Body.String(), wantEndpoint)
				}
			}
		}
	}
	if resourceCalls["main.example"] != 4 || resourceCalls["assets.example"] != 3 {
		t.Fatalf("prefetch/cache/no-cache isolation: %v", resourceCalls)
	}
}

func bodyOriginScripts(body string) []map[string]string {
	var scripts []map[string]string
	z := html.NewTokenizer(strings.NewReader(body))
	for z.Next() != html.ErrorToken {
		token := z.Token()
		if token.Data != "script" || len(token.Attr) == 0 {
			continue
		}
		attrs := map[string]string{}
		for _, attr := range token.Attr {
			attrs[attr.Key] = attr.Val
		}
		scripts = append(scripts, attrs)
	}
	return scripts
}

func TestBodyOriginCSPCacheAndRevalidation(t *testing.T) {
	calls := 0
	s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
		calls++
		response := audit267CacheResponse(`window.endpoint="https://main.example/data";`)
		response.Header.Set("Content-Type", "application/javascript")
		response.Header.Set("ETag", `"upstream-version"`)
		response.Header.Set("Cache-Control", "max-age=0")
		path := "/initial/"
		if r.Header.Get("If-None-Match") != "" {
			response.StatusCode = http.StatusNotModified
			response.Header.Set("Cache-Control", "max-age=600")
			path = "/updated/"
		}
		response.Header.Set("Content-Security-Policy", "default-src 'none'; script-src https://main.example"+path+" 'nonce-YWJj'; connect-src wss://main.example/socket https://assets.example/data")
		return response, nil
	}, "https://assets.example")
	for _, host := range []string{"127.0.0.1:18099", "localhost:18099"} {
		etag := ""
		for step := 0; step < 3; step++ {
			r := httptest.NewRequest("GET", "https://"+host+"/script", nil)
			if step == 2 {
				r.Header.Set("If-None-Match", etag)
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			wantStatus := 200
			if step == 2 {
				wantStatus = 304
			}
			path := "/initial/"
			if step > 0 {
				path = "/updated/"
			}
			wantPolicy := "default-src 'none'; script-src https://" + host + path + " 'nonce-YWJj'; connect-src wss://" + host + "/socket " + s.origins.RewriteUpstreamURL("https://assets.example/data")
			if w.Code != wantStatus || w.Header().Get("Content-Security-Policy") != wantPolicy {
				t.Fatalf("host=%s step=%d status=%d policy=%q want=%q", host, step, w.Code, w.Header().Get("Content-Security-Policy"), wantPolicy)
			}
			etag = w.Header().Get("ETag")
		}
	}
	if calls != 4 {
		t.Fatalf("expected independent initial/revalidation pairs then cache hits; upstream calls=%d", calls)
	}
}
