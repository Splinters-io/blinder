package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPathFidelityHTTPRestoresIssuedThemeSegment(t *testing.T) {
	const want = "/wp-content/themes/AcmeCorp/assets/script"
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.RequestURI
		w.Header().Set("Content-Type", "text/plain")
		if r.RequestURI != want {
			http.Error(w, "asset not found", http.StatusNotFound)
			return
		}
		io.WriteString(w, "asset")
	}))
	defer upstream.Close()
	s := mappingReviewServer(t, upstream.URL, []string{"AcmeCorp"}, nil)
	mirror := formFidelityMirror(t, s)
	alias := s.gate.Scrub("AcmeCorp", "path-fixture")
	response, err := mirror.Client().Get(mirror.URL + "/wp-content/themes/" + url.PathEscape(alias) + "/assets/script")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if uri := <-seen; uri != want || response.StatusCode != http.StatusOK {
		t.Fatalf("issued theme alias reached the real upstream: status=%d URI=%q; want=%q", response.StatusCode, uri, want)
	}
}

func TestPathFidelityHTTPPreservesEscapedSegmentsAndQuery(t *testing.T) {
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.RequestURI
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	s := mappingReviewServer(t, upstream.URL, []string{"AcmeCorp", "segment/name", "name?part#fragment"}, nil)
	mirror := formFidelityMirror(t, s)
	alias := url.PathEscape(s.gate.Scrub("AcmeCorp", "path-fixture"))
	slashAlias := url.PathEscape(s.gate.Scrub("segment/name", "path-fixture"))
	reservedAlias := url.PathEscape(s.gate.Scrub("name?part#fragment", "path-fixture"))
	fileAlias := s.gate.Scrub("asset.js", "path-fixture")
	for _, tc := range []struct{ name, input, want string }{
		{"untouched_escape_spelling", "/a%2fb/" + alias + "/%7euser?first=a+b&first=a%20b&bare&&", "/a%2fb/AcmeCorp/%7euser?first=a+b&first=a%20b&bare&&"},
		{"slash_remains_segment_data", "/socket/" + slashAlias, "/socket/segment%2Fname"},
		{"reserved_data_is_not_query_or_fragment", "/socket/" + reservedAlias + "?keep=value", "/socket/name%3Fpart%23fragment?keep=value"},
		{"empty_query_marker", "/" + alias + "?", "/AcmeCorp?"},
		{"unknown_alias_and_domain_filename", "/" + alias + "/%5BREDACTED%3Aunknown%5D/" + fileAlias, "/AcmeCorp/%5BREDACTED%3Aunknown%5D/asset.js"},
		{"unchanged_encoded_slash", "/a%2fb/%7euser?keep=%2f", "/a%2fb/%7euser?keep=%2f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response, err := mirror.Client().Get(mirror.URL + tc.input)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if uri := <-seen; uri != tc.want || response.StatusCode != http.StatusOK {
				t.Fatalf("path restoration changed source semantics: status=%d URI=%q; want=%q", response.StatusCode, uri, tc.want)
			}
		})
	}
}

func TestPathFidelityRestoredPathSharesResponseCache(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.EscapedPath() != "/assets/AcmeCorp" {
			http.Error(w, "asset not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "public, max-age=60")
		io.WriteString(w, "asset")
	}))
	defer upstream.Close()
	s := mappingReviewServer(t, upstream.URL, []string{"AcmeCorp"}, nil)
	mirror := formFidelityMirror(t, s)
	alias := s.gate.Scrub("AcmeCorp", "path-fixture")
	for _, path := range []string{"/assets/" + url.PathEscape(alias), "/assets/AcmeCorp"} {
		response, err := mirror.Client().Get(mirror.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "asset" {
			t.Fatalf("path/cache request failed: %s status=%d body=%q error=%v", path, response.StatusCode, body, readErr)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("restored and original path used different cache identities: %d upstream calls", calls.Load())
	}
}

func TestPathFidelityIssuedSRIReferenceUsesRestoredEscapedPath(t *testing.T) {
	for _, assetPath := range []string{"/assets/AcmeCorp", "/assets/AcmeCorp%3Fpart%23fragment", "/a%2fb/AcmeCorp"} {
		t.Run(assetPath, func(t *testing.T) {
			const asset = "const value = 7;"
			const cookie = "sid=path-session"
			seen := make(chan string, 4)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/page" {
					w.Header().Set("Content-Type", "text/html")
					io.WriteString(w, audit267SRIPage(assetPath, asset))
					return
				}
				seen <- r.RequestURI
				if r.RequestURI != assetPath || r.Header.Get("Cookie") != cookie {
					http.Error(w, "wrong path or credentials", http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/javascript")
				w.Header().Set("Cache-Control", "no-store")
				io.WriteString(w, asset)
			}))
			defer upstream.Close()
			s := mappingReviewServer(t, upstream.URL, []string{"AcmeCorp"}, nil)
			mirror := formFidelityMirror(t, s)
			get := func(path string) (int, string) {
				t.Helper()
				req, err := http.NewRequest(http.MethodGet, mirror.URL+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Cookie", cookie)
				response, err := mirror.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				return response.StatusCode, string(body)
			}
			status, page := get("/page")
			src := audit267SRIAttribute(page, "src")
			resource, err := url.Parse(src)
			if status != http.StatusOK || err != nil || resource.Query().Get("__blv") == "" || strings.Contains(src, "AcmeCorp") {
				t.Fatalf("fixture did not issue an aliased version reference: status=%d src=%q error=%v", status, src, err)
			}
			status, body := get(resource.RequestURI())
			if status != http.StatusOK || body != asset {
				t.Fatalf("matching restored SRI path rejected: src=%q status=%d body=%q", src, status, body)
			}
			if len(seen) != 2 {
				t.Fatalf("expected prefetch and no-store refetch; upstream attempts=%d", len(seen))
			}
			for len(seen) > 0 {
				if uri := <-seen; uri != assetPath {
					t.Fatalf("versioned resource used different source path: %q; want=%q", uri, assetPath)
				}
			}
			// Path restoration must not turn an authentic token into a route
			// override for a different incoming resource.
			status, _ = get("/different?__blv=" + url.QueryEscape(resource.Query().Get("__blv")))
			if status < 400 || len(seen) != 0 {
				t.Fatalf("issued token retargeted another path: status=%d upstream attempts=%d", status, len(seen))
			}
		})
	}
}
