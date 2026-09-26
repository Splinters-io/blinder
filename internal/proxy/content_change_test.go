package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const originalTagHeader = "X-Blinder-Original-Body-Tag"

func TestContentChangeEqualSizeEvidence(t *testing.T) {
	// These synthetic 200 responses differ only in text, as can happen with
	// boolean/query-result tests or included content. No error marker exists.
	bodies := []string{"<p>The result is the first synthetic record.</p>", "<p>The result is the other synthetic record.</p>"}
	if len(bodies[0]) != len(bodies[1]) {
		t.Fatal("fixture lengths differ")
	}
	current := 0
	s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
		response := audit267SRIResponse("text/html", bodies[current])
		response.Header.Set("Cache-Control", "no-store")
		response.Header.Set(originalTagHeader, "forged-upstream-tag")
		return response, nil
	})
	s.cfg.Paranoid = true
	var tags, views []string
	for _, index := range []int{0, 1, 0} {
		current = index
		got := audit267CacheRequest(s, "GET", "/result", nil)
		tag := got.Header().Get(originalTagHeader)
		digest := sha256.Sum256([]byte(bodies[index]))
		if got.Code != 200 || tag != s.gate.ContentTag([]byte(bodies[index])) || tag == hex.EncodeToString(digest[:]) {
			t.Fatalf("untrusted/public/missing tag: status=%d tag=%q", got.Code, tag)
		}
		if got.Body.Len() != len(bodies[index]) || strings.Contains(got.Body.String(), "synthetic record") {
			t.Fatalf("masking/byte budget changed: %s", got.Body.String())
		}
		if lastResponseMetrics(t, s).OriginalBodyTag != tag {
			t.Fatal("manifest lost original equality signal")
		}
		tags = append(tags, tag)
		views = append(views, got.Body.String())
	}
	if tags[0] == tags[1] || views[0] == views[1] {
		t.Fatal("equal-length changed originals collapsed")
	}
	if tags[0] != tags[2] || views[0] != views[2] {
		t.Fatal("unchanged original gained artificial variation")
	}
}

func TestContentChangeShortBodyTag(t *testing.T) {
	// Short visible filler has finite capacity. Search synthetic Unicode
	// originals with the same UTF-8 length for an actual output collision,
	// then require the independent original tag to distinguish them.
	current := ""
	s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
		response := audit267SRIResponse("text/html", current)
		response.Header.Set("Cache-Control", "no-store")
		return response, nil
	})
	s.cfg.Paranoid = true
	seen := map[string]string{}
	for ch := rune(0x100); ch < 0x800; ch++ {
		current = "<title>" + string(ch) + "</title>"
		got := audit267CacheRequest(s, "GET", "/", nil)
		view, tag := got.Body.String(), got.Header().Get(originalTagHeader)
		if tag == "" {
			t.Fatal("missing original tag")
		}
		if prior, ok := seen[view]; ok {
			if prior == tag {
				t.Fatal("filler collision also erased original change signal")
			}
			return
		}
		seen[view] = tag
	}
	t.Fatal("fixture did not find a short-output collision")
}

func TestContentChangeTagCacheHeadAndRevalidation(t *testing.T) {
	calls := 0
	const original = `{"result":"synthetic value"}`
	s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("If-None-Match") != "" {
			response := audit267CacheResponse("")
			response.StatusCode = 304
			response.Header.Set(originalTagHeader, "forged-revalidation")
			return response, nil
		}
		response := audit267CacheResponse(original)
		response.Header.Set("Content-Type", "application/json")
		response.Header.Set("ETag", `"upstream"`)
		return response, nil
	})
	first := audit267CacheRequest(s, "GET", "/data", nil)
	tag := first.Header().Get(originalTagHeader)
	for _, tc := range []struct {
		method  string
		headers http.Header
		status  int
	}{
		{"GET", nil, 200}, {"HEAD", nil, 200},
		{"GET", http.Header{"If-None-Match": {first.Header().Get("ETag")}}, 304},
		{"GET", http.Header{"Cache-Control": {"no-cache"}}, 200},
		{"GET", http.Header{"Cache-Control": {"no-cache"}, "If-None-Match": {first.Header().Get("ETag")}}, 304},
	} {
		got := audit267CacheRequest(s, tc.method, "/data", tc.headers)
		if tag == "" || got.Header().Get(originalTagHeader) != tag || got.Code != tc.status || lastResponseMetrics(t, s).OriginalBodyTag != tag {
			t.Fatalf("lost cached source tag: %s %d %v", tc.method, got.Code, got.Header())
		}
	}
	if calls != 3 {
		t.Fatalf("cache/revalidation paths not exercised: calls=%d", calls)
	}
}

func TestContentChangeUnknownBodiesHaveNoTag(t *testing.T) {
	for _, scenario := range []string{"head", "transport", "not-modified"} {
		t.Run(scenario, func(t *testing.T) {
			s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
				if scenario == "transport" {
					return nil, errors.New("synthetic disconnect")
				}
				response := audit267SRIResponse("text/plain", "")
				response.Header.Set(originalTagHeader, "upstream-forgery")
				if scenario == "not-modified" {
					response.StatusCode = 304
				}
				return response, nil
			})
			method := "GET"
			if scenario == "head" {
				method = "HEAD"
			}
			got := audit267CacheRequest(s, method, "/unknown", nil)
			if got.Header().Get(originalTagHeader) != "" || lastResponseMetrics(t, s).OriginalBodyTag != "" {
				t.Fatal("invented a tag for unavailable original bytes")
			}
		})
	}
}

func TestContentChangeSRIPrefetchTag(t *testing.T) {
	const script = `window.label = "AcmeCorp";`
	calls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resource" {
			calls++
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, script)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<script src="/resource" integrity="sha256-%s"></script>`, sha256b64([]byte(script)))
	}))
	defer target.Close()
	s := mappingReviewServer(t, target.URL, []string{"AcmeCorp"}, nil)
	defer s.transport.(*http.Transport).CloseIdleConnections()
	if page := audit267CacheRequest(s, "GET", "/", nil); page.Code != 200 {
		t.Fatal(page.Code)
	}
	resource := audit267CacheRequest(s, "GET", "/resource", nil)
	tag := s.gate.ContentTag([]byte(script))
	if resource.Code != 200 || resource.Header().Get(originalTagHeader) != tag || strings.Contains(resource.Body.String(), "AcmeCorp") || lastResponseMetrics(t, s).Source != "sri-cache" {
		t.Fatalf("SRI tag/rewritten representation lost: %d %v %s", resource.Code, resource.Header(), resource.Body.String())
	}
	conditional := audit267CacheRequest(s, "GET", "/resource", http.Header{"If-None-Match": {resource.Header().Get("ETag")}})
	if conditional.Code != 304 || conditional.Header().Get(originalTagHeader) != tag || calls != 1 {
		t.Fatalf("SRI conditional lost original identity: %d %v calls=%d", conditional.Code, conditional.Header(), calls)
	}
}
