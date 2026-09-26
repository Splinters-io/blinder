package proxy

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestBodySizeTitleOnlyResponseMatchesEmittedBytes(t *testing.T) {
	for _, original := range []string{`<title>X</title>`, `<title>AcmeCorp café &amp; 日本語</title>`, `<title>` + strings.Repeat("Long title ", 30) + `</title>`, `<title>AcmeCorp`} {
		s := mappingReviewServer(t, "https://main.example", []string{"AcmeCorp"}, func(r *http.Request) (*http.Response, error) { return audit267SRIResponse("text/html", original), nil })
		s.cfg.Paranoid = true
		got := audit267CacheRequest(s, "GET", "/title", nil)
		if got.Code != 200 || got.Body.Len() != len(original) || got.Header().Get("Content-Length") != strconv.Itoa(len(original)) || got.Header().Get("X-Blinder-Body-Size-Match") != "exact" || strings.Contains(got.Body.String(), "AcmeCorp") {
			t.Fatalf("actual response does not match original length: %d -> %d %v", len(original), got.Body.Len(), got.Header())
		}
	}
}

func TestBodySizeQuotedAttributePreservesOriginalBytes(t *testing.T) {
	const original = `<INPUT DISABLED data-note='BrandToken' keep="&#39;">`
	s := mappingReviewServer(t, "https://main.example", []string{"BrandToken"}, func(r *http.Request) (*http.Response, error) { return audit267SRIResponse("text/html", original), nil })
	s.cfg.Paranoid = true
	got := audit267CacheRequest(s, "GET", "/attribute", nil)
	body := got.Body.String()
	if got.Code != 200 || len(body) != len(original) || got.Header().Get("Content-Length") != strconv.Itoa(len(original)) || got.Header().Get("X-Blinder-Body-Size-Match") != "exact" {
		t.Fatalf("actual response expanded: %d -> %d %v", len(original), len(body), got.Header())
	}
	if strings.Contains(body, "BrandToken") || !strings.HasPrefix(body, "<INPUT DISABLED data-note='") || !strings.HasSuffix(body, `' keep="&#39;">`) {
		t.Fatalf("untouched structure/escaping changed: %s", body)
	}
}
