package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Check the emitted representation, not just the alias allocator: old builds
// also invented title/image labels independently of functional value aliases.
func TestContentContractGeneratedResponsesUseNeutralContent(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body string
		status                  int
		retained                []string
	}{
		{"page", "text/html", `<title>AcmeCorp Portal</title><p>Welcome to AcmeCorp and the ordinary page content.</p><img src="/icon" alt="AcmeCorp logo"><button aria-label="AcmeCorp account" title="AcmeCorp settings">Account</button><input name="company" value="AcmeCorp">`, 200, []string{`src="/icon"`, `name="company"`, "aria-label=", "title="}},
		{"json", "application/json", `{"company":"AcmeCorp","number":9007199254740993,"ok":false}`, 200, []string{`"number":9007199254740993`, `"ok":false`}},
		{"script", "application/javascript", `window.company="AcmeCorp";window.count=42;`, 200, []string{"window.company=", "window.count=42;"}},
		{"style", "text/css", `.notice:after { content: "AcmeCorp"; color: red; }`, 200, []string{".notice:after", "color: red;"}},
		{"error", "text/html", `<title>AcmeCorp failure</title><pre>SQLSTATE[42000]: AcmeCorp query failed at character 17</pre>`, 503, []string{"SQLSTATE[42000]", "query failed at character 17"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("X-Diagnostic", "AcmeCorp E_INPUT 17")
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer target.Close()
			s := mappingReviewEphemeralServer(t, target.URL, []string{"AcmeCorp"}, nil)
			s.cfg.Paranoid = true
			defer s.transport.(*http.Transport).CloseIdleConnections()
			response := audit267CacheRequest(s, "GET", "/fixture", nil)
			body := response.Body.String()
			if response.Code != tc.status || response.Header().Get("Content-Length") != strconv.Itoa(len(body)) {
				t.Fatalf("status or actual body length changed: status=%d length=%s bytes=%d", response.Code, response.Header().Get("Content-Length"), len(body))
			}
			if response.Header().Get("X-Blinder-View") != "transformed" {
				t.Fatal("neutral content lost explicit transformation provenance")
			}
			generated := strings.ToLower(body + response.Header().Get("X-Diagnostic"))
			for _, unwanted := range []string{"acmecorp", "redacted", "[removed]", "[image]", "title removed", "content hidden"} {
				if strings.Contains(generated, unwanted) {
					t.Fatalf("emitted fixture contains identity or invented removal label %q", unwanted)
				}
			}
			for _, retained := range tc.retained {
				if !strings.Contains(body, retained) {
					t.Fatalf("lost application structure/diagnostic %q: %s", retained, body)
				}
			}
			if got := s.gate.RestoreBody(response.Header().Get("X-Diagnostic")); got != "AcmeCorp E_INPUT 17" {
				t.Fatalf("diagnostic value is no longer reversible: %q", got)
			}
			if tc.name == "json" || tc.name == "error" {
				if len(body) != len(tc.body) || s.gate.RestoreBody(body) != tc.body {
					t.Fatal("functional/diagnostic source lost its byte budget or reversible values")
				}
			}
		})
	}
}

// A response-wide blacklist would satisfy the first test by destroying real
// evidence. The contract forbids invented labels, not upstream application text.
func TestContentContractPreservesLiteralRemovalWordsInEvidence(t *testing.T) {
	const original = `<title>record removed</title><pre>SQLSTATE[42000]: AcmeCorp returned [REDACTED], content hidden, [image]</pre>`
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, original)
	}))
	defer target.Close()
	s := mappingReviewEphemeralServer(t, target.URL, []string{"AcmeCorp"}, nil)
	s.cfg.Paranoid = true
	defer s.transport.(*http.Transport).CloseIdleConnections()
	response := audit267CacheRequest(s, "GET", "/fixture", nil)
	body := response.Body.String()
	if response.Code != 503 || strings.Contains(body, "AcmeCorp") || s.gate.RestoreBody(body) != original || len(body) != len(original) {
		t.Fatalf("literal application evidence changed: status=%d body=%q", response.Code, body)
	}
}
