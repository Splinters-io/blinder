package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiagnosticPreservedInHTTP200HTML(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		retained []string
	}{
		{
			"sql_error_in_div",
			`<html><body><div>SQLSTATE[42000]: query failed at character 17</div></body></html>`,
			[]string{"SQLSTATE[42000]", "query failed at character 17"},
		},
		{
			"stack_trace_in_p",
			`<html><body><p>Fatal error: Uncaught TypeError in /app/handler.php on line 42</p></body></html>`,
			[]string{"Fatal error:", "TypeError", "line 42"},
		},
		{
			"access_denied_in_span",
			`<html><body><span>Access denied for user 'admin'@'localhost'</span></body></html>`,
			[]string{"Access denied"},
		},
		{
			"reflected_xss_in_div",
			`<html><body><div>Search results for: <script>alert(1)</script></div></body></html>`,
			[]string{"<script>alert(1)</script>"},
		},
		{
			"java_exception_in_p",
			`<html><body><p>java.lang.NullPointerException at com.app.Service.handle(Service.java:42)</p></body></html>`,
			[]string{" at ", "(", ":42)"},
		},
		{
			"permission_denied",
			`<html><body><div>Permission denied: you do not have permission to access this resource</div></body></html>`,
			[]string{"Permission denied", "you do not have permission"},
		},
		{
			"go_panic",
			`<html><body><div>panic: runtime error: index out of range [5] with length 3</div></body></html>`,
			[]string{"panic:", "index out of range"},
		},
		{
			"session_expired",
			`<html><body><div>Your session expired. Please log in again.</div></body></html>`,
			[]string{"session expired"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(200)
				io.WriteString(w, tc.body)
			}))
			defer target.Close()
			s := mappingReviewEphemeralServer(t, target.URL, []string{"AcmeCorp"}, nil)
			s.cfg.Paranoid = true
			defer s.transport.(*http.Transport).CloseIdleConnections()
			response := audit267CacheRequest(s, "GET", "/fixture", nil)
			body := response.Body.String()
			if response.Code != 200 {
				t.Fatalf("status changed: %d", response.Code)
			}
			for _, retained := range tc.retained {
				if !strings.Contains(body, retained) {
					t.Errorf("lost diagnostic %q in 200 response:\n%s", retained, body)
				}
			}
		})
	}
}

func TestDiagnostic200StillScrubsIdentity(t *testing.T) {
	const page = `<html><body><div>SQLSTATE[42000]: AcmeCorp query failed at character 17</div></body></html>`
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		io.WriteString(w, page)
	}))
	defer target.Close()
	s := mappingReviewEphemeralServer(t, target.URL, []string{"AcmeCorp"}, nil)
	s.cfg.Paranoid = true
	defer s.transport.(*http.Transport).CloseIdleConnections()
	response := audit267CacheRequest(s, "GET", "/fixture", nil)
	body := response.Body.String()
	if strings.Contains(strings.ToLower(body), "acmecorp") {
		t.Fatalf("identity leaked through diagnostic preservation: %s", body)
	}
	if !strings.Contains(body, "SQLSTATE[42000]") {
		t.Fatalf("diagnostic was destroyed: %s", body)
	}
	if !strings.Contains(body, "query failed at character 17") {
		t.Fatalf("diagnostic detail was destroyed: %s", body)
	}
}

func TestOrdinaryProseStillReplacedIn200(t *testing.T) {
	const page = `<html><body><p>Welcome to our wonderful platform where you can manage your account and explore features.</p></body></html>`
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		io.WriteString(w, page)
	}))
	defer target.Close()
	s := mappingReviewEphemeralServer(t, target.URL, []string{"AcmeCorp"}, nil)
	s.cfg.Paranoid = true
	defer s.transport.(*http.Transport).CloseIdleConnections()
	response := audit267CacheRequest(s, "GET", "/fixture", nil)
	body := response.Body.String()
	if strings.Contains(body, "Welcome to our wonderful platform") {
		t.Fatalf("ordinary prose was not replaced: %s", body)
	}
}
