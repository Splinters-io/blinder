package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// Local form/validation acceptance. No external service or live CAPTCHA.
func TestResponseFidelityBrowser(t *testing.T) {
	if os.Getenv("BLINDER_REVIEW_BROWSER") != "1" {
		t.Skip("requires local browser")
	}
	const errorBody = `<!doctype html><title>Validation result</title><h1>Validation failed</h1><div role="alert">AcmeCorp: E_EMAIL — enter a valid email address.</div><pre>field=email; supplied=café; retryable=true</pre><form action="/" method="GET"><input type="submit" value="Try again"></form>`
	const formBody = `<!doctype html><title>Local validation fixture</title><p>Ordinary prose with room for a short verse and some quiet reflection.</p><form action="/validate" method="POST"><input name="email" aria-label="Email" value="café"><textarea name="message" aria-label="Message">AcmeCorp &amp; café</textarea><select name="choice" aria-label="Choice"><option>AcmeCorp &amp; café</option></select><input type="submit" value="Validate"></form>`
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/validate" && r.Method == "POST" {
			r.ParseForm()
			if r.Form.Get("email") != "café" {
				t.Errorf("form value changed: %q", r.Form.Get("email"))
			}
			for _, field := range []string{"message", "choice"} {
				if r.Form.Get(field) != "AcmeCorp & café" {
					t.Errorf("%s form value changed: %q", field, r.Form.Get(field))
				}
			}
			w.WriteHeader(422)
			io.WriteString(w, errorBody)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, formBody)
	}))
	defer target.Close()
	s := mappingReviewEphemeralServer(t, target.URL, []string{"AcmeCorp"}, nil)
	s.cfg.Paranoid = true
	defer s.transport.(*http.Transport).CloseIdleConnections()
	cleanup := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/review-cleanup", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Validation fixture complete")
		select {
		case cleanup <- struct{}{}:
		default:
		}
	})
	mux.Handle("/", s)
	server := httptest.NewServer(mux)
	defer server.Close()
	if err := os.WriteFile("/private/tmp/blinder-response-browser-url.txt", []byte(server.URL), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cleanup:
	case <-time.After(100 * time.Second):
		t.Fatal("browser did not complete validation fixture")
	}
	var found, foundPage bool
	for _, entry := range s.Manifest().Requests() {
		if entry.Path == "/" && entry.StatusCode == 200 {
			foundPage = true
			m := entry.Response
			if m == nil || m.OriginalBodyBytes != int64(len(formBody)) || m.RewrittenBodyBytes != m.OriginalBodyBytes || m.DownstreamBytes != m.OriginalBodyBytes {
				t.Fatalf("browser page did not retain original body size: %+v", m)
			}
			t.Logf("Browser form page matched %d original/rewritten/emitted bytes", m.OriginalBodyBytes)
		}
		if entry.Path != "/validate" {
			continue
		}
		found = true
		if entry.StatusCode != 422 || entry.Response == nil || entry.Response.OriginalBodyBytes != int64(len(errorBody)) || entry.Response.DownstreamBytes <= 0 {
			t.Fatalf("browser validation outcome missing: %+v", entry)
		}
		t.Logf("Browser form returned 422; original=%d rewritten=%d sent=%d", entry.Response.OriginalBodyBytes, entry.Response.RewrittenBodyBytes, entry.Response.DownstreamBytes)
	}
	if !found || !foundPage {
		t.Fatal("browser did not load and submit the form")
	}
	if err := s.Manifest().Flush(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Log("Diagnostic expected: E_EMAIL — enter a valid email address.")
}
