package proxy

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/har"
	"github.com/Splinters-io/blinder/internal/rewriter"
	"github.com/Splinters-io/blinder/internal/sri"
	"golang.org/x/net/html"
)

type audit267SRITransport func(*http.Request) (*http.Response, error)

func TestAudit267SRIFailedOriginalCannotBecomeValidAfterScrubbing(t *testing.T) {
	original := `var company="AcmeCorp";`
	expected := `var company="[REDACTED]";`
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset", expected)), nil
		}
		return audit267SRIResponse("application/javascript", original), nil
	})
	page := audit267SRIRequest(s, "GET", "/page", "", "")
	asset := audit267SRIRequest(s, "GET", "/asset", "", "")
	findings := s.SRIFindings()
	if len(findings) != 1 || findings[0].UpstreamValid {
		t.Fatalf("fixture should fail original verification: %+v", findings)
	}
	valid, _ := sri.Verify(asset.Body.Bytes(), sri.ParseIntegrity(audit267SRIAttribute(page.Body.String(), "integrity")))
	if asset.Code == 200 && valid {
		t.Fatalf("original verification failed but scrubbed resource passes retained SRI: status=%d body=%q", asset.Code, asset.Body.String())
	}
}

func TestAudit267SRIAllowlistChecksWholeOrigin(t *testing.T) {
	for _, resource := range []string{"https://main.example:8443/asset", "http://main.example/asset"} {
		t.Run(resource, func(t *testing.T) {
			var escaped []string
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Scheme == "https" && r.URL.Host == "main.example" && r.URL.Path == "/page" {
					return audit267SRIResponse("text/html", audit267SRIPage(resource, "var x=1;")), nil
				}
				escaped = append(escaped, fmt.Sprintf("url=%s cookie=%q authorization=%q", r.URL, r.Header.Get("Cookie"), r.Header.Get("Authorization")))
				return audit267SRIResponse("application/javascript", "var x=1;"), nil
			})
			audit267SRIRequest(s, "GET", "/page", "sid=synthetic", "Bearer synthetic")
			if len(escaped) > 0 {
				t.Fatalf("prefetch escaped configured https://main.example origin: %v", escaped)
			}
		})
	}
}

func TestAudit267SRIPrefetchRestoresBrowserCookieAliases(t *testing.T) {
	assetBody := `var value=1;`
	var resourceCookies []string
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/login":
			resp := audit267SRIResponse("text/plain", "ok")
			resp.Header.Set("Set-Cookie", "sid=secret; Path=/; Secure; HttpOnly")
			return resp, nil
		case "/page":
			return audit267SRIResponse("text/html", audit267SRIPage("/asset", assetBody)), nil
		default:
			resourceCookies = append(resourceCookies, r.Header.Get("Cookie"))
			if r.Header.Get("Cookie") != "sid=secret" {
				resp := audit267SRIResponse("text/plain", "denied")
				resp.StatusCode = 403
				resp.Status = "403 Forbidden"
				return resp, nil
			}
			return audit267SRIResponse("application/javascript", assetBody), nil
		}
	})
	login := audit267SRIRequest(s, "GET", "/login", "", "")
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing fixture cookie")
	}
	browserCookie := cookies[0].Name + "=" + cookies[0].Value
	control := audit267SRIRequest(s, "GET", "/asset", browserCookie, "")
	if control.Code != 200 {
		t.Fatalf("ordinary authenticated request failed: %d", control.Code)
	}
	audit267SRIRequest(s, "GET", "/page", browserCookie, "")
	resource := audit267SRIRequest(s, "GET", "/asset", browserCookie, "")
	if resource.Code != 200 {
		t.Fatalf("SRI prefetch broke working cookie authentication: status=%d upstream cookies=%q", resource.Code, resourceCookies)
	}
}

func TestAudit267SRIFailedFetchAppearsInRawEvidence(t *testing.T) {
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset", "var x=1;")), nil
		}
		resp := audit267SRIResponse("text/plain", "unavailable")
		resp.StatusCode = 503
		resp.Status = "503 Service Unavailable"
		return resp, nil
	})
	path := filepath.Join(t.TempDir(), "capture.har")
	s.harWriter = har.NewWriter(path, 1024, 100)
	audit267SRIRequest(s, "GET", "/page", "", "")
	if err := s.FlushHAR(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var evidence har.HARFile
	if err := json.Unmarshal(data, &evidence); err != nil {
		t.Fatal(err)
	}
	for _, entry := range evidence.Log.Entries {
		if strings.HasSuffix(entry.Request.URL, "/asset") && entry.Response.Status == 503 {
			return
		}
	}
	t.Fatalf("503 prefetch missing from HAR, entries=%d", len(evidence.Log.Entries))
}

func (f audit267SRITransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func audit267SRIServer(t *testing.T, fn audit267SRITransport) *Server {
	t.Helper()
	cfg, err := config.New("https://main.example", "127.0.0.1:18099", "alias.local", []string{"AcmeCorp"}, true, false, false, "", "", 0, "", "", 30, 60)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	s.transport = fn
	s.sriPipeline = sri.NewPipeline(sri.PipelineConfig{
		Transport: fn,
		Cache:     s.sriCache,
		ScrubFn: func(body []byte, contentType, path string) []byte {
			return rewriter.RewriteBody(body, contentType, path, s.gate, s.cfg.Paranoid).Body
		},
		IsAllowedOrigin: s.origins.IsKnownFullOrigin,
		CookieRestoreFn: s.gate.RestoreCookieHeader,
		OnFetch: func(rec sri.FetchRecord) {
			if s.harWriter != nil {
				if rec.Error != "" {
					s.harWriter.RecordFetchFailure(rec.Request, rec.Status, rec.Headers, rec.Body, rec.Error, rec.Elapsed)
					return
				}
				s.harWriter.Record(rec.Request, nil, &http.Response{StatusCode: rec.Status, Status: fmt.Sprintf("%d %s", rec.Status, http.StatusText(rec.Status)), Header: rec.Headers, Proto: "HTTP/1.1"}, rec.Body, rec.Elapsed)
			}
		},
	})
	return s
}

func audit267SRIResponse(ct, body string) *http.Response {
	return &http.Response{StatusCode: 200, Status: "200 OK", Proto: "HTTP/1.1", Header: http.Header{"Content-Type": {ct}}, Body: io.NopCloser(strings.NewReader(body))}
}

func audit267SRIPage(src, body string) string {
	return fmt.Sprintf(`<script src="%s" integrity="%s" crossorigin="anonymous"></script>`, src, sri.ComputeIntegrity([]byte(body), "sha384"))
}

func audit267SRIRequest(s *Server, method, path, cookie, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://127.0.0.1:18099"+path, nil)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func audit267SRIAttribute(body, key string) string {
	z := html.NewTokenizer(strings.NewReader(body))
	for z.Next() != html.ErrorToken {
		tok := z.Token()
		for _, a := range tok.Attr {
			if a.Key == key {
				return a.Val
			}
		}
	}
	return ""
}

func TestAudit267SRISharedCacheDoesNotExposeAuthenticatedBody(t *testing.T) {
	secret := `var privateValue="only-alice";`
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset", secret)), nil
		}
		if r.Header.Get("Cookie") == "sid=alice" {
			return audit267SRIResponse("application/javascript", secret), nil
		}
		resp := audit267SRIResponse("text/plain", "access denied")
		resp.StatusCode = 403
		resp.Status = "403 Forbidden"
		return resp, nil
	})
	audit267SRIRequest(s, "GET", "/page", "sid=alice", "")
	guest := audit267SRIRequest(s, "GET", "/asset", "", "")
	if guest.Code == 200 || strings.Contains(guest.Body.String(), "only-alice") {
		t.Fatalf("guest received status=%d body=%q from authenticated cache", guest.Code, guest.Body.String())
	}
}

func TestAudit267SRICachedSuccessDoesNotRepairLaterInvalidIntegrity(t *testing.T) {
	asset := `var company="AcmeCorp";`
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/good":
			return audit267SRIResponse("text/html", audit267SRIPage("/asset", asset)), nil
		case "/bad":
			return audit267SRIResponse("text/html", audit267SRIPage("/asset", "different bytes")), nil
		default:
			return audit267SRIResponse("application/javascript", asset), nil
		}
	})
	audit267SRIRequest(s, "GET", "/good", "", "")
	bad := audit267SRIRequest(s, "GET", "/bad", "", "")
	delivered := audit267SRIRequest(s, "GET", "/asset", "", "")
	rewrittenIntegrity := audit267SRIAttribute(bad.Body.String(), "integrity")
	valid, _ := sri.Verify(delivered.Body.Bytes(), sri.ParseIntegrity(rewrittenIntegrity))
	if delivered.Code == 200 && valid {
		t.Fatalf("invalid original integrity was replaced with passing %q after another page primed the URL cache", rewrittenIntegrity)
	}
}

func TestAudit267SRIPrefetchCannotExpandRouteOrCredentialScope(t *testing.T) {
	asset := `var value=1;`
	var escaped []string
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "main.example" {
			return audit267SRIResponse("text/html", audit267SRIPage("//unconfigured.invalid:8443/asset", asset)), nil
		}
		escaped = append(escaped, fmt.Sprintf("host=%s cookie=%q authorization=%q", r.URL.Host, r.Header.Get("Cookie"), r.Header.Get("Authorization")))
		return audit267SRIResponse("application/javascript", asset), nil
	})
	audit267SRIRequest(s, "GET", "/page", "sid=synthetic", "Bearer synthetic-secret")
	if len(escaped) > 0 {
		t.Fatalf("unconfigured prefetch received credentials: %v", escaped)
	}
}

func TestAudit267SRIUsesContextAwareJavaScriptRewrite(t *testing.T) {
	asset := `document.querySelector("form").addEventListener("submit", function () { console.log(window.location.href); });`
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset", asset)), nil
		}
		return audit267SRIResponse("application/javascript", asset), nil
	})
	ordinary := audit267SRIRequest(s, "GET", "/asset", "", "")
	if ordinary.Body.String() != asset {
		t.Fatalf("normal rewrite control changed technical surface: %s", ordinary.Body.String())
	}
	audit267SRIRequest(s, "GET", "/page", "", "")
	cached := audit267SRIRequest(s, "GET", "/asset", "", "")
	if cached.Body.String() != asset {
		t.Fatalf("SRI path corrupted unchanged JavaScript: %s", cached.Body.String())
	}
}

func TestAudit267SRICacheDoesNotInterceptPost(t *testing.T) {
	asset := `var value=1;`
	posts := 0
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			posts++
			return audit267SRIResponse("text/plain", "posted"), nil
		}
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset", asset)), nil
		}
		return audit267SRIResponse("application/javascript", asset), nil
	})
	audit267SRIRequest(s, "GET", "/page", "", "")
	rr := audit267SRIRequest(s, "POST", "/asset", "", "")
	if posts != 1 || rr.Body.String() != "posted" {
		t.Fatalf("cached GET swallowed POST: upstream posts=%d response=%q", posts, rr.Body.String())
	}
}

func TestAudit267SRICachePreservesResponseSecurityHeaders(t *testing.T) {
	asset := `var value=1;`
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset", asset)), nil
		}
		resp := audit267SRIResponse("application/javascript", asset)
		resp.Header.Set("X-Content-Type-Options", "nosniff")
		resp.Header.Set("Access-Control-Allow-Origin", "https://main.example")
		resp.Header.Set("Cross-Origin-Resource-Policy", "same-origin")
		return resp, nil
	})
	audit267SRIRequest(s, "GET", "/page", "", "")
	rr := audit267SRIRequest(s, "GET", "/asset", "", "")
	for _, key := range []string{"X-Content-Type-Options", "Access-Control-Allow-Origin", "Cross-Origin-Resource-Policy"} {
		if rr.Header().Get(key) == "" {
			t.Errorf("cached response dropped %s", key)
		}
	}
}

func TestAudit267SRIPrefetchUsesCurrentDocumentURL(t *testing.T) {
	asset := `var value=1;`
	var fetched []string
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/nested/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("asset", asset)), nil
		}
		fetched = append(fetched, r.URL.Path)
		return audit267SRIResponse("application/javascript", asset), nil
	})
	audit267SRIRequest(s, "GET", "/nested/page", "", "")
	if len(fetched) != 1 || fetched[0] != "/nested/asset" {
		t.Fatalf("relative resource fetched from %v, want /nested/asset", fetched)
	}
}

func TestAudit267SRIPrefetchAppearsInRawEvidence(t *testing.T) {
	asset := `var value=1;`
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset", asset)), nil
		}
		return audit267SRIResponse("application/javascript", asset), nil
	})
	path := filepath.Join(t.TempDir(), "capture.har")
	s.harWriter = har.NewWriter(path, 1024, 100)
	audit267SRIRequest(s, "GET", "/page", "", "")
	audit267SRIRequest(s, "GET", "/asset", "", "")
	if err := s.FlushHAR(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var evidence har.HARFile
	if err := json.Unmarshal(data, &evidence); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range evidence.Log.Entries {
		if strings.HasSuffix(entry.Request.URL, "/asset") {
			found = true
		}
	}
	if !found {
		t.Fatalf("actual upstream SRI fetch missing from HAR; entries=%d", len(evidence.Log.Entries))
	}
}

func TestAudit267SRINoIntegrityStillPreservesCrossorigin(t *testing.T) {
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		return audit267SRIResponse("text/html", `<script src="/asset" crossorigin="anonymous"></script>`), nil
	})
	rr := audit267SRIRequest(s, "GET", "/page", "", "")
	if audit267SRIAttribute(rr.Body.String(), "crossorigin") != "anonymous" {
		t.Fatalf("crossorigin removed from resource without integrity: %s", rr.Body.String())
	}
}

func TestAudit267SRIBlockingDigestCannotMatchDeliveredBytes(t *testing.T) {
	// The blocking hash is the digest of these public, ordinary bytes.
	body := "blinder:poison:verification-failed"
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset", "other bytes")), nil
		}
		return audit267SRIResponse("application/javascript", body), nil
	})
	page := audit267SRIRequest(s, "GET", "/page", "", "")
	asset := audit267SRIRequest(s, "GET", "/asset", "", "")
	if findings := s.SRIFindings(); len(findings) != 1 || findings[0].UpstreamValid {
		t.Fatalf("expected failed upstream verification: %+v", findings)
	}
	integrity := audit267SRIAttribute(page.Body.String(), "integrity")
	valid, _ := sri.Verify(asset.Body.Bytes(), sri.ParseIntegrity(integrity))
	if asset.Code == 200 && valid {
		t.Fatalf("failed original integrity is accepted by emitted blocking digest: %s; body=%q", integrity, asset.Body.String())
	}
}

func TestAudit267SRIBlocksAllAlgorithms(t *testing.T) {
	for _, alg := range []string{"sha256", "sha384", "sha512"} {
		t.Run(alg, func(t *testing.T) {
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/page" {
					return audit267SRIResponse("text/html", fmt.Sprintf(`<script src="/asset" integrity="%s"></script>`, sri.ComputeIntegrity([]byte("wrong bytes"), alg))), nil
				}
				return audit267SRIResponse("application/javascript", "var x=1;"), nil
			})
			page := audit267SRIRequest(s, "GET", "/page", "", "")
			if audit267SRIAttribute(page.Body.String(), "src") != "" {
				t.Fatalf("failed original retained executable resource reference: %s", page.Body.String())
			}
		})
	}
}

func TestAudit267SRIHARPreservesFailureEvidence(t *testing.T) {
	for _, scenario := range []string{"upstream_503", "partial_body", "transport_disconnect"} {
		t.Run(scenario, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/page" {
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprint(w, audit267SRIPage("/asset", "var x=1;"))
					return
				}
				if scenario == "transport_disconnect" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						conn.Close()
					}
					return
				}
				w.Header().Set("X-Upstream-Evidence", "synthetic-marker")
				w.Header().Set("Content-Type", "text/plain")
				if scenario == "upstream_503" {
					w.WriteHeader(503)
					fmt.Fprint(w, "upstream unavailable")
					return
				}
				w.Header().Set("Content-Length", "100")
				w.WriteHeader(200)
				fmt.Fprint(w, "partial evidence")
			}))
			defer target.Close()
			path := filepath.Join(t.TempDir(), "capture.har")
			cfg, err := config.New(target.URL, "127.0.0.1:18099", "alias.local", []string{"AcmeCorp"}, false, false, false, "", path, 1024, "", "", 30, 60)
			if err != nil {
				t.Fatal(err)
			}
			// Use the actual constructor, transport and HAR callback unchanged.
			s, err := NewWithCertificate(cfg, tls.Certificate{})
			if err != nil {
				t.Fatal(err)
			}
			audit267SRIRequest(s, "GET", "/page", "", "")
			if err := s.FlushHAR(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var capture har.HARFile
			if err := json.Unmarshal(data, &capture); err != nil {
				t.Fatal(err)
			}
			for _, entry := range capture.Log.Entries {
				if !strings.HasSuffix(entry.Request.URL, "/asset") {
					continue
				}
				if scenario == "transport_disconnect" {
					if entry.Response.Status != 0 {
						t.Errorf("no upstream HTTP response, but HAR invents status=%d body=%q", entry.Response.Status, entry.Response.Content.Text)
					}
					return
				}
				found := false
				for _, h := range entry.Response.Headers {
					if strings.EqualFold(h.Name, "X-Upstream-Evidence") && h.Value == "synthetic-marker" {
						found = true
					}
				}
				if !found {
					t.Errorf("available upstream response headers discarded: %+v", entry.Response)
				}
				if scenario == "partial_body" && entry.Response.Content.Text != "partial evidence" {
					t.Errorf("available partial body replaced by error message: %q", entry.Response.Content.Text)
				}
				return
			}
			t.Fatal("prefetch missing from HAR")
		})
	}
}

func TestAudit267SRIBlockDoesNotEnableInlineScript(t *testing.T) {
	original := `<p id="result">NOT EXECUTED</p><script src="/asset.js" integrity="` + sri.ComputeIntegrity([]byte("wrong bytes"), "sha384") + `">document.getElementById("result").textContent="UNEXPECTED INLINE EXECUTION";</script>`
	asset := `document.getElementById("result").textContent="EXTERNAL EXECUTION";`
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", original), nil
		}
		return audit267SRIResponse("application/javascript", asset), nil
	})
	page := audit267SRIRequest(s, "GET", "/page", "", "")
	dir := t.TempDir()
	for name, data := range map[string]string{"original.html": original, "rewritten.html": page.Body.String(), "asset.js": asset} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if audit267SRIAttribute(page.Body.String(), "src") == "" && audit267SRIAttribute(page.Body.String(), "type") == "" && strings.Contains(page.Body.String(), "UNEXPECTED INLINE EXECUTION") {
		t.Fatalf("blocked external script became executable inline script: %s", page.Body.String())
	}
}

func TestAudit267SRIBlockConsumesSelfClosingScriptBody(t *testing.T) {
	// In text/html, a slash does not make script a void element.
	original := `<p id="result">NOT EXECUTED</p><script src="/asset.js" integrity="` + sri.ComputeIntegrity([]byte("wrong bytes"), "sha384") + `" />` + `'<svg onload="document[&quot;getElementById&quot;](&quot;result&quot;)[&quot;textContent&quot;]=&quot;UNEXPECTED EVENT EXECUTION&quot;"></svg>'` + `</script><p id="following">FOLLOWING MARKUP</p>`
	asset := `document.getElementById("result").textContent="EXTERNAL EXECUTION";`
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", original), nil
		}
		return audit267SRIResponse("application/javascript", asset), nil
	})
	page := audit267SRIRequest(s, "GET", "/page", "", "")
	dir := t.TempDir()
	for name, data := range map[string]string{"selfclosing-original.html": original, "selfclosing-rewritten.html": page.Body.String(), "asset.js": asset} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(page.Body.String(), "UNEXPECTED EVENT EXECUTION") || strings.Contains(page.Body.String(), "<svg") || strings.Contains(page.Body.String(), "</script>") {
		t.Errorf("failed self-closing syntax script leaked its raw-text body into HTML: %s", page.Body.String())
	}
	if !strings.Contains(page.Body.String(), "FOLLOWING MARKUP") {
		t.Errorf("following markup lost: %s", page.Body.String())
	}
}
