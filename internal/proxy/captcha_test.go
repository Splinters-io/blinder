package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"crypto/tls"

	"github.com/Splinters-io/blinder/internal/captcha"
	"github.com/Splinters-io/blinder/internal/config"
)

func captchaServer(t *testing.T, captchaCfg *captcha.Config, fn audit267SRITransport) *Server {
	t.Helper()
	cfg, err := config.New("https://main.example", "127.0.0.1:18099", "alias.local", []string{"AcmeCorp"}, true, false, false, "", "", 0, "", "", 30, 60)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Captcha = captchaCfg
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	s.transport = fn
	return s
}

func TestCaptchaProviderOriginPreservedInHTML(t *testing.T) {
	captchaCfg, err := captcha.ParseConfig([]byte(`
version: 1
captcha:
  providers:
    - hcaptcha
`))
	if err != nil {
		t.Fatal(err)
	}

	const page = `<html><body>
<script src="https://hcaptcha.com/1/api.js" async defer></script>
<div class="h-captcha" data-sitekey="example-key"></div>
<form method="POST" action="/login">
<input type="hidden" name="h-captcha-response" value="">
</form>
</body></html>`

	s := captchaServer(t, captchaCfg, func(r *http.Request) (*http.Response, error) {
		return audit267SRIResponse("text/html", page), nil
	})

	got := audit267CacheRequest(s, "GET", "/page", nil)
	body := got.Body.String()

	if !strings.Contains(body, "hcaptcha.com") {
		t.Fatalf("hcaptcha.com origin was scrubbed from HTML:\n%s", body)
	}
}

func TestCaptchaOpaqueFieldPreservedInFormSubmission(t *testing.T) {
	captchaCfg, err := captcha.ParseConfig([]byte(`
version: 1
captcha:
  providers:
    - hcaptcha
`))
	if err != nil {
		t.Fatal(err)
	}

	var receivedBody string
	s := captchaServer(t, captchaCfg, func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			receivedBody = string(b)
		}
		return audit267SRIResponse("text/plain", "ok"), nil
	})

	tokenValue := "P1_eyJ0eX_hcaptcha_opaque_token_data"
	form := url.Values{
		"h-captcha-response": {tokenValue},
		"username":           {"AcmeCorp"},
	}

	r := httptest.NewRequest("POST", "https://alias.local:18099/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	parsed, err := url.ParseQuery(receivedBody)
	if err != nil {
		t.Fatal(err)
	}

	if got := parsed.Get("h-captcha-response"); got != tokenValue {
		t.Fatalf("opaque CAPTCHA token was modified: want=%q got=%q", tokenValue, got)
	}

	if got := parsed.Get("username"); got != "AcmeCorp" {
		t.Fatalf("non-opaque field was not restored: want=AcmeCorp got=%q", got)
	}
}

func TestCaptchaOpaqueFieldNotRestoredForUnknownField(t *testing.T) {
	captchaCfg, err := captcha.ParseConfig([]byte(`
version: 1
captcha:
  providers:
    - hcaptcha
`))
	if err != nil {
		t.Fatal(err)
	}

	var receivedBody string
	s := captchaServer(t, captchaCfg, func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			receivedBody = string(b)
		}
		return audit267SRIResponse("text/plain", "ok"), nil
	})

	alias := s.gate.Scrub("AcmeCorp", "test")
	form := url.Values{
		"regular-field": {alias},
	}

	r := httptest.NewRequest("POST", "https://alias.local:18099/api", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	parsed, err := url.ParseQuery(receivedBody)
	if err != nil {
		t.Fatal(err)
	}

	if got := parsed.Get("regular-field"); got != "AcmeCorp" {
		t.Fatalf("regular field not restored: want=AcmeCorp got=%q", got)
	}
}

func TestCaptchaCustomProviderOriginPreserved(t *testing.T) {
	captchaCfg, err := captcha.ParseConfig([]byte(`
version: 1
captcha:
  custom:
    - name: vendor
      resource_origins:
        - https://captcha.vendor.test
      opaque_fields:
        - vendor-token
`))
	if err != nil {
		t.Fatal(err)
	}

	const page = `<html><body>
<script src="https://captcha.vendor.test/widget.js"></script>
</body></html>`

	s := captchaServer(t, captchaCfg, func(r *http.Request) (*http.Response, error) {
		return audit267SRIResponse("text/html", page), nil
	})

	got := audit267CacheRequest(s, "GET", "/page", nil)
	body := got.Body.String()

	if !strings.Contains(body, "captcha.vendor.test") {
		t.Fatalf("custom provider origin was scrubbed:\n%s", body)
	}
}

func TestCaptchaNilConfigDoesNotBreakProxy(t *testing.T) {
	s := captchaServer(t, nil, func(r *http.Request) (*http.Response, error) {
		return audit267SRIResponse("text/plain", "ok"), nil
	})

	got := audit267CacheRequest(s, "GET", "/page", nil)
	if got.Code != 200 {
		t.Fatalf("nil captcha config broke proxy: status=%d", got.Code)
	}
}

func TestCaptchaProviderOriginDoesNotDisableScrubbing(t *testing.T) {
	captchaCfg, err := captcha.ParseConfig([]byte(`
version: 1
captcha:
  providers:
    - hcaptcha
`))
	if err != nil {
		t.Fatal(err)
	}

	const page = `<html><body>
<script src="https://hcaptcha.com/1/api.js"></script>
<p>Contact us at info@main.example for AcmeCorp support.</p>
</body></html>`

	s := captchaServer(t, captchaCfg, func(r *http.Request) (*http.Response, error) {
		return audit267SRIResponse("text/html", page), nil
	})

	got := audit267CacheRequest(s, "GET", "/page", nil)
	body := got.Body.String()

	if strings.Contains(body, "AcmeCorp") {
		t.Fatalf("identity token leaked despite CAPTCHA config:\n%s", body)
	}
	if strings.Contains(body, "main.example") {
		t.Fatalf("target domain leaked despite CAPTCHA config:\n%s", body)
	}
	if !strings.Contains(body, "hcaptcha.com") {
		t.Fatalf("hcaptcha.com was incorrectly scrubbed:\n%s", body)
	}
}

func TestCaptchaMisleadingOriginNotPreserved(t *testing.T) {
	captchaCfg, err := captcha.ParseConfig([]byte(`
version: 1
captcha:
  providers:
    - hcaptcha
`))
	if err != nil {
		t.Fatal(err)
	}

	const page = `<html><body>
<script src="https://evil-hcaptcha.com/steal.js"></script>
</body></html>`

	s := captchaServer(t, captchaCfg, func(r *http.Request) (*http.Response, error) {
		return audit267SRIResponse("text/html", page), nil
	})

	got := audit267CacheRequest(s, "GET", "/page", nil)
	body := got.Body.String()

	if strings.Contains(body, "evil-hcaptcha.com") {
		t.Fatalf("misleading domain was preserved:\n%s", body)
	}
}

func TestCaptchaCSPNotInjectedWithoutUpstreamCSP(t *testing.T) {
	captchaCfg, err := captcha.ParseConfig([]byte(`
version: 1
captcha:
  providers:
    - hcaptcha
`))
	if err != nil {
		t.Fatal(err)
	}

	const page = `<html><body>ok</body></html>`

	s := captchaServer(t, captchaCfg, func(r *http.Request) (*http.Response, error) {
		resp := audit267SRIResponse("text/html", page)
		return resp, nil
	})

	got := audit267CacheRequest(s, "GET", "/page", nil)
	csp := got.Header().Get("Content-Security-Policy")

	if csp != "" {
		t.Fatalf("CSP injected without upstream policy: %s", csp)
	}
}

func TestCaptchaConfigurationPreservesUpstreamCSPDecisions(t *testing.T) {
	captchaCfg, err := captcha.ParseConfig([]byte(`
version: 1
captcha:
  providers:
    - hcaptcha
`))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		enforcing  []string
		reportOnly []string
		want       []string
	}{
		{name: "no_policy"},
		{name: "deny_all", enforcing: []string{"default-src 'none'"}, want: []string{"default-src 'none'"}},
		{name: "inherited_self", enforcing: []string{"default-src 'self'"}, want: []string{"default-src 'self'"}},
		{name: "explicit_denial", enforcing: []string{"script-src 'none'; frame-src 'none'; connect-src 'none'"}, want: []string{"script-src 'none'; frame-src 'none'; connect-src 'none'"}},
		{name: "already_allowed", enforcing: []string{"script-src https://js.hcaptcha.com; frame-src https://hcaptcha.com"}, want: []string{"script-src https://js.hcaptcha.com; frame-src https://hcaptcha.com"}},
		{name: "report_only", reportOnly: []string{"default-src 'none'"}},
		{name: "independent_policies", enforcing: []string{"script-src https://js.hcaptcha.com", "script-src 'none'"}, reportOnly: []string{"default-src 'self'"}, want: []string{"script-src https://js.hcaptcha.com", "script-src 'none'"}},
		{name: "origin_mapping_only", enforcing: []string{"script-src https://main.example https://js.hcaptcha.com; frame-src 'none'"}, want: []string{"script-src https://127.0.0.1:18099 https://js.hcaptcha.com; frame-src 'none'"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := captchaServer(t, captchaCfg, func(r *http.Request) (*http.Response, error) {
				resp := audit267SRIResponse("text/html", "<html><body>ok</body></html>")
				for _, value := range tc.enforcing {
					resp.Header.Add("Content-Security-Policy", value)
				}
				for _, value := range tc.reportOnly {
					resp.Header.Add("Content-Security-Policy-Report-Only", value)
				}
				return resp, nil
			})
			got := audit267CacheRequest(s, "GET", "/page", nil)
			if got.Code != http.StatusOK {
				t.Fatalf("status = %d; body = %s", got.Code, got.Body)
			}
			if values := got.Header().Values("Content-Security-Policy"); !slices.Equal(values, tc.want) {
				t.Fatalf("CAPTCHA configuration changed enforcing policy: got %q, want %q", values, tc.want)
			}
			if values := got.Header().Values("Content-Security-Policy-Report-Only"); !slices.Equal(values, tc.reportOnly) {
				t.Fatalf("CAPTCHA configuration changed report-only policy: got %q, want %q", values, tc.reportOnly)
			}
		})
	}
}

func TestCaptchaNoCSPWithoutConfig(t *testing.T) {
	s := captchaServer(t, nil, func(r *http.Request) (*http.Response, error) {
		return audit267SRIResponse("text/html", "<html><body>ok</body></html>"), nil
	})

	got := audit267CacheRequest(s, "GET", "/page", nil)
	csp := got.Header().Get("Content-Security-Policy")

	if strings.Contains(csp, "hcaptcha") {
		t.Fatalf("CSP contains CAPTCHA entries without config: %s", csp)
	}
}
