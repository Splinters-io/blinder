package captcha

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestParseConfigBuiltInProviders(t *testing.T) {
	yaml := `
version: 1
captcha:
  providers:
    - hcaptcha
    - recaptcha
    - turnstile
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Providers) != 3 {
		t.Fatalf("want 3 providers, got %d", len(cfg.Providers))
	}
	names := map[string]bool{}
	for _, p := range cfg.Providers {
		names[p.Name] = true
		if len(p.ResourceOrigins) == 0 {
			t.Fatalf("built-in provider %q has no resource origins", p.Name)
		}
		if len(p.OpaqueFields) == 0 {
			t.Fatalf("built-in provider %q has no opaque fields", p.Name)
		}
	}
	for _, want := range []string{"hcaptcha", "recaptcha", "turnstile"} {
		if !names[want] {
			t.Fatalf("missing provider %q", want)
		}
	}
}

func TestParseConfigCustomProvider(t *testing.T) {
	yaml := `
version: 1
captcha:
  custom:
    - name: vendor-captcha
      resource_origins:
        - https://captcha.vendor.example
      resource_url_regex:
        - '^https://captcha\.vendor\.example/(widget|assets)/'
      opaque_fields:
        - vendor-response
      submissions:
        - target: primary
          method: POST
          path_regex: '^/login$'
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Providers) != 1 {
		t.Fatalf("want 1 provider, got %d", len(cfg.Providers))
	}
	p := cfg.Providers[0]
	if p.Name != "vendor-captcha" {
		t.Fatalf("name = %q", p.Name)
	}
	if len(p.Submissions) != 1 {
		t.Fatalf("submissions = %d", len(p.Submissions))
	}
	if p.Submissions[0].PathRegex == nil {
		t.Fatal("path regex not compiled")
	}
}

func TestParseConfigRejectsInvalidVersion(t *testing.T) {
	yaml := `
version: 2
captcha:
  providers:
    - hcaptcha
`
	_, err := ParseConfig([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for version 2")
	}
}

func TestParseConfigRejectsUnknownBuiltIn(t *testing.T) {
	yaml := `
version: 1
captcha:
  providers:
    - nonexistent
`
	_, err := ParseConfig([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestParseConfigRejectsBadRegex(t *testing.T) {
	yaml := `
version: 1
captcha:
  custom:
    - name: bad
      resource_origins:
        - https://bad.example
      resource_url_regex:
        - '[invalid'
      opaque_fields:
        - token
`
	_, err := ParseConfig([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for bad regex")
	}
}

func TestParseConfigRejectsCustomWithoutOrigins(t *testing.T) {
	yaml := `
version: 1
captcha:
  custom:
    - name: no-origins
      opaque_fields:
        - token
`
	_, err := ParseConfig([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing origins")
	}
}

func TestParseConfigMixedBuiltInAndCustom(t *testing.T) {
	yaml := `
version: 1
captcha:
  providers:
    - hcaptcha
  custom:
    - name: my-captcha
      resource_origins:
        - https://my.captcha.example
      opaque_fields:
        - my-token
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Providers) != 2 {
		t.Fatalf("want 2 providers (1 built-in + 1 custom), got %d", len(cfg.Providers))
	}
}

func TestMatcherResourceOrigin(t *testing.T) {
	yaml := `
version: 1
captcha:
  providers:
    - hcaptcha
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(cfg)

	hcaptchaURL, _ := url.Parse("https://hcaptcha.com/1/api.js")
	if !m.IsProviderResource(hcaptchaURL) {
		t.Fatal("hcaptcha.com should be a provider resource")
	}
	if !m.IsProviderResource(mustParse("https://newassets.hcaptcha.com/captcha/v1/abc/static/some.js")) {
		t.Fatal("newassets.hcaptcha.com should be a provider resource")
	}
	if m.IsProviderResource(mustParse("https://evil-hcaptcha.com/fake")) {
		t.Fatal("evil-hcaptcha.com must not match")
	}
	if m.IsProviderResource(mustParse("https://example.com/hcaptcha.com")) {
		t.Fatal("hcaptcha.com as path must not match")
	}
}

func TestMatcherOpaqueFieldPreservation(t *testing.T) {
	yaml := `
version: 1
captcha:
  providers:
    - hcaptcha
    - recaptcha
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(cfg)

	if !m.IsOpaqueField("h-captcha-response") {
		t.Fatal("h-captcha-response should be opaque")
	}
	if !m.IsOpaqueField("g-recaptcha-response") {
		t.Fatal("g-recaptcha-response should be opaque")
	}
	if m.IsOpaqueField("username") {
		t.Fatal("username should not be opaque")
	}
}

func TestMatcherSubmissionScope(t *testing.T) {
	yaml := `
version: 1
captcha:
  custom:
    - name: vendor
      resource_origins:
        - https://captcha.vendor.example
      opaque_fields:
        - vendor-token
      submissions:
        - target: primary
          method: POST
          path_regex: '^/(login|checkout)$'
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(cfg)

	login := &http.Request{Method: "POST", URL: mustParse("/login")}
	if !m.SubmissionHasOpaqueFields(login, "vendor-token") {
		t.Fatal("POST /login should allow opaque vendor-token")
	}

	checkout := &http.Request{Method: "POST", URL: mustParse("/checkout")}
	if !m.SubmissionHasOpaqueFields(checkout, "vendor-token") {
		t.Fatal("POST /checkout should allow opaque vendor-token")
	}

	api := &http.Request{Method: "POST", URL: mustParse("/api")}
	if m.SubmissionHasOpaqueFields(api, "vendor-token") {
		t.Fatal("POST /api should not allow opaque vendor-token")
	}

	get := &http.Request{Method: "GET", URL: mustParse("/login")}
	if m.SubmissionHasOpaqueFields(get, "vendor-token") {
		t.Fatal("GET /login should not allow opaque vendor-token")
	}
}

func TestMatcherMisleadingHostnameSuffix(t *testing.T) {
	yaml := `
version: 1
captcha:
  providers:
    - hcaptcha
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(cfg)

	bad := []string{
		"https://evil-hcaptcha.com/api.js",
		"https://hcaptcha.com.evil.example/api.js",
		"https://nothcaptcha.com/1/api.js",
		"https://xhcaptcha.com/api.js",
	}
	for _, raw := range bad {
		u := mustParse(raw)
		if m.IsProviderResource(u) {
			t.Fatalf("misleading hostname accepted: %s", raw)
		}
	}
}

func TestMatcherCSPDirectives(t *testing.T) {
	yaml := `
version: 1
captcha:
  providers:
    - hcaptcha
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(cfg)
	csp := m.CSPDirectives()
	if len(csp) == 0 {
		t.Fatal("expected CSP directives for hcaptcha")
	}
	found := false
	for _, d := range csp {
		if strings.Contains(d, "hcaptcha.com") {
			found = true
		}
	}
	if !found {
		t.Fatalf("CSP directives missing hcaptcha.com: %v", csp)
	}
}

func TestMatcherResourceRegex(t *testing.T) {
	yaml := `
version: 1
captcha:
  custom:
    - name: vendor
      resource_origins:
        - https://captcha.vendor.example
      resource_url_regex:
        - '^https://captcha\.vendor\.example/(widget|assets)/'
      opaque_fields:
        - token
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(cfg)

	if !m.IsProviderResource(mustParse("https://captcha.vendor.example/widget/v1.js")) {
		t.Fatal("widget path should match")
	}
	if !m.IsProviderResource(mustParse("https://captcha.vendor.example/assets/style.css")) {
		t.Fatal("assets path should match")
	}
	if m.IsProviderResource(mustParse("https://captcha.vendor.example/admin/panel")) {
		t.Fatal("admin path should not match regex")
	}
}

func TestParseConfigRejectsDuplicateNames(t *testing.T) {
	yaml := `
version: 1
captcha:
  providers:
    - hcaptcha
  custom:
    - name: hcaptcha
      resource_origins:
        - https://custom.example
      opaque_fields:
        - tok
`
	_, err := ParseConfig([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestEmptyConfigIsValid(t *testing.T) {
	cfg, err := ParseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Providers) != 0 {
		t.Fatalf("empty config should have 0 providers, got %d", len(cfg.Providers))
	}
}

func mustParse(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func TestTorPolicyDefaultsToRouteWithTarget(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
version: 1
captcha:
  providers:
    - hcaptcha
`))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Providers[0].TorPolicy != TorPolicyRouteWithTarget {
		t.Fatalf("expected default tor policy %q, got %q", TorPolicyRouteWithTarget, cfg.Providers[0].TorPolicy)
	}
}

func TestTorPolicyDirect(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
version: 1
captcha:
  custom:
    - name: vendor
      resource_origins:
        - https://captcha.vendor.test
      opaque_fields:
        - token
      tor_policy: direct
`))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Providers[0].TorPolicy != TorPolicyDirect {
		t.Fatalf("expected direct tor policy, got %q", cfg.Providers[0].TorPolicy)
	}
}

func TestTorPolicyInvalidRejected(t *testing.T) {
	_, err := ParseConfig([]byte(`
version: 1
captcha:
  custom:
    - name: vendor
      resource_origins:
        - https://captcha.vendor.test
      tor_policy: invalid-policy
`))
	if err == nil {
		t.Fatal("expected error for invalid tor_policy")
	}
	if !strings.Contains(err.Error(), "invalid tor_policy") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestMatcherShouldBypassTor(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
version: 1
captcha:
  providers:
    - hcaptcha
  custom:
    - name: vendor
      resource_origins:
        - https://captcha.vendor.test
      opaque_fields:
        - token
      tor_policy: direct
`))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Matcher.ShouldBypassTor("hcaptcha.com") {
		t.Fatal("hcaptcha should not bypass Tor (default policy)")
	}
	if !cfg.Matcher.ShouldBypassTor("captcha.vendor.test") {
		t.Fatal("vendor should bypass Tor (direct policy)")
	}
	if cfg.Matcher.ShouldBypassTor("unknown.example.com") {
		t.Fatal("unknown host should not bypass Tor")
	}
}
