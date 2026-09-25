package captcha

import (
	"testing"
)

func TestDetectChallengeHcaptcha(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
version: 1
captcha:
  providers:
    - hcaptcha
`))
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`<html><head><title>Access Denied</title></head><body>
<p>Please verify you are human</p>
<script src="https://hcaptcha.com/1/api.js"></script>
<div class="h-captcha" data-sitekey="key"></div>
</body></html>`)

	result := cfg.Matcher.DetectChallenge(body, "text/html", 403)
	if !result.IsCaptcha {
		t.Fatal("expected hcaptcha detection on 403 challenge page")
	}
	if result.ProviderName != "hcaptcha" {
		t.Fatalf("wrong provider: %s", result.ProviderName)
	}
}

func TestDetectChallengeNotTriggeredOn200(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
version: 1
captcha:
  providers:
    - hcaptcha
`))
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`<html><body>
<script src="https://hcaptcha.com/1/api.js"></script>
<div class="h-captcha" data-sitekey="key"></div>
<form method="POST"><input type="submit"></form>
</body></html>`)

	result := cfg.Matcher.DetectChallenge(body, "text/html", 200)
	if result.IsCaptcha {
		t.Fatal("should not detect CAPTCHA on 200 response")
	}
}

func TestDetectChallengeTurnstile(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
version: 1
captcha:
  providers:
    - turnstile
`))
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`<html><body>
<p>Just a moment...</p>
<p>Checking your browser before accessing the site.</p>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
<div class="cf-turnstile" data-sitekey="key"></div>
</body></html>`)

	result := cfg.Matcher.DetectChallenge(body, "text/html", 503)
	if !result.IsCaptcha {
		t.Fatal("expected turnstile detection on 503")
	}
}

func TestDetectChallengeNonHTML(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
version: 1
captcha:
  providers:
    - hcaptcha
`))
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"captcha": "hcaptcha.com", "challenge": true}`)

	result := cfg.Matcher.DetectChallenge(body, "application/json", 403)
	if result.IsCaptcha {
		t.Fatal("should not detect CAPTCHA in JSON")
	}
}

func TestDetectChallengeNoProviderConfig(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
version: 1
captcha:
  providers: []
`))
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`<html><p>Please verify you are human</p>
<script src="https://hcaptcha.com/1/api.js"></script></html>`)

	result := cfg.Matcher.DetectChallenge(body, "text/html", 403)
	if result.IsCaptcha {
		t.Fatal("should not detect CAPTCHA without matching provider config")
	}
}

func TestDetectChallengeCustomProvider(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
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

	body := []byte(`<html><body>
<p>Access denied - please complete the challenge</p>
<script src="https://captcha.vendor.test/widget.js"></script>
<form method="POST"><input name="vendor-token"></form>
</body></html>`)

	result := cfg.Matcher.DetectChallenge(body, "text/html", 403)
	if !result.IsCaptcha {
		t.Fatal("expected custom provider detection")
	}
	if result.ProviderName != "vendor" {
		t.Fatalf("wrong provider: %s", result.ProviderName)
	}
}

func TestDetectChallengeNilMatcher(t *testing.T) {
	var m *Matcher
	result := m.DetectChallenge([]byte("<html>hcaptcha.com challenge</html>"), "text/html", 403)
	if result.IsCaptcha {
		t.Fatal("nil matcher should not detect")
	}
}

func TestDetectChallengeNoChallengeIndicators(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
version: 1
captcha:
  providers:
    - hcaptcha
`))
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`<html><body>
<p>Internal Server Error</p>
<script src="https://hcaptcha.com/1/api.js"></script>
</body></html>`)

	result := cfg.Matcher.DetectChallenge(body, "text/html", 500)
	if result.IsCaptcha {
		t.Fatal("should not detect CAPTCHA without challenge indicators")
	}
}
