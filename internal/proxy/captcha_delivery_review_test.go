package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/captcha"
)

func captchaDeliveryConfig(t *testing.T, body string) *captcha.Config {
	t.Helper()
	cfg, err := captcha.ParseConfig([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

const captchaDeliveryBuiltin = `version: 1
captcha:
  providers: [hcaptcha]
`

func captchaDeliveryWaitID(t *testing.T, s *Server) string {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if pending := s.captchaQueue.Pending(); len(pending) > 0 {
			return pending[0].ID
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("challenge was not queued")
	return ""
}
func captchaDeliveryOperatorPost(s *Server, id, value, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://alias.local:18099/__blinder/captcha/challenge/"+id, strings.NewReader(url.Values{"h-captcha-response": {value}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, r)
	return w
}

func TestCaptchaDeliveryCompletionRequiresTargetAcceptance(t *testing.T) {
	var calls atomic.Int32
	s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		resp := audit267SRIResponse("text/html", `<p>Verify you are human</p><script src="https://js.hcaptcha.com/1/api.js"></script><form method="post" action="/verify"></form>`)
		resp.StatusCode = 403
		return resp, nil
	})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(w, httptest.NewRequest("GET", "https://alias.local:18099/protected", nil))
		done <- w
	}()
	id := captchaDeliveryWaitID(t, s)
	defer s.captchaQueue.Complete(id, map[string]string{"cleanup": "only"})
	operator := captchaDeliveryOperatorPost(s, id, "fabricated-not-accepted-by-target", s.CaptchaOperatorToken())
	if operator.Code != 200 {
		t.Fatalf("operator fixture was rejected: %d", operator.Code)
	}
	select {
	case got := <-done:
		if got.Code == 200 {
			t.Errorf("invented successful response without target acceptance: upstream calls=%d status=%d body=%q", calls.Load(), got.Code, got.Body.String())
		}
		if strings.Contains(got.Body.String(), "fabricated-not-accepted-by-target") {
			t.Error("raw solution token returned to ordinary proxy client")
		}
	case <-time.After(time.Second):
		t.Fatal("completion did not release synthetic request")
	}
}

func TestCaptchaDeliveryOperatorControlIsPrivate(t *testing.T) {
	for _, kind := range []string{"list", "raw_page", "complete"} {
		t.Run(kind, func(t *testing.T) {
			s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
				return audit267SRIResponse("text/plain", "upstream"), nil
			})
			id := s.captchaQueue.Submit("hcaptcha", "https://private-target.synthetic/account", []byte("<p>AcmeCorp original private page</p>"), "text/html")
			var w *httptest.ResponseRecorder
			if kind == "complete" {
				w = captchaDeliveryOperatorPost(s, id, "untrusted-client-token", "")
			} else {
				path := "/__blinder/captcha/"
				if kind == "raw_page" {
					path = "/__blinder/captcha/page/" + id
				}
				w = httptest.NewRecorder()
				s.server.Handler.ServeHTTP(w, httptest.NewRequest("GET", "https://alias.local:18099"+path, nil))
			}
			if w.Code == 200 {
				t.Fatalf("ordinary proxy client can access operator %s without operator authorization: body=%q", kind, w.Body.String())
			}
		})
	}
}

func TestCaptchaDeliveryOpaqueFieldsHonorFormatAndScope(t *testing.T) {
	cfg := captchaDeliveryConfig(t, `version: 1
captcha:
  custom:
    - name: synthetic
      resource_origins: [https://captcha.vendor.synthetic]
      opaque_fields: [challenge-token]
      submissions:
        - target: primary
          method: POST
          path_regex: '^/login$'
`)
	for _, mode := range []string{"json_token", "out_of_scope_form"} {
		t.Run(mode, func(t *testing.T) {
			var received []byte
			s := captchaServer(t, cfg, func(r *http.Request) (*http.Response, error) {
				received, _ = io.ReadAll(r.Body)
				return audit267SRIResponse("text/plain", "ok"), nil
			})
			alias := s.gate.Scrub("AcmeCorp", "fixture")
			path := "/login"
			ct := "application/json"
			payload, _ := json.Marshal(map[string]string{"challenge-token": alias})
			if mode == "out_of_scope_form" {
				path = "/ordinary"
				ct = "application/x-www-form-urlencoded"
				payload = []byte(url.Values{"challenge-token": {alias}}.Encode())
			}
			r := httptest.NewRequest("POST", "https://alias.local:18099"+path, strings.NewReader(string(payload)))
			r.Header.Set("Content-Type", ct)
			s.ServeHTTP(httptest.NewRecorder(), r)
			if mode == "json_token" {
				var got map[string]string
				if err := json.Unmarshal(received, &got); err != nil {
					t.Fatal(err)
				}
				if got["challenge-token"] != alias {
					t.Fatalf("opaque JSON token modified: want=%q got=%q", alias, got["challenge-token"])
				}
			} else {
				form, err := url.ParseQuery(string(received))
				if err != nil {
					t.Fatal(err)
				}
				if form.Get("challenge-token") != "AcmeCorp" {
					t.Fatalf("submission scope ignored outside /login: got=%q", form.Get("challenge-token"))
				}
			}
		})
	}
}

func captchaDeliveryDirective(policy, name string) string {
	for _, d := range strings.Split(policy, ";") {
		parts := strings.Fields(d)
		if len(parts) > 0 && parts[0] == name {
			return strings.Join(parts[1:], " ")
		}
	}
	return ""
}
func TestCaptchaDeliveryCSPPreservesApplicationAndSDK(t *testing.T) {
	for _, mode := range []string{"no_original_policy", "inherited_self", "hcaptcha_sdk"} {
		t.Run(mode, func(t *testing.T) {
			s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
				resp := audit267SRIResponse("text/html", `<script src="/app"></script><script src="https://js.hcaptcha.com/1/api.js"></script>`)
				if mode != "no_original_policy" {
					resp.Header.Set("Content-Security-Policy", "default-src 'self'")
				}
				return resp, nil
			})
			got := audit267CacheRequest(s, "GET", "/page", nil)
			policy := got.Header().Get("Content-Security-Policy")
			script := captchaDeliveryDirective(policy, "script-src")
			switch mode {
			case "no_original_policy":
				if policy != "" {
					t.Fatalf("CAPTCHA configuration creates a new policy restricting ordinary app scripts: %q", policy)
				}
			case "inherited_self":
				if script != "" && !strings.Contains(script, "'self'") {
					t.Fatalf("new script-src loses inherited default-src self: %q", policy)
				}
			case "hcaptcha_sdk":
				if !strings.Contains(script, "https://js.hcaptcha.com") && !strings.Contains(script, "https://*.hcaptcha.com") {
					t.Fatalf("injected policy blocks official hCaptcha SDK at js.hcaptcha.com: %q", policy)
				}
			}
		})
	}
}

func TestCaptchaDeliveryResourceRegexActuallyScopesException(t *testing.T) {
	cfg := captchaDeliveryConfig(t, `version: 1
captcha:
  custom:
    - name: synthetic
      resource_origins: [https://captcha.vendor.synthetic]
      resource_url_regex: ['^https://captcha\.vendor\.synthetic/widget/']
`)
	const excluded = "https://captcha.vendor.synthetic/unrelated/tracker"
	u, _ := url.Parse(excluded)
	if cfg.Matcher.IsProviderResource(u) {
		t.Fatal("fixture URL should not match configured exception")
	}
	s := captchaServer(t, cfg, func(r *http.Request) (*http.Response, error) {
		return audit267SRIResponse("text/html", `<script src="`+excluded+`"></script>`), nil
	})
	got := audit267CacheRequest(s, "GET", "/page", nil)
	if strings.Contains(got.Body.String(), excluded) {
		t.Fatalf("regex rejected URL but production rewriting exempts it anyway: %q", got.Body.String())
	}
}

func TestCaptchaDeliveryWaitEndsWhenRequestCancelled(t *testing.T) {
	s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
		resp := audit267SRIResponse("text/html", `<p>verify you are human</p><div class="h-captcha"></div>`)
		resp.StatusCode = 403
		return resp, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("GET", "https://alias.local:18099/protected", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() { s.server.Handler.ServeHTTP(httptest.NewRecorder(), r); close(done) }()
	id := captchaDeliveryWaitID(t, s)
	defer func() {
		s.captchaQueue.Complete(id, map[string]string{"cleanup": "only"})
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(150 * time.Millisecond):
		t.Fatal("cancelled client request remains blocked in five-minute CAPTCHA wait")
	}
}

func TestCaptchaDeliveryQueueExpiryAppliesWithoutListing(t *testing.T) {
	q := captcha.NewChallengeQueue(time.Millisecond)
	id := q.Submit("synthetic", "https://target.synthetic", []byte("challenge"), "text/html")
	time.Sleep(15 * time.Millisecond)
	if _, ok := q.Get(id); ok {
		t.Error("Get serves expired challenge until someone calls Pending")
	}
	if q.Complete(id, map[string]string{"token": "late"}) {
		t.Error("expired challenge can still be completed")
	}
}

func TestCaptchaDeliveryVersionSigningStillNeedsRandomSecret(t *testing.T) {
	var forwarded string
	s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
		forwarded = r.URL.RequestURI()
		return audit267SRIResponse("text/plain", "ok"), nil
	})
	secret := sha256.Sum256([]byte("blinder-version-registry\x00alias.local\x00main.example"))
	const data = "0123456789abcdef"
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte(data))
	forged := data + hex.EncodeToString(mac.Sum(nil)[:16])
	uri := "/api?__blv=" + forged
	got := audit267CacheRequest(s, "GET", uri, nil)
	if got.Code != 200 || forwarded != uri {
		t.Fatalf("application __blv intercepted as proxy metadata: forwarded=%q status=%d body=%q", forwarded, got.Code, got.Body.String())
	}
}
