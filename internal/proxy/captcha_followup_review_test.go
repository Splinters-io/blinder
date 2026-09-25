package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/har"
)

func captchaFollowupWaiter(t *testing.T, s *Server, id string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if s.captchaQueue.HasWaiter(id) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("fixture waiter did not start")
}

func TestCaptchaFollowupCompletionRequiresAuthWhileWaiting(t *testing.T) {
	s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), nil)
	id := s.captchaQueue.Submit("hcaptcha", "https://main.example/protected", []byte("challenge"), "text/html")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.captchaQueue.WaitForCompletion(ctx, id, time.Second) }()
	defer func() { cancel(); <-done }()
	captchaFollowupWaiter(t, s, id)
	w := captchaDeliveryOperatorPost(s, id, "unauthorized-solution", "")
	if w.Code < 400 {
		t.Fatalf("having a waiter authorizes an unauthenticated completion: status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestCaptchaFollowupRetryPreservesTargetSessionAndRequest(t *testing.T) {
	var calls atomic.Int32
	var retryCookie, retryAuth, retryPayload string
	var retryDeadline bool
	s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
		payload, _ := io.ReadAll(r.Body)
		if calls.Add(1) == 1 {
			resp := audit267SRIResponse("text/html", `<p>Verify you are human</p><script src="https://js.hcaptcha.com/1/api.js"></script><form method="post" action="/login"><input name="username" value="person"><input name="csrf" value="original-nonce"></form>`)
			resp.StatusCode = 403
			resp.Header.Set("Set-Cookie", "challenge_nonce=fresh; Path=/; Secure")
			return resp, nil
		}
		retryCookie, retryAuth, retryPayload = r.Header.Get("Cookie"), r.Header.Get("Authorization"), string(payload)
		_, retryDeadline = r.Context().Deadline()
		form, _ := url.ParseQuery(string(payload))
		resp := audit267SRIResponse("text/plain", "target rejected lost session or form state")
		resp.StatusCode = 401
		if form.Get("username") == "person" && form.Get("csrf") == "original-nonce" && form.Get("h-captcha-response") == "valid-for-this-fixture" && strings.Contains(retryCookie, "sid=original") && strings.Contains(retryCookie, "challenge_nonce=fresh") && retryAuth == "Bearer session-credential" {
			resp.StatusCode = 200
			resp.Body = io.NopCloser(strings.NewReader("protected account"))
		}
		return resp, nil
	})
	s.harWriter = har.NewWriter(filepath.Join(t.TempDir(), "capture.har"), 1024*1024, 50)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("POST", "https://alias.local:18099/login", strings.NewReader("username=person&csrf=original-nonce")).WithContext(ctx)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Cookie", "sid=original")
		r.Header.Set("Authorization", "Bearer session-credential")
		w := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(w, r)
		done <- w
	}()
	id := captchaDeliveryWaitID(t, s)
	captchaFollowupWaiter(t, s, id)
	r := httptest.NewRequest("POST", "https://alias.local:18099/__blinder/captcha/challenge/"+id, strings.NewReader("h-captcha-response=valid-for-this-fixture"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+s.CaptchaOperatorToken())
	s.server.Handler.ServeHTTP(httptest.NewRecorder(), r)
	select {
	case got := <-done:
		if got.Code != 200 || got.Body.String() != "protected account" {
			t.Errorf("valid human solution could not resume original session: status=%d retry cookie=%q authorization=%q body=%q", got.Code, retryCookie, retryAuth, retryPayload)
		}
		if !retryDeadline {
			t.Error("CAPTCHA retry bypasses configured upstream timeout")
		}
		if count := s.harWriter.Len(); count != int(calls.Load()) {
			t.Errorf("HAR omitted CAPTCHA retry: upstream requests=%d HAR entries=%d", calls.Load(), count)
		}
	case <-time.After(time.Second):
		t.Fatal("fixture completion did not finish")
	}
}

func TestCaptchaFollowupOpaqueJSONPreservesExistingContracts(t *testing.T) {
	for _, mode := range []string{"number_precision", "nested_token", "restored_key_collision"} {
		t.Run(mode, func(t *testing.T) {
			var forwarded string
			s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(r.Body)
				forwarded = string(body)
				return audit267SRIResponse("text/plain", "accepted"), nil
			})
			alias := s.gate.Scrub("AcmeCorp", "fixture")
			payload := `{"id":9007199254740993,"h-captcha-response":"opaque-token"}`
			if mode == "nested_token" {
				b, _ := json.Marshal(map[string]any{"challenge": map[string]string{"h-captcha-response": alias}})
				payload = string(b)
			} else if mode == "restored_key_collision" {
				b, _ := json.Marshal(map[string]any{alias: 1, "AcmeCorp": 2, "h-captcha-response": "opaque-token"})
				payload = string(b)
			}
			r := httptest.NewRequest("POST", "https://alias.local:18099/login", strings.NewReader(payload))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			switch mode {
			case "number_precision":
				if !strings.Contains(forwarded, "9007199254740993") {
					t.Fatalf("CAPTCHA opacity path rounded JSON number: %s", forwarded)
				}
			case "nested_token":
				var got map[string]map[string]string
				if err := json.Unmarshal([]byte(forwarded), &got); err != nil {
					t.Fatal(err)
				}
				if got["challenge"]["h-captcha-response"] != alias {
					t.Fatalf("nested opaque token restored as identity: %s", forwarded)
				}
			case "restored_key_collision":
				if forwarded != "" || w.Code != 400 {
					t.Fatalf("CAPTCHA helper bypassed ambiguous JSON rejection: forwarded=%s status=%d", forwarded, w.Code)
				}
			}
		})
	}
}

func TestCaptchaFollowupResourceOriginScope(t *testing.T) {
	for _, raw := range []string{"http://captcha.vendor.synthetic/widget", "https://captcha.vendor.synthetic:8443/widget"} {
		t.Run(raw, func(t *testing.T) {
			cfg := captchaDeliveryConfig(t, `version: 1
captcha:
  custom:
    - name: synthetic
      resource_origins: [https://captcha.vendor.synthetic]
      resource_url_regex: ['^https?://']
`)
			s := captchaServer(t, cfg, func(r *http.Request) (*http.Response, error) {
				return audit267SRIResponse("text/html", `<script src="`+raw+`"></script>`), nil
			})
			got := audit267CacheRequest(s, "GET", "/page", nil)
			if strings.Contains(got.Body.String(), raw) {
				t.Fatalf("different full origin received CAPTCHA exception: %s", got.Body.String())
			}
		})
	}
}

func TestCaptchaFollowupSubmissionTargetScope(t *testing.T) {
	capcfg := captchaDeliveryConfig(t, `version: 1
captcha:
  custom:
    - name: synthetic
      resource_origins: [https://captcha.vendor.synthetic]
      opaque_fields: [vendor-token]
      submissions:
        - target: primary
          method: POST
          path_regex: '^/login$'
`)
	cfg, err := config.New("https://main.example", "127.0.0.1:18099", "alias.local", []string{"AcmeCorp"}, true, false, false, "", "", 0, "", "", 30, 60, "https://extra.example")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Captcha = capcfg
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	var forwarded, host string
	s.transport = audit267SRITransport(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		forwarded, host = string(body), r.URL.Host
		return audit267SRIResponse("text/plain", "ok"), nil
	})
	alias := s.gate.Scrub("AcmeCorp", "fixture")
	dest := s.origins.RewriteUpstreamURL("https://extra.example/login")
	r := httptest.NewRequest("POST", dest, strings.NewReader(url.Values{"vendor-token": {alias}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if host != "extra.example" {
		t.Fatalf("fixture routed incorrectly: host=%q status=%d destination=%q", host, w.Code, dest)
	}
	values, _ := url.ParseQuery(forwarded)
	if values.Get("vendor-token") != "AcmeCorp" {
		t.Fatalf("primary-only opacity applied to extra origin: %s", forwarded)
	}
}

func TestCaptchaFollowupLifecycleReleasesChallenge(t *testing.T) {
	for _, mode := range []string{"cancel", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
				resp := audit267SRIResponse("text/html", `<p>Verify you are human</p><script src="https://js.hcaptcha.com/1/api.js"></script>`)
				resp.StatusCode = 403
				return resp, nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				s.server.Handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "https://alias.local:18099/protected", nil).WithContext(ctx))
			}()
			defer func() { cancel(); <-done }()
			id := captchaDeliveryWaitID(t, s)
			captchaFollowupWaiter(t, s, id)
			if mode == "cancel" {
				cancel()
			} else {
				shutdownCtx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer stop()
				_ = s.Shutdown(shutdownCtx)
			}
			select {
			case <-done:
				if _, ok := s.captchaQueue.Get(id); ok {
					t.Error("finished request retained raw pending challenge")
				}
			case <-time.After(150 * time.Millisecond):
				t.Error("shutdown did not release CAPTCHA waiter")
			}
		})
	}
}

func TestCaptchaFollowupRestartDoesNotForwardOwnedVersionMetadata(t *testing.T) {
	keyDir := t.TempDir()
	const oldBody = "var version=1;"
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset", oldBody)), nil
		}
		return audit267SRIResponse("application/javascript", oldBody), nil
	}, keyDir)
	page := audit267CacheRequest(s, "GET", "/page", nil)
	src := audit267SRIAttribute(page.Body.String(), "src")
	u, err := url.Parse(src)
	if err != nil || u.Query().Get("__blv") == "" {
		t.Fatalf("fixture reference missing: %q %v", src, err)
	}
	path := audit750BrowserPath(t, src)
	var forwarded string
	restarted := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		forwarded = r.URL.RequestURI()
		return audit267SRIResponse("application/javascript", "var version=2;"), nil
	}, keyDir)
	got := audit267CacheRequest(restarted, "GET", path, nil)
	if strings.Contains(forwarded, "__blv=") || got.Code < 400 {
		t.Fatalf("restart lost proxy metadata ownership: forwarded=%q status=%d body=%q", forwarded, got.Code, got.Body.String())
	}
}
