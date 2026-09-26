package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func captchaIntegrationFinish(t *testing.T, s *Server, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("GET", "https://alias.local:18099"+path, nil).WithContext(ctx)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(w, r)
		done <- w
	}()
	id := captchaDeliveryWaitID(t, s)
	captchaFollowupWaiter(t, s, id)
	w := captchaDeliveryOperatorPost(s, id, "synthetic-valid-solution", s.CaptchaOperatorToken())
	if w.Code != 200 {
		t.Fatalf("fixture completion rejected: %d", w.Code)
	}
	select {
	case got := <-done:
		return got
	case <-time.After(time.Second):
		t.Fatal("fixture request did not finish")
		return nil
	}
}

func TestCaptchaIntegrationActionCannotExportCredentials(t *testing.T) {
	for _, action := range []string{"https://unconfigured.synthetic/collect", "http://main.example/verify"} {
		t.Run(action, func(t *testing.T) {
			var calls atomic.Int32
			var exported string
			s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
				if calls.Add(1) == 1 {
					resp := audit267SRIResponse("text/html", `<p>Verify you are human</p><script src="https://js.hcaptcha.com/1/api.js"></script><form method="POST" action="`+action+`"></form>`)
					resp.StatusCode = 403
					return resp, nil
				}
				if r.URL.Host != "main.example" || r.URL.Scheme != "https" {
					b, _ := io.ReadAll(r.Body)
					exported = fmt.Sprintf("%s cookie=%q authorization=%q body=%q", r.URL, r.Header.Get("Cookie"), r.Header.Get("Authorization"), b)
				}
				return audit267SRIResponse("text/plain", "received"), nil
			})
			got := captchaIntegrationFinish(t, s, "/protected", map[string]string{"Cookie": "sid=private-session", "Authorization": "Bearer private-session-credential"})
			if exported != "" {
				t.Fatalf("untrusted form action exports target credentials: %s client status=%d", exported, got.Code)
			}
		})
	}
}

func TestCaptchaIntegrationRelativeFormActionUsesDocumentBase(t *testing.T) {
	var calls atomic.Int32
	var forwarded string
	s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			resp := audit267SRIResponse("text/html", `<p>Verify you are human</p><script src="https://js.hcaptcha.com/1/api.js"></script><form method="POST" action="verify"></form>`)
			resp.StatusCode = 403
			return resp, nil
		}
		forwarded = r.URL.String()
		return audit267SRIResponse("text/plain", "ok"), nil
	})
	captchaIntegrationFinish(t, s, "/account/protected", nil)
	if forwarded != "https://main.example/account/verify" {
		t.Fatalf("relative form action resolved to wrong destination: %q", forwarded)
	}
}

func TestCaptchaIntegrationPreservesVerificationFormFields(t *testing.T) {
	var calls atomic.Int32
	var forwarded string
	s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			resp := audit267SRIResponse("text/html", `<p>Verify you are human</p><script src="https://js.hcaptcha.com/1/api.js"></script><form method="POST" action="/verify"><input type="hidden" name="csrf" value="challenge-nonce"><input type="hidden" name="return_to" value="/protected"></form>`)
			resp.StatusCode = 403
			return resp, nil
		}
		b, _ := io.ReadAll(r.Body)
		forwarded = string(b)
		values, _ := url.ParseQuery(forwarded)
		resp := audit267SRIResponse("text/plain", "accepted")
		if values.Get("csrf") != "challenge-nonce" || values.Get("return_to") != "/protected" {
			resp.StatusCode = 403
		}
		return resp, nil
	})
	got := captchaIntegrationFinish(t, s, "/protected", nil)
	if got.Code != 200 {
		t.Fatalf("verification lost challenge form fields: status=%d body=%q", got.Code, forwarded)
	}
}

func TestCaptchaIntegrationCustomProviderAcceptance(t *testing.T) {
	const customConfig = `version: 1
captcha:
  custom:
    - name: synthetic-provider
      resource_origins: [https://captcha.synthetic.test]
      resource_url_regex: ['^https://captcha\.synthetic\.test/']
      opaque_fields: [synth-token]
      tor_policy: direct
      submissions:
        - target: primary
          method: POST
          path_regex: '^/protected$'
`
	var calls atomic.Int32
	var retryMethod, retryPath, retryBody string
	cfg := captchaDeliveryConfig(t, customConfig)
	s := captchaServer(t, cfg, func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			resp := audit267SRIResponse("text/html",
				`<p>Please verify</p>`+
					`<script src="https://captcha.synthetic.test/widget.js"></script>`+
					`<form method="POST" action="/verify-challenge">`+
					`<input type="hidden" name="csrf_token" value="fresh-nonce">`+
					`<input type="hidden" name="session_id" value="challenge-session-42">`+
					`</form>`)
			resp.StatusCode = 403
			return resp, nil
		}
		retryMethod = r.Method
		retryPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		retryBody = string(b)
		values, _ := url.ParseQuery(retryBody)
		resp := audit267SRIResponse("text/plain", "challenge-accepted")
		if values.Get("csrf_token") != "fresh-nonce" ||
			values.Get("session_id") != "challenge-session-42" ||
			values.Get("synth-token") == "" {
			resp.StatusCode = 400
			resp.Body = io.NopCloser(strings.NewReader("missing fields"))
		}
		return resp, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("POST", "https://alias.local:18099/protected",
			strings.NewReader("username=person")).WithContext(ctx)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Cookie", "sid=user-session")
		w := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(w, r)
		done <- w
	}()

	id := captchaDeliveryWaitID(t, s)
	captchaFollowupWaiter(t, s, id)

	ch, ok := s.captchaQueue.Get(id)
	if !ok {
		t.Fatal("challenge not pending")
	}
	if ch.ProviderName != "synthetic-provider" {
		t.Fatalf("wrong provider detected: %s", ch.ProviderName)
	}

	opReq := captchaDeliveryOperatorRequest(s, "POST", "challenge/"+id,
		strings.NewReader(url.Values{"synth-token": {"synth-solution-abc"}}.Encode()))
	opReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	opReq.Header.Set("Authorization", "Bearer "+s.CaptchaOperatorToken())
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, opReq)
	if w.Code != 200 {
		t.Fatalf("operator completion rejected: %d %s", w.Code, w.Body.String())
	}

	select {
	case got := <-done:
		if got.Code != 200 || got.Body.String() != "challenge-accepted" {
			t.Fatalf("custom provider acceptance failed: status=%d retry=%s %s body=%q",
				got.Code, retryMethod, retryPath, retryBody)
		}
		if retryMethod != "POST" {
			t.Fatalf("retry used wrong method: %s", retryMethod)
		}
		if retryPath != "/verify-challenge" {
			t.Fatalf("retry used wrong path: %s", retryPath)
		}
		values, _ := url.ParseQuery(retryBody)
		if values.Get("csrf_token") != "fresh-nonce" {
			t.Fatalf("CSRF token lost in retry: %s", retryBody)
		}
		if values.Get("session_id") != "challenge-session-42" {
			t.Fatalf("session ID lost in retry: %s", retryBody)
		}
	case <-time.After(time.Second):
		t.Fatal("fixture request did not finish")
	}
}

func TestCaptchaIntegrationApplicationHexValuesAreNotProxyOwned(t *testing.T) {
	for _, value := range []string{strings.Repeat("a", 48), strings.Repeat("0123456789abcdef", 3)} {
		t.Run(value, func(t *testing.T) {
			var forwarded string
			s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
				forwarded = r.URL.RequestURI()
				return audit267SRIResponse("text/plain", "ok"), nil
			})
			uri := "/api?__blv=" + value + "&keep=appdata"
			got := audit267CacheRequest(s, "GET", uri, nil)
			if got.Code != 200 || forwarded != uri {
				t.Fatalf("unissued application value claimed by shape alone: input=%q forwarded=%q status=%d body=%q", uri, forwarded, got.Code, got.Body.String())
			}
		})
	}
}
