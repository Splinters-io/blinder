package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCaptchaRetryFormSemantics(t *testing.T) {
	for _, method := range []string{"POST", "GET"} {
		t.Run(method, func(t *testing.T) {
			calls := 0
			s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					resp := audit267SRIResponse("text/html", fmt.Sprintf(`<p>Verify you are human</p><script src="https://js.hcaptcha.com/1/api.js"></script><form method="%s" action="/login?keep=one"><input type="hidden" name="csrf" value="fresh"></form>`, method))
					resp.StatusCode = 403
					return resp, nil
				}
				b, _ := io.ReadAll(r.Body)
				if r.Method != method {
					t.Errorf("method=%s", r.Method)
				}
				values := r.URL.Query()
				if method == "POST" {
					values, _ = url.ParseQuery(string(b))
					if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
						t.Error("form media type lost")
					}
				} else if len(b) != 0 {
					t.Error("GET form sent a body")
				}
				if values.Get("username") != "fixture-user" || values.Get("csrf") != "fresh" || values.Get("h-captcha-response") != "synthetic-valid-solution" {
					t.Errorf("original and challenge fields lost: query=%s body=%s", r.URL.RawQuery, b)
				}
				return audit267SRIResponse("text/plain", "accepted"), nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				r := httptest.NewRequest("POST", "https://alias.local:18099/login", strings.NewReader("username=fixture-user&csrf=old")).WithContext(ctx)
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()
				s.server.Handler.ServeHTTP(w, r)
				done <- w
			}()
			id := captchaDeliveryWaitID(t, s)
			captchaFollowupWaiter(t, s, id)
			if got := captchaDeliveryOperatorPost(s, id, "synthetic-valid-solution", s.CaptchaOperatorToken()); got.Code != 200 {
				t.Fatalf("completion=%d", got.Code)
			}
			select {
			case got := <-done:
				if got.Code != 200 {
					t.Fatalf("retry=%d", got.Code)
				}
			case <-time.After(time.Second):
				t.Fatal("retry did not complete")
			}
		})
	}
}
