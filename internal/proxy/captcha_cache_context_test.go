package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCaptchaRetryDoesNotCacheUnderConsumerURL(t *testing.T) {
	var calls atomic.Int32
	s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
		n := calls.Add(1)
		switch {
		case n == 1 && r.URL.Path == "/account/start":
			resp := audit267SRIResponse("text/html",
				`<p>Verify you are human</p><script src="https://js.hcaptcha.com/1/api.js"></script><form method="GET" action="/verified/done"></form>`)
			resp.StatusCode = 403
			return resp, nil
		case r.URL.Path == "/verified/done":
			resp := audit267SRIResponse("text/html", `<html><body>welcome to verified</body></html>`)
			resp.Header.Set("Cache-Control", "max-age=300")
			return resp, nil
		case r.URL.Path == "/account/start":
			resp := audit267SRIResponse("text/html", `<html><body>account start page</body></html>`)
			resp.Header.Set("Cache-Control", "max-age=300")
			return resp, nil
		default:
			return audit267SRIResponse("text/plain", "not found"), nil
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("GET", "https://alias.local:18099/account/start", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(w, r)
		done <- w
	}()
	id := captchaDeliveryWaitID(t, s)
	captchaFollowupWaiter(t, s, id)
	op := captchaDeliveryOperatorPost(s, id, "synthetic-valid-solution", s.CaptchaOperatorToken())
	if op.Code != 200 {
		t.Fatalf("operator completion rejected: %d", op.Code)
	}
	select {
	case got := <-done:
		if got.Code != 200 {
			t.Fatalf("consumer got %d, want 200", got.Code)
		}
		if !strings.Contains(got.Body.String(), "welcome to verified") {
			t.Fatalf("consumer did not get retry response: %s", got.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("consumer request timed out")
	}

	later := audit267CacheRequest(s, "GET", "/account/start", nil)
	if later.Code != 200 {
		t.Fatalf("later GET /account/start got %d, want 200", later.Code)
	}
	body := later.Body.String()
	if strings.Contains(body, "welcome to verified") {
		t.Fatalf("later GET /account/start got retry's cached response instead of its own: %s", body)
	}
	if !strings.Contains(body, "account start page") {
		t.Fatalf("later GET /account/start did not get fresh response: %s", body)
	}
}

func TestCaptchaRetryNonGETConsumerDoesNotPopulateCache(t *testing.T) {
	var calls atomic.Int32
	s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
		n := calls.Add(1)
		switch {
		case n == 1 && r.Method == "POST":
			resp := audit267SRIResponse("text/html",
				`<p>Verify you are human</p><script src="https://js.hcaptcha.com/1/api.js"></script><form method="GET" action="/verified/done"></form>`)
			resp.StatusCode = 403
			return resp, nil
		case r.URL.Path == "/verified/done":
			resp := audit267SRIResponse("text/html", `<html><body>verified page</body></html>`)
			resp.Header.Set("Cache-Control", "max-age=300")
			return resp, nil
		case r.URL.Path == "/submit":
			resp := audit267SRIResponse("text/html", `<html><body>fresh submit response</body></html>`)
			resp.Header.Set("Cache-Control", "max-age=300")
			return resp, nil
		default:
			return audit267SRIResponse("text/plain", "not found"), nil
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("POST", "https://alias.local:18099/submit", strings.NewReader("data=1")).WithContext(ctx)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(w, r)
		done <- w
	}()
	id := captchaDeliveryWaitID(t, s)
	captchaFollowupWaiter(t, s, id)
	op := captchaDeliveryOperatorPost(s, id, "synthetic-valid-solution", s.CaptchaOperatorToken())
	if op.Code != 200 {
		t.Fatalf("operator completion rejected: %d", op.Code)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumer request timed out")
	}

	later := audit267CacheRequest(s, "GET", "/submit", nil)
	body := later.Body.String()
	if strings.Contains(body, "verified page") {
		t.Fatalf("GET /submit served retry response from cache: %s", body)
	}
	if !strings.Contains(body, "fresh submit response") {
		t.Fatalf("GET /submit did not get fresh response: %s", body)
	}
}

func TestCaptchaRetryResourceResolvesFromUpstreamDocument(t *testing.T) {
	var calls atomic.Int32
	var resourcePaths []string
	s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
		n := calls.Add(1)
		switch {
		case n == 1 && r.URL.Path == "/account/start":
			resp := audit267SRIResponse("text/html",
				`<p>Verify you are human</p><script src="https://js.hcaptcha.com/1/api.js"></script><form method="GET" action="/verified/done"></form>`)
			resp.StatusCode = 403
			return resp, nil
		case r.URL.Path == "/verified/done":
			resp := audit267SRIResponse("text/html",
				`<html><head><script src="app.js"></script></head><body>verified</body></html>`)
			return resp, nil
		default:
			resourcePaths = append(resourcePaths, r.URL.Path)
			return audit267SRIResponse("application/javascript", "console.log('ok')"), nil
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan string, 1)
	go func() {
		r := httptest.NewRequest("GET", "https://alias.local:18099/account/start", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(w, r)
		done <- w.Body.String()
	}()
	id := captchaDeliveryWaitID(t, s)
	captchaFollowupWaiter(t, s, id)
	op := captchaDeliveryOperatorPost(s, id, "synthetic-valid-solution", s.CaptchaOperatorToken())
	if op.Code != 200 {
		t.Fatalf("operator completion rejected: %d", op.Code)
	}
	select {
	case body := <-done:
		if !strings.Contains(body, "verified") {
			t.Fatalf("did not get retry body: %s", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("consumer request timed out")
	}

	w := audit267CacheRequest(s, "GET", "/verified/app.js", nil)
	if w.Code == 404 {
		t.Logf("resource paths seen by target: %v", resourcePaths)
	}
	got := w.Body.String()
	if !strings.Contains(got, "console.log") {
		t.Fatalf("resource at /verified/app.js was not resolved from document base /verified/done; got status %d body: %s", w.Code, got)
	}
}

func TestCaptchaRetryCredentialHashUsesUpstreamRequest(t *testing.T) {
	var calls atomic.Int32
	s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
		n := calls.Add(1)
		switch {
		case n == 1 && r.URL.Path == "/login":
			resp := audit267SRIResponse("text/html",
				`<p>Verify you are human</p><script src="https://js.hcaptcha.com/1/api.js"></script><form method="GET" action="/dashboard"></form>`)
			resp.StatusCode = 403
			resp.Header.Set("Set-Cookie", "session=challenge-token")
			return resp, nil
		case r.URL.Path == "/dashboard":
			resp := audit267SRIResponse("text/html", `<html><body>dashboard content</body></html>`)
			resp.Header.Set("Cache-Control", "private, max-age=300")
			return resp, nil
		case r.URL.Path == "/login":
			return audit267SRIResponse("text/html", `<html><body>login page</body></html>`), nil
		default:
			return audit267SRIResponse("text/plain", "other"), nil
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("GET", "https://alias.local:18099/login", nil).WithContext(ctx)
		r.Header.Set("Cookie", "session=user-token")
		w := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(w, r)
		done <- w
	}()
	id := captchaDeliveryWaitID(t, s)
	captchaFollowupWaiter(t, s, id)
	op := captchaDeliveryOperatorPost(s, id, "synthetic-valid-solution", s.CaptchaOperatorToken())
	if op.Code != 200 {
		t.Fatalf("operator completion rejected: %d", op.Code)
	}
	select {
	case got := <-done:
		if got.Code != 200 {
			t.Fatalf("consumer got %d, want 200", got.Code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("consumer request timed out")
	}

	later := audit267CacheRequest(s, "GET", "/login", http.Header{"Cookie": {"session=user-token"}})
	body := later.Body.String()
	if strings.Contains(body, "dashboard") {
		t.Fatalf("GET /login with original credentials got retry's cached response: %s", body)
	}
}
