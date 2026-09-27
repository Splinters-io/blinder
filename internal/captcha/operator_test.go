package captcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testOperatorSetup(t *testing.T) (*OperatorHandler, *ChallengeQueue, *Matcher, string) {
	t.Helper()
	cfg, err := ParseConfig([]byte(`
version: 1
captcha:
  providers:
    - hcaptcha
`))
	if err != nil {
		t.Fatal(err)
	}
	q := NewChallengeQueue(5 * time.Minute)
	h, token := NewOperatorHandler(q, cfg.Matcher, nil)
	if err := h.SetOperatorOrigin("https://" + OperatorHost + ":8099"); err != nil {
		t.Fatal(err)
	}
	return h, q, cfg.Matcher, token
}

func operatorRequest(method, path, token string, body *strings.Reader) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, body)
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestOperatorListEmpty(t *testing.T) {
	h, _, _, token := testOperatorSetup(t)

	r := operatorRequest("GET", "/__blinder/captcha/", token, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "0 pending") {
		t.Fatalf("expected 0 pending in body: %s", body)
	}
}

func TestOperatorListWithChallenge(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)

	q.Submit("hcaptcha", "https://example.com/login", []byte("<html>captcha</html>"), "text/html")

	r := operatorRequest("GET", "/__blinder/captcha/", token, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "1 pending") {
		t.Fatalf("expected 1 pending: %s", body)
	}
	if !strings.Contains(body, "hcaptcha") {
		t.Fatalf("expected hcaptcha provider name: %s", body)
	}
}

func TestOperatorShowChallenge(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)

	id := q.Submit("hcaptcha", "https://example.com/login", []byte("<html>captcha</html>"), "text/html")
	completionWaiter(t, q, id)

	r := operatorRequest("GET", "/__blinder/captcha/challenge/"+id, token, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "h-captcha-response") {
		t.Fatalf("expected opaque field in form: %s", body)
	}
}

func TestOperatorShowChallengeNotFound(t *testing.T) {
	h, _, _, token := testOperatorSetup(t)

	r := operatorRequest("GET", "/__blinder/captcha/challenge/nonexistent", token, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestOperatorCompleteChallenge(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)

	id := q.Submit("hcaptcha", "https://example.com/login", []byte("<html>captcha</html>"), "text/html")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiterDone := make(chan struct{})
	go func() {
		defer close(waiterDone)
		q.WaitForCompletion(ctx, id, 5*time.Second)
	}()
	time.Sleep(10 * time.Millisecond)

	form := url.Values{"h-captcha-response": {"token123"}}
	r := operatorRequest("POST", "/__blinder/captcha/challenge/"+id, token, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "completed" {
		t.Fatalf("expected completed status: %v", resp)
	}

	<-waiterDone
}

func TestOperatorCompleteEmptySolution(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)

	id := q.Submit("hcaptcha", "https://example.com", []byte("ch"), "text/html")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { q.WaitForCompletion(ctx, id, 5*time.Second) }()
	time.Sleep(10 * time.Millisecond)

	form := url.Values{"h-captcha-response": {""}}
	r := operatorRequest("POST", "/__blinder/captcha/challenge/"+id, token, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 400 {
		t.Fatalf("expected 400 for empty solution, got %d", w.Code)
	}
}

func TestOperatorServeChallengePage(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)

	pageBody := []byte("<html><body>please solve captcha</body></html>")
	id := q.Submit("hcaptcha", "https://example.com/login", pageBody, "text/html; charset=utf-8")
	completionWaiter(t, q, id)

	r := operatorRequest("GET", "/__blinder/captcha/page/"+id, token, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `sandbox="allow-scripts allow-forms allow-same-origin"`) || strings.Contains(w.Body.String(), "please solve captcha") || strings.Contains(w.Body.String(), "srcdoc=") {
		t.Fatalf("challenge page is not an isolated-origin wrapper")
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("wrong content type: %s", ct)
	}
}

func TestOperatorMethodNotAllowed(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)

	id := q.Submit("hcaptcha", "https://example.com", []byte("ch"), "text/html")

	r := operatorRequest("DELETE", "/__blinder/captcha/challenge/"+id, token, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestOperatorNotFoundRoutes(t *testing.T) {
	h, _, _, token := testOperatorSetup(t)

	routes := []string{
		"/__blinder/captcha/unknown",
		"/__blinder/captcha/challenge/",
	}

	for _, route := range routes {
		r := operatorRequest("GET", route, token, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		if w.Code != 404 {
			t.Fatalf("route %s: expected 404, got %d", route, w.Code)
		}
	}
}

func TestOperatorUnauthorizedAccess(t *testing.T) {
	h, q, _, _ := testOperatorSetup(t)

	q.Submit("hcaptcha", "https://example.com", []byte("ch"), "text/html")

	r := httptest.NewRequest("GET", "/__blinder/captcha/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 403 {
		t.Fatalf("expected 403 without auth, got %d", w.Code)
	}
}

func TestOperatorCompletionRequiresAuth(t *testing.T) {
	h, q, _, _ := testOperatorSetup(t)

	id := q.Submit("hcaptcha", "https://example.com", []byte("ch"), "text/html")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { q.WaitForCompletion(ctx, id, 5*time.Second) }()
	time.Sleep(10 * time.Millisecond)

	form := url.Values{"h-captcha-response": {"token123"}}
	r := httptest.NewRequest("POST", "/__blinder/captcha/challenge/"+id, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 403 {
		t.Fatalf("completion without auth should be 403, got %d", w.Code)
	}
}

func TestOperatorCookieAuth(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)

	q.Submit("hcaptcha", "https://example.com", []byte("ch"), "text/html")

	r := httptest.NewRequest("GET", "/__blinder/captcha/", nil)
	r.AddCookie(&http.Cookie{Name: OperatorCookieName, Value: token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("cookie auth should succeed, got %d", w.Code)
	}
}

func TestOperatorBearerSetsCookie(t *testing.T) {
	h, _, _, token := testOperatorSetup(t)

	r := operatorRequest("GET", "/__blinder/captcha/", token, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}

	cookies := w.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == OperatorCookieName && c.Value == token {
			found = true
			if !c.HttpOnly {
				t.Fatal("cookie must be HttpOnly")
			}
			if !c.Secure {
				t.Fatal("cookie must be Secure")
			}
			if c.Path != "/" || c.Domain != "" {
				t.Fatal("operator cookie must be host-only with root path")
			}
		}
	}
	if !found {
		t.Fatal("bearer auth did not set operator cookie")
	}
}
