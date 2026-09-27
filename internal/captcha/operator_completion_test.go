package captcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func completionWaiter(t *testing.T, queue *ChallengeQueue, id string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		queue.WaitForCompletion(ctx, id, 5*time.Second)
	}()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(time.Second)
	for !queue.HasWaiter(id) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !queue.HasWaiter(id) {
		t.Fatal("fixture waiter did not start")
	}
}

func completionBrowserRequest(id, token, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/__blinder/captcha/challenge/"+id, strings.NewReader(body))
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Dest", "document")
	r.Header.Set("Origin", "https://"+OperatorHost+":8099")
	r.AddCookie(&http.Cookie{Name: operatorCookieName, Value: token})
	return r
}

func TestOperatorCompletionBrowserReceiptRequiresSuccessfulPOST(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)
	id := q.Submit("hcaptcha", "https://example.com/login", []byte("<html>challenge</html>"), "text/html")
	completionWaiter(t, q, id)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, completionBrowserRequest(id, token, "h-captcha-response=accepted-for-retry"))
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("native completion did not get a receipt: %d %s", w.Code, w.Body.String())
	}
	for _, text := range []string{"<h1>Solution submitted</h1>", `role="status"`, "original page to check its result", "Challenge queue"} {
		if !strings.Contains(w.Body.String(), text) {
			t.Errorf("receipt lacks %q: %s", text, w.Body.String())
		}
	}
	if strings.Contains(w.Body.String(), "accepted-for-retry") || strings.Contains(w.Body.String(), token) {
		t.Fatal("receipt exposed submitted solution or operator credential")
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Vary") != "Accept" {
		t.Fatalf("receipt caching headers missing: %v", w.Header())
	}
}

func TestOperatorCompletionBrowserErrorsRemainVisibleAndRetryable(t *testing.T) {
	for _, tc := range []struct {
		name, body, errorText string
		waiter                bool
		status                int
	}{
		{"empty", "h-captcha-response=", "no solution fields provided", true, http.StatusBadRequest},
		{"malformed", "h-captcha-response=%GG", "bad form data", true, http.StatusBadRequest},
		{"no_waiter", "h-captcha-response=token", "no pending request", false, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, q, _, token := testOperatorSetup(t)
			id := q.Submit("hcaptcha", "https://example.com/login", []byte("<html>challenge</html>"), "text/html")
			if tc.waiter {
				completionWaiter(t, q, id)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, completionBrowserRequest(id, token, tc.body))
			body := w.Body.String()
			if w.Code != tc.status || !strings.Contains(body, tc.errorText) || !strings.Contains(body, `role="alert"`) || !strings.Contains(body, "Try again") {
				t.Fatalf("error not visible/retryable: status=%d body=%s", w.Code, body)
			}
			if strings.Contains(body, "Solution submitted") {
				t.Fatal("failed POST displayed a success receipt")
			}
			if _, ok := q.Get(id); !ok {
				t.Fatal("failed submission consumed the pending challenge")
			}
			if tc.waiter {
				retry := httptest.NewRecorder()
				h.ServeHTTP(retry, completionBrowserRequest(id, token, "h-captcha-response=retry-token"))
				if retry.Code != http.StatusOK || !strings.Contains(retry.Body.String(), "<h1>Solution submitted</h1>") {
					t.Fatalf("corrected retry failed: %d %s", retry.Code, retry.Body.String())
				}
			}
		})
	}
}

func TestOperatorCompletionAPIKeepsJSONAndFetchAuthBoundary(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)
	id := q.Submit("hcaptcha", "https://example.com/login", []byte("<html>challenge</html>"), "text/html")
	completionWaiter(t, q, id)
	r := completionBrowserRequest(id, token, "h-captcha-response=token")
	r.Header.Set("Sec-Fetch-Dest", "empty")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cookie-only fetch authorized by UI change: %d", w.Code)
	}
	r = completionBrowserRequest(id, token, "h-captcha-response=token")
	r.Header.Set("Sec-Fetch-Dest", "empty")
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Accept", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var receipt struct{ Status, ID string }
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil || w.Code != http.StatusOK || receipt.Status != "completed" || receipt.ID != id {
		t.Fatalf("API contract changed: %d %s, %v", w.Code, w.Body.String(), err)
	}
}

func TestOperatorCompletionPagesUseNativeSubmissionWithoutCredentials(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)
	id := q.Submit("hcaptcha", "https://example.com/login", []byte(`<html><body><input name="h-captcha-response"></body></html>`), "text/html")
	completionWaiter(t, q, id)
	for _, path := range []string{"/challenge/", "/solve/"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, operatorRequest(http.MethodGet, "/__blinder/captcha"+path+id, token, nil))
		body := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(body, operatorCompletionRuntime) {
			t.Fatalf("%s missing completion controller: %d", path, w.Code)
		}
		if strings.Contains(body, token) || strings.Contains(body, "fetch(submitURL") || strings.Contains(body, "document.body.innerHTML =") || strings.Contains(body, "Solution submitted") {
			t.Fatalf("%s embeds credential or optimistic completion behavior", path)
		}
	}
}

func TestOperatorCompletionClientState(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for completion controller state tests")
	}
	command := exec.Command(node, "operator_completion_test.js")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("completion controller state tests: %v\n%s", err, output)
	}
}
