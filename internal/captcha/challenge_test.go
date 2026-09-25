package captcha

import (
	"context"
	"testing"
	"time"
)

func TestChallengeQueueSubmitAndGet(t *testing.T) {
	q := NewChallengeQueue(5 * time.Minute)

	id := q.Submit("hcaptcha", "https://example.com/login", []byte("<html>challenge</html>"), "text/html")

	if id == "" {
		t.Fatal("empty challenge ID")
	}

	ch, ok := q.Get(id)
	if !ok {
		t.Fatal("challenge not found after submit")
	}
	if ch.ProviderName != "hcaptcha" {
		t.Fatalf("wrong provider: %s", ch.ProviderName)
	}
	if ch.PageURL != "https://example.com/login" {
		t.Fatalf("wrong page URL: %s", ch.PageURL)
	}
	if string(ch.PageBody) != "<html>challenge</html>" {
		t.Fatalf("wrong body: %s", ch.PageBody)
	}
}

func TestChallengeQueuePending(t *testing.T) {
	q := NewChallengeQueue(5 * time.Minute)

	q.Submit("hcaptcha", "https://a.com/1", []byte("a"), "text/html")
	q.Submit("turnstile", "https://b.com/2", []byte("b"), "text/html")

	pending := q.Pending()
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending, got %d", len(pending))
	}
}

func TestChallengeQueueComplete(t *testing.T) {
	q := NewChallengeQueue(5 * time.Minute)

	id := q.Submit("hcaptcha", "https://example.com/login", []byte("challenge"), "text/html")

	solution := map[string]string{"h-captcha-response": "token123"}
	if !q.Complete(id, solution) {
		t.Fatal("complete returned false")
	}

	pending := q.Pending()
	if len(pending) != 0 {
		t.Fatalf("expected 0 pending after completion, got %d", len(pending))
	}

	if q.Complete(id, solution) {
		t.Fatal("double complete should return false")
	}
}

func TestChallengeQueueCompleteNonexistent(t *testing.T) {
	q := NewChallengeQueue(5 * time.Minute)

	if q.Complete("nonexistent", map[string]string{"x": "y"}) {
		t.Fatal("complete of nonexistent should return false")
	}
}

func TestChallengeQueueWaitForCompletion(t *testing.T) {
	q := NewChallengeQueue(5 * time.Minute)

	id := q.Submit("hcaptcha", "https://example.com", []byte("ch"), "text/html")

	go func() {
		time.Sleep(50 * time.Millisecond)
		q.Complete(id, map[string]string{"h-captcha-response": "solved"})
	}()

	sol, ok := q.WaitForCompletion(context.Background(), id, 2*time.Second)
	if !ok {
		t.Fatal("wait returned false")
	}
	if sol["h-captcha-response"] != "solved" {
		t.Fatalf("wrong solution: %v", sol)
	}
}

func TestChallengeQueueWaitTimeout(t *testing.T) {
	q := NewChallengeQueue(5 * time.Minute)

	id := q.Submit("hcaptcha", "https://example.com", []byte("ch"), "text/html")

	_, ok := q.WaitForCompletion(context.Background(), id, 100*time.Millisecond)
	if ok {
		t.Fatal("wait should timeout")
	}
}

func TestChallengeQueueExpiry(t *testing.T) {
	q := NewChallengeQueue(1 * time.Millisecond)

	q.Submit("hcaptcha", "https://example.com", []byte("ch"), "text/html")
	time.Sleep(10 * time.Millisecond)

	pending := q.Pending()
	if len(pending) != 0 {
		t.Fatalf("expected expired challenge to be removed, got %d pending", len(pending))
	}
}

func TestChallengeQueueGetReturnsCopy(t *testing.T) {
	q := NewChallengeQueue(5 * time.Minute)

	id := q.Submit("hcaptcha", "https://example.com", []byte("original"), "text/html")

	ch1, _ := q.Get(id)
	ch2, _ := q.Get(id)

	ch1.PageURL = "mutated"
	if ch2.PageURL == "mutated" {
		t.Fatal("Get returned a shared reference, not a copy")
	}
}

func TestChallengeQueueSubmitCopiesBody(t *testing.T) {
	q := NewChallengeQueue(5 * time.Minute)

	body := []byte("original")
	id := q.Submit("hcaptcha", "https://example.com", body, "text/html")

	body[0] = 'X'

	ch, _ := q.Get(id)
	if string(ch.PageBody) != "original" {
		t.Fatalf("submit did not copy body: %s", ch.PageBody)
	}
}
