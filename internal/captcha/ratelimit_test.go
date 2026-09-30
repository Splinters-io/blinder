package captcha

import (
	"testing"
	"time"
)

func TestAuthRateLimiter(t *testing.T) {
	l := newAuthRateLimiter(3, 100*time.Millisecond)

	for i := 0; i < 3; i++ {
		if !l.allowed() {
			t.Fatalf("should be allowed before limit reached (attempt %d)", i+1)
		}
		l.recordFailure()
	}

	if l.allowed() {
		t.Fatal("should be blocked after reaching limit")
	}

	time.Sleep(150 * time.Millisecond)

	if !l.allowed() {
		t.Fatal("should be allowed after window expires")
	}
}

func TestAuthRateLimiterSuccessDoesNotCount(t *testing.T) {
	l := newAuthRateLimiter(3, time.Minute)

	l.recordFailure()
	l.recordFailure()

	if !l.allowed() {
		t.Fatal("should still be allowed with 2 failures under limit of 3")
	}

	l.recordFailure()

	if l.allowed() {
		t.Fatal("should be blocked at 3 failures")
	}
}
