package scrub

import (
	"testing"
	"time"
)

func TestReviewReplacementTokenTerminates(t *testing.T) {
	done := make(chan struct{})
	go func() {
		NewGate(nil, []string{"red"}, "alias.local").Scrub("red", "review")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("accepted identity token 'red' loops while re-scrubbing [REDACTED]")
	}
}
