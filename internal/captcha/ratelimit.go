package captcha

import (
	"sync"
	"time"
)

type authRateLimiter struct {
	mu       sync.Mutex
	failures []time.Time
	limit    int
	window   time.Duration
}

func newAuthRateLimiter(limit int, window time.Duration) *authRateLimiter {
	return &authRateLimiter{
		limit:  limit,
		window: window,
	}
}

func (l *authRateLimiter) recordFailure() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures = append(l.failures, time.Now())
}

func (l *authRateLimiter) allowed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-l.window)
	n := 0
	for _, t := range l.failures {
		if t.After(cutoff) {
			l.failures[n] = t
			n++
		}
	}
	l.failures = l.failures[:n]
	return n < l.limit
}
