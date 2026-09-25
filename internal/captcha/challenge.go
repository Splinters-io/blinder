package captcha

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type Challenge struct {
	ID           string
	ProviderName string
	PageURL      string
	PageBody     []byte
	ContentType  string
	FormAction   string
	FormMethod   string
	FormFields   map[string]string
	CreatedAt    time.Time
	CompletedAt  time.Time
	Solution     map[string]string
}

type completionSignal struct {
	mu   sync.Mutex
	ch   chan struct{}
	done bool
}

func newCompletionSignal() *completionSignal {
	return &completionSignal{ch: make(chan struct{})}
}

func (s *completionSignal) signal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.done {
		s.done = true
		close(s.ch)
	}
}

func (s *completionSignal) wait() <-chan struct{} {
	return s.ch
}

const (
	maxPendingChallenges = 64
	maxChallengeBodySize = 2 * 1024 * 1024
)

type ChallengeQueue struct {
	mu        sync.Mutex
	pending   map[string]*Challenge
	completed map[string]*Challenge
	signals   map[string]*completionSignal
	waiters   map[string]bool
	maxAge    time.Duration
}

func NewChallengeQueue(maxAge time.Duration) *ChallengeQueue {
	if maxAge <= 0 {
		maxAge = 10 * time.Minute
	}
	return &ChallengeQueue{
		pending:   make(map[string]*Challenge),
		completed: make(map[string]*Challenge),
		signals:   make(map[string]*completionSignal),
		waiters:   make(map[string]bool),
		maxAge:    maxAge,
	}
}

func (q *ChallengeQueue) Submit(providerName, pageURL string, pageBody []byte, contentType string, formOpts ...string) string {
	id := generateChallengeID()
	body := pageBody
	if len(body) > maxChallengeBodySize {
		body = body[:maxChallengeBodySize]
	}

	var formAction, formMethod string
	if len(formOpts) >= 1 {
		formAction = formOpts[0]
	}
	if len(formOpts) >= 2 {
		formMethod = formOpts[1]
	}

	ch := &Challenge{
		ID:           id,
		ProviderName: providerName,
		PageURL:      pageURL,
		PageBody:     append([]byte(nil), body...),
		ContentType:  contentType,
		FormAction:   formAction,
		FormMethod:   formMethod,
		CreatedAt:    time.Now(),
	}

	q.mu.Lock()
	q.expireLocked()
	if len(q.pending) >= maxPendingChallenges {
		q.evictOldestLocked()
	}
	q.pending[id] = ch
	q.signals[id] = newCompletionSignal()
	q.mu.Unlock()

	return id
}

func (q *ChallengeQueue) SetFormFields(id string, fields map[string]string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	ch, ok := q.pending[id]
	if !ok {
		return
	}
	cp := make(map[string]string, len(fields))
	for k, v := range fields {
		cp[k] = v
	}
	ch.FormFields = cp
}

func (q *ChallengeQueue) Pending() []*Challenge {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.expireLocked()

	result := make([]*Challenge, 0, len(q.pending))
	for _, ch := range q.pending {
		result = append(result, copyChallenge(ch))
	}
	return result
}

func (q *ChallengeQueue) Get(id string) (*Challenge, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	ch, ok := q.pending[id]
	if !ok {
		return nil, false
	}
	if q.isExpired(ch) {
		q.removePendingLocked(id)
		return nil, false
	}
	return copyChallenge(ch), true
}

func (q *ChallengeQueue) Complete(id string, solution map[string]string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	ch, ok := q.pending[id]
	if !ok {
		return false
	}
	if q.isExpired(ch) {
		q.removePendingLocked(id)
		return false
	}

	solCopy := make(map[string]string, len(solution))
	for k, v := range solution {
		solCopy[k] = v
	}

	var fieldsCopy map[string]string
	if len(ch.FormFields) > 0 {
		fieldsCopy = make(map[string]string, len(ch.FormFields))
		for k, v := range ch.FormFields {
			fieldsCopy[k] = v
		}
	}

	completed := &Challenge{
		ID:           ch.ID,
		ProviderName: ch.ProviderName,
		PageURL:      ch.PageURL,
		ContentType:  ch.ContentType,
		FormAction:   ch.FormAction,
		FormMethod:   ch.FormMethod,
		FormFields:   fieldsCopy,
		CreatedAt:    ch.CreatedAt,
		CompletedAt:  time.Now(),
		Solution:     solCopy,
	}

	delete(q.pending, id)
	q.completed[id] = completed

	if sig, ok := q.signals[id]; ok {
		sig.signal()
	}

	return true
}

func (q *ChallengeQueue) Cancel(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.removePendingLocked(id)
}

func (q *ChallengeQueue) WaitForCompletion(ctx context.Context, id string, timeout time.Duration) (map[string]string, bool) {
	q.mu.Lock()
	if ch, ok := q.completed[id]; ok {
		q.mu.Unlock()
		return copySolution(ch.Solution), true
	}
	sig, ok := q.signals[id]
	if !ok {
		q.mu.Unlock()
		return nil, false
	}
	q.waiters[id] = true
	q.mu.Unlock()

	defer func() {
		q.mu.Lock()
		delete(q.waiters, id)
		q.mu.Unlock()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-sig.wait():
	case <-timer.C:
		return nil, false
	case <-ctx.Done():
		return nil, false
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if ch, ok := q.completed[id]; ok {
		return copySolution(ch.Solution), true
	}
	return nil, false
}

func (q *ChallengeQueue) GetCompleted(id string) (*Challenge, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	ch, ok := q.completed[id]
	if !ok {
		return nil, false
	}
	return copyChallenge(ch), true
}

func (q *ChallengeQueue) HasWaiter(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.waiters[id]
}

func (q *ChallengeQueue) Shutdown() {
	q.mu.Lock()
	defer q.mu.Unlock()

	for id := range q.pending {
		q.removePendingLocked(id)
	}
	for id := range q.completed {
		delete(q.completed, id)
	}
}

func (q *ChallengeQueue) removePendingLocked(id string) {
	delete(q.pending, id)
	if sig, ok := q.signals[id]; ok {
		sig.signal()
		delete(q.signals, id)
	}
}

func (q *ChallengeQueue) evictOldestLocked() {
	var oldestID string
	var oldestTime time.Time
	for id, ch := range q.pending {
		if oldestID == "" || ch.CreatedAt.Before(oldestTime) {
			oldestID = id
			oldestTime = ch.CreatedAt
		}
	}
	if oldestID != "" {
		q.removePendingLocked(oldestID)
	}
}

func (q *ChallengeQueue) isExpired(ch *Challenge) bool {
	return time.Since(ch.CreatedAt) > q.maxAge
}

func (q *ChallengeQueue) expireLocked() {
	for id, ch := range q.pending {
		if q.isExpired(ch) {
			q.removePendingLocked(id)
		}
	}
	cutoff := time.Now().Add(-q.maxAge)
	for id, ch := range q.completed {
		if ch.CompletedAt.Before(cutoff) {
			delete(q.completed, id)
			delete(q.signals, id)
		}
	}
}

func copyChallenge(ch *Challenge) *Challenge {
	cp := *ch
	cp.PageBody = append([]byte(nil), ch.PageBody...)
	if ch.Solution != nil {
		cp.Solution = copySolution(ch.Solution)
	}
	return &cp
}

func copySolution(m map[string]string) map[string]string {
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func generateChallengeID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
