package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Entry stores a rewritten response with separate upstream and downstream validators.
type Entry struct {
	Body        []byte
	StatusCode  int
	Headers     http.Header
	ContentType string

	// Downstream validator: computed from the rewritten Body bytes.
	ETag string

	// Upstream validators: used for conditional revalidation with origin.
	UpstreamETag         string
	UpstreamLastModified string

	VaryFields []string
	VaryValues map[string]string

	HasCredentials bool
	Directives     Directives
	StoredAt       time.Time
}

// Directives holds parsed Cache-Control values.
type Directives struct {
	NoStore        bool
	NoCache        bool
	Private        bool
	MustRevalidate bool
	MaxAge         int // seconds; -1 means unset
}

// ResponseCache is a thread-safe LRU cache for rewritten responses.
type ResponseCache struct {
	mu       sync.RWMutex
	entries  map[string]*Entry
	order    []string
	maxItems int
}

func New(maxItems int) *ResponseCache {
	if maxItems <= 0 {
		maxItems = 4096
	}
	return &ResponseCache{
		entries:  make(map[string]*Entry),
		maxItems: maxItems,
	}
}

// ComputeETag returns a strong ETag for the given response body.
// The "bl-" prefix distinguishes downstream ETags from upstream ones.
func ComputeETag(body []byte) string {
	h := sha256.Sum256(body)
	return `"bl-` + hex.EncodeToString(h[:8]) + `"`
}

// Key computes the cache lookup key from URL, credential state and Vary dimensions.
func Key(rawURL string, hasCredentials bool, req *http.Request, varyFields []string) string {
	var b strings.Builder
	b.WriteString(rawURL)
	b.WriteByte('\x00')
	if hasCredentials {
		b.WriteString("authed")
	} else {
		b.WriteString("anon")
	}
	for _, field := range varyFields {
		b.WriteByte('\x00')
		b.WriteString(strings.ToLower(field))
		b.WriteByte('=')
		if req != nil {
			b.WriteString(req.Header.Get(field))
		}
	}
	return b.String()
}

// Lookup returns a copy of the cached entry for the given key, if present.
func (c *ResponseCache) Lookup(key string) (Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok {
		return Entry{}, false
	}
	cp := *e
	return cp, true
}

// Store adds or replaces a cache entry. NoStore entries are silently dropped.
func (c *ResponseCache) Store(key string, entry Entry) {
	if entry.Directives.NoStore {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists {
		c.order = append(c.order, key)
	}
	stored := entry
	c.entries[key] = &stored
	c.evict()
}

// Touch refreshes the StoredAt timestamp on an existing entry.
func (c *ResponseCache) Touch(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		updated := *e
		updated.StoredAt = time.Now()
		c.entries[key] = &updated
	}
}

// Len returns the number of cached entries.
func (c *ResponseCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *ResponseCache) evict() {
	for len(c.entries) > c.maxItems && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
}

// IsFresh reports whether the entry is still usable without revalidation.
func (e *Entry) IsFresh() bool {
	if e.Directives.NoCache || e.Directives.MustRevalidate {
		return false
	}
	if e.Directives.MaxAge < 0 {
		return false
	}
	return time.Since(e.StoredAt) < time.Duration(e.Directives.MaxAge)*time.Second
}

// MatchesETag reports whether the given If-None-Match value matches this entry.
func MatchesETag(ifNoneMatch, etag string) bool {
	if ifNoneMatch == "" || etag == "" {
		return false
	}
	if ifNoneMatch == "*" {
		return true
	}
	for _, tag := range splitETags(ifNoneMatch) {
		if weakEqual(tag, etag) {
			return true
		}
	}
	return false
}

func splitETags(s string) []string {
	var tags []string
	for _, part := range strings.Split(s, ",") {
		tag := strings.TrimSpace(part)
		if tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

func weakEqual(a, b string) bool {
	return strings.TrimPrefix(a, "W/") == strings.TrimPrefix(b, "W/")
}

// ParseDirectives extracts Cache-Control directives from the header value.
func ParseDirectives(header string) Directives {
	d := Directives{MaxAge: -1}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		switch {
		case part == "no-store":
			d.NoStore = true
		case part == "no-cache":
			d.NoCache = true
		case part == "private":
			d.Private = true
		case part == "must-revalidate":
			d.MustRevalidate = true
		case strings.HasPrefix(part, "max-age="):
			if v, err := strconv.Atoi(strings.TrimPrefix(part, "max-age=")); err == nil {
				d.MaxAge = v
			}
		}
	}
	return d
}

// ParseVary extracts header field names from a Vary header value.
// Returns ["*"] for Vary: * (uncacheable).
func ParseVary(header string) []string {
	if header == "" {
		return nil
	}
	if strings.TrimSpace(strings.ToLower(header)) == "*" {
		return []string{"*"}
	}
	var fields []string
	for _, f := range strings.Split(header, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			fields = append(fields, f)
		}
	}
	return fields
}

// CaptureVaryValues records request header values for the given Vary fields.
func CaptureVaryValues(req *http.Request, fields []string) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	vals := make(map[string]string, len(fields))
	for _, f := range fields {
		vals[strings.ToLower(f)] = req.Header.Get(f)
	}
	return vals
}

// HasCredentials reports whether the request carries authentication material.
func HasCredentials(req *http.Request) bool {
	return req.Header.Get("Cookie") != "" || req.Header.Get("Authorization") != ""
}
