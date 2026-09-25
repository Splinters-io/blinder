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

type Entry struct {
	Body        []byte
	StatusCode  int
	Headers     http.Header
	ContentType string

	ETag string

	UpstreamETag         string
	UpstreamLastModified string
	UpstreamACAO         string

	VaryFields   []string
	VaryValues   map[string]string
	VarySentinel bool

	Directives Directives
	InitialAge int
	StoredAt   time.Time
}

type Directives struct {
	NoStore        bool
	NoCache        bool
	Private        bool
	MustRevalidate bool
	MaxAge         int // seconds; -1 means unset
}

type ResponseCache struct {
	mu       sync.Mutex
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

func ComputeETag(body []byte) string {
	h := sha256.Sum256(body)
	return `"bl-` + hex.EncodeToString(h[:8]) + `"`
}

func CredentialHash(req *http.Request) string {
	cookie := req.Header.Get("Cookie")
	auth := req.Header.Get("Authorization")
	if cookie == "" && auth == "" {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(cookie))
	h.Write([]byte{0})
	h.Write([]byte(auth))
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func Key(rawURL string, credHash string, req *http.Request, varyFields []string) string {
	var b strings.Builder
	b.WriteString(rawURL)
	b.WriteByte('\x00')
	b.WriteString(credHash)
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

func (c *ResponseCache) Lookup(key string) (Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return Entry{}, false
	}
	c.promote(key)
	cp := *e
	return cp, true
}

func (c *ResponseCache) Store(key string, entry Entry) {
	if entry.Directives.NoStore || entry.Directives.Private {
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

func (c *ResponseCache) Touch(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		updated := *e
		updated.StoredAt = time.Now()
		c.entries[key] = &updated
	}
}

func (c *ResponseCache) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; !ok {
		return
	}
	delete(c.entries, key)
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

func (c *ResponseCache) Revalidate(key string, respHeaders http.Header) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return
	}

	if cc := respHeaders.Get("Cache-Control"); cc != "" {
		dirs := ParseDirectives(cc)
		if dirs.NoStore || dirs.Private {
			delete(c.entries, key)
			for i, k := range c.order {
				if k == key {
					c.order = append(c.order[:i], c.order[i+1:]...)
					break
				}
			}
			return
		}
	}

	updated := *e
	updated.Headers = e.Headers.Clone()
	updated.StoredAt = time.Now()

	if cc := respHeaders.Get("Cache-Control"); cc != "" {
		updated.Directives = ParseDirectives(cc)
		updated.Headers.Set("Cache-Control", cc)
	}
	if etag := respHeaders.Get("ETag"); etag != "" {
		updated.UpstreamETag = etag
	}
	if lm := respHeaders.Get("Last-Modified"); lm != "" {
		updated.UpstreamLastModified = lm
	}
	if age := respHeaders.Get("Age"); age != "" {
		updated.InitialAge = ParseAge(age)
	} else {
		updated.InitialAge = 0
	}
	if vary := respHeaders.Get("Vary"); vary != "" {
		updated.VaryFields = ParseVary(vary)
		updated.Headers.Set("Vary", vary)
	}
	c.entries[key] = &updated
	c.promote(key)
}

func (c *ResponseCache) UpdatePolicyHeaders(key string, headers http.Header, names []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return
	}
	updated := *e
	updated.Headers = e.Headers.Clone()
	for _, name := range names {
		vals := headers.Values(name)
		if len(vals) > 0 {
			updated.Headers.Del(name)
			for _, v := range vals {
				updated.Headers.Add(name, v)
			}
		}
	}
	c.entries[key] = &updated
}

func (c *ResponseCache) InvalidateURL(rawURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prefix := rawURL + "\x00"
	var remaining []string
	for _, key := range c.order {
		if key == rawURL || strings.HasPrefix(key, prefix) {
			delete(c.entries, key)
		} else {
			remaining = append(remaining, key)
		}
	}
	c.order = remaining
}

func (c *ResponseCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *ResponseCache) promote(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			c.order = append(c.order, key)
			return
		}
	}
}

func (c *ResponseCache) evict() {
	for len(c.entries) > c.maxItems && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
}

func (e *Entry) IsFresh() bool {
	if e.Directives.NoCache {
		return false
	}
	if e.Directives.MaxAge < 0 {
		return false
	}
	currentAge := e.InitialAge + int(time.Since(e.StoredAt).Seconds())
	return currentAge < e.Directives.MaxAge
}

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

func HasCredentials(req *http.Request) bool {
	return req.Header.Get("Cookie") != "" || req.Header.Get("Authorization") != ""
}

func ParseAge(header string) int {
	v, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil || v < 0 {
		return 0
	}
	return v
}
