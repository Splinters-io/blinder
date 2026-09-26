package sri

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

type CacheEntry struct {
	FetchError   string
	ScrubbedBody []byte
	// ReplacementHash describes all supported digests of ScrubbedBody for
	// compatibility with cache inspectors; it is not per-reference metadata.
	ReplacementHash   string
	ContentType       string
	BytesModified     bool
	ResponseHeaders   http.Header
	OriginalDigests   map[string][]byte
	BodyVersion       string
	OriginalBodyBytes int64
	OriginalBodyKnown bool
}

func CacheKey(resourceURL string, req *http.Request) string {
	key := resourceURL
	if req != nil {
		cookie := req.Header.Get("Cookie")
		auth := req.Header.Get("Authorization")
		if cookie != "" || auth != "" {
			h := sha256.Sum256([]byte(cookie + "\x00" + auth))
			key += "\x00" + hex.EncodeToString(h[:8])
		}
	}
	return key
}

// CacheKeyForAuthority separates transformed bytes by browser entry authority.
// The URL prefix remains intact so a write invalidates all representations.
func CacheKeyForAuthority(resourceURL string, req *http.Request, authority string) string {
	return CacheKey(resourceURL, req) + "\x00view=" + authority
}

type Cache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	order   []string
	maxSize int

	digestIndex map[string][32]byte
}

func NewCache(maxSize int) *Cache {
	if maxSize <= 0 {
		maxSize = 256
	}
	return &Cache{
		entries:     make(map[string]*CacheEntry),
		maxSize:     maxSize,
		digestIndex: make(map[string][32]byte),
	}
}

func (c *Cache) Get(key string) (*CacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	return e, ok
}

func (c *Cache) getForDocument(key string, reserved ...map[string]string) (*CacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || len(reserved) == 0 || len(reserved[0]) == 0 {
		return entry, ok
	}
	original := entry.OriginalDigests["sha256"]
	if len(original) != sha256.Size || !c.sourceIdentityCollision(entry.ScrubbedBody, entry.OriginalDigests, reserved[0]) {
		return entry, true
	}
	// Published entries are immutable: concurrent users may still hold this
	// one, and previous documents can still request its registered version.
	copy := *entry
	if base, attempt, valid := collisionVersion(copy.BodyVersion); valid {
		suffix := sourceIdentitySuffix(original, attempt)
		if bytes.HasSuffix(copy.ScrubbedBody, suffix) {
			copy.ScrubbedBody = copy.ScrubbedBody[:len(copy.ScrubbedBody)-len(suffix)]
			copy.BodyVersion = base
		}
	}
	c.putResourceLocked(key, &copy, reserved[0])
	// The raw body is not retained, but its authenticated full SHA256 was.
	// Keep old version constraints and bind this newly selected variant too.
	c.digestIndex[key+"\x01"+copy.BodyVersion] = [32]byte(original)
	return &copy, true
}

func (c *Cache) Put(key string, entry *CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.putLocked(key, entry)
}

// PutResource reserves the rewritten source identity and publishes the entry
// under one lock. Distinct original JS/CSS bodies must not acquire the same CSP
// hash permission merely because their masked bytes converge. The scan is
// bounded by the existing cache capacity, with no additional identity index.
func (c *Cache) PutResource(key string, entry *CacheEntry, reserved ...map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var document map[string]string
	if len(reserved) > 0 {
		document = reserved[0]
	}
	c.putResourceLocked(key, entry, document)
}

func (c *Cache) putResourceLocked(key string, entry *CacheEntry, document map[string]string) {

	mediaType, _, _ := strings.Cut(strings.ToLower(entry.ContentType), ";")
	switch strings.TrimSpace(mediaType) {
	case "text/javascript", "application/javascript", "application/x-javascript", "text/ecmascript", "application/ecmascript", "text/css":
		original := entry.OriginalDigests["sha256"]
		// The caller owns document for one sequential rewrite. We only read
		// it; cache eviction must not erase the document's prior identities.
		base := entry.ScrubbedBody
		attempt := 0
		for len(original) == sha256.Size && c.sourceIdentityCollision(entry.ScrubbedBody, entry.OriginalDigests, document) {
			attempt++
			entry.ScrubbedBody = append(append([]byte(nil), base...), sourceIdentitySuffix(original, attempt)...)
			entry.BytesModified = true
		}
		if attempt > 0 {
			entry.BodyVersion += ".c" + strconv.Itoa(attempt)
		}
	}
	entry.ReplacementHash = ComputeIntegrity(entry.ScrubbedBody, "sha256") + " " + ComputeIntegrity(entry.ScrubbedBody, "sha384") + " " + ComputeIntegrity(entry.ScrubbedBody, "sha512")
	c.putLocked(key, entry)
}

func sourceIdentitySuffix(originalSHA256 []byte, attempt int) []byte {
	suffix := make([]byte, 0, 257+attempt-1)
	suffix = append(suffix, '\n')
	for _, b := range originalSHA256 {
		for bit := 7; bit >= 0; bit-- {
			if b&(1<<bit) == 0 {
				suffix = append(suffix, ' ')
			} else {
				suffix = append(suffix, '\t')
			}
		}
	}
	for i := 1; i < attempt; i++ {
		suffix = append(suffix, ' ')
	}
	return suffix
}

// ApplyBodyVersion reproduces a collision-specific representation after a
// no-store fetch or cache eviction. The caller must first authenticate the full
// original body against the registered version's digest. The version contains
// only the selected whitespace variant; it never supplies executable bytes.
func ApplyBodyVersion(raw, rewritten []byte, version string) []byte {
	base, attempt, valid := collisionVersion(version)
	if !valid {
		return rewritten
	}
	original := sha256.Sum256(raw)
	if base != "bl"+hex.EncodeToString(original[:8]) {
		return rewritten
	}
	return append(append([]byte(nil), rewritten...), sourceIdentitySuffix(original[:], attempt)...)
}

func collisionVersion(version string) (string, int, bool) {
	base, count, present := strings.Cut(version, ".c")
	if !present {
		return "", 0, false
	}
	attempt, err := strconv.Atoi(count)
	// Normal proxies have 256 cache entries. Allow larger bounded caches
	// without letting a malformed internal version request unbounded padding.
	if err != nil || attempt < 1 || attempt > 65536 {
		return "", 0, false
	}
	return base, attempt, true
}

// sourceIdentityCollision is called only with c.mu held. Errors and synthetic
// cache entries without an original digest do not reserve a source identity.
func (c *Cache) sourceIdentityCollision(body []byte, originals map[string][]byte, document map[string]string) bool {
	original := originals["sha256"]
	if len(document) > 0 {
		digests := computeAllDigests(body)
		if previous, ok := document[base64.StdEncoding.EncodeToString(digests["sha256"])]; ok && previous != base64.StdEncoding.EncodeToString(original) {
			return true
		}
		// Tagged entries reserve metadata permissions too. An invalid weaker
		// integrity item can translate into a hash which is not the current
		// resource's actual output; later resources must not acquire that grant.
		for algorithm, digest := range digests {
			key := algorithm + "-" + base64.StdEncoding.EncodeToString(digest)
			if previous, ok := document[key]; ok && previous != base64.StdEncoding.EncodeToString(originals[algorithm]) && previous != algorithm+"-"+base64.StdEncoding.EncodeToString(originals[algorithm]) {
				return true
			}
		}
	}
	for _, existing := range c.entries {
		previous := existing.OriginalDigests["sha256"]
		if len(previous) == sha256.Size && !bytes.Equal(previous, original) && bytes.Equal(body, existing.ScrubbedBody) {
			return true
		}
	}
	return false
}

func (c *Cache) putLocked(key string, entry *CacheEntry) {

	if _, exists := c.entries[key]; !exists {
		if len(c.order) >= c.maxSize {
			evict := c.order[0]
			c.order = c.order[1:]
			delete(c.entries, evict)
		}
		c.order = append(c.order, key)
	}
	c.entries[key] = entry
}

func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CacheEntry)
	c.order = nil
	c.digestIndex = make(map[string][32]byte)
}

func (c *Cache) InvalidateURL(rawURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prefix := rawURL + "\x00"
	var remaining []string
	for _, key := range c.order {
		if key == rawURL || strings.HasPrefix(key, prefix) {
			delete(c.entries, key)
			delete(c.digestIndex, key)
		} else {
			remaining = append(remaining, key)
		}
	}
	c.order = remaining
	for key := range c.digestIndex {
		if key == rawURL || strings.HasPrefix(key, prefix) {
			delete(c.digestIndex, key)
		}
	}
}

func (c *Cache) IndexDigest(key string, rawBody []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.digestIndex[key] = sha256.Sum256(rawBody)
}

func (c *Cache) HasDigest(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.digestIndex[key]
	return ok
}

func (c *Cache) CheckBodyIntegrity(key string, rawBody []byte) bool {
	c.mu.RLock()
	stored, ok := c.digestIndex[key]
	c.mu.RUnlock()
	if !ok {
		return true
	}
	actual := sha256.Sum256(rawBody)
	return stored == actual
}
