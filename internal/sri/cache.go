package sri

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
)

type CacheEntry struct {
	FetchError      string
	ScrubbedBody    []byte
	ReplacementHash string
	ContentType     string
	BytesModified   bool
	ResponseHeaders http.Header
	OriginalDigests map[string][]byte
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

func (c *Cache) Put(key string, entry *CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

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
	if _, exists := c.digestIndex[key]; !exists {
		c.digestIndex[key] = sha256.Sum256(rawBody)
	}
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
