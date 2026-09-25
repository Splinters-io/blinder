package sri

import (
	"testing"
)

func TestCache_PutGet(t *testing.T) {
	c := NewCache(10)
	entry := &CacheEntry{ReplacementHash: "sha384-abc"}
	c.Put("https://example.com/bundle.js", entry)

	got, ok := c.Get("https://example.com/bundle.js")
	if !ok {
		t.Fatal("expected entry to be found")
	}
	if got.ReplacementHash != "sha384-abc" {
		t.Errorf("got hash %q", got.ReplacementHash)
	}
}

func TestCache_Miss(t *testing.T) {
	c := NewCache(10)
	_, ok := c.Get("https://example.com/missing.js")
	if ok {
		t.Error("expected miss for absent key")
	}
}

func TestCache_Eviction(t *testing.T) {
	c := NewCache(3)
	for i := 0; i < 5; i++ {
		c.Put(string(rune('a'+i)), &CacheEntry{ReplacementHash: string(rune('a' + i))})
	}
	if c.Len() != 3 {
		t.Errorf("cache should be bounded to 3, got %d", c.Len())
	}
	if _, ok := c.Get("a"); ok {
		t.Error("oldest entry 'a' should have been evicted")
	}
	if _, ok := c.Get("b"); ok {
		t.Error("second oldest 'b' should have been evicted")
	}
	if _, ok := c.Get("c"); !ok {
		t.Error("'c' should still be present")
	}
}

func TestCache_Clear(t *testing.T) {
	c := NewCache(10)
	c.Put("k1", &CacheEntry{})
	c.Put("k2", &CacheEntry{})
	c.Clear()
	if c.Len() != 0 {
		t.Errorf("cache should be empty after clear, got %d", c.Len())
	}
}

func TestCache_UpdateExisting(t *testing.T) {
	c := NewCache(3)
	c.Put("k1", &CacheEntry{ReplacementHash: "old"})
	c.Put("k1", &CacheEntry{ReplacementHash: "new"})

	if c.Len() != 1 {
		t.Errorf("update should not grow cache, got %d", c.Len())
	}
	got, _ := c.Get("k1")
	if got.ReplacementHash != "new" {
		t.Errorf("should reflect update, got %q", got.ReplacementHash)
	}
}
