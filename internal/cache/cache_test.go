package cache

import (
	"net/http"
	"testing"
	"time"
)

func TestComputeETag_Deterministic(t *testing.T) {
	body := []byte("hello world")
	e1 := ComputeETag(body)
	e2 := ComputeETag(body)
	if e1 != e2 {
		t.Errorf("same body should produce same ETag: %s vs %s", e1, e2)
	}
	if e1 == "" || e1[0] != '"' {
		t.Errorf("ETag should be a quoted string, got: %s", e1)
	}
	if !contains(e1, "bl-") {
		t.Errorf("downstream ETag should contain bl- prefix, got: %s", e1)
	}
}

func TestComputeETag_DifferentBodies(t *testing.T) {
	e1 := ComputeETag([]byte("body A"))
	e2 := ComputeETag([]byte("body B"))
	if e1 == e2 {
		t.Error("different bodies should produce different ETags")
	}
}

func TestMatchesETag(t *testing.T) {
	etag := `"bl-abc123"`
	tests := []struct {
		name  string
		inm   string
		match bool
	}{
		{"exact match", `"bl-abc123"`, true},
		{"weak match", `W/"bl-abc123"`, true},
		{"no match", `"bl-xyz789"`, false},
		{"wildcard", "*", true},
		{"empty", "", false},
		{"multiple with match", `"other", "bl-abc123"`, true},
		{"multiple no match", `"other", "another"`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesETag(tt.inm, etag)
			if got != tt.match {
				t.Errorf("MatchesETag(%q, %q) = %v, want %v", tt.inm, etag, got, tt.match)
			}
		})
	}
}

func TestParseDirectives(t *testing.T) {
	tests := []struct {
		header string
		check  func(Directives) bool
		desc   string
	}{
		{"no-store", func(d Directives) bool { return d.NoStore }, "no-store parsed"},
		{"no-cache", func(d Directives) bool { return d.NoCache }, "no-cache parsed"},
		{"private", func(d Directives) bool { return d.Private }, "private parsed"},
		{"must-revalidate", func(d Directives) bool { return d.MustRevalidate }, "must-revalidate parsed"},
		{"max-age=3600", func(d Directives) bool { return d.MaxAge == 3600 }, "max-age parsed"},
		{"public, max-age=60", func(d Directives) bool { return d.MaxAge == 60 && !d.Private }, "combined"},
		{"", func(d Directives) bool { return d.MaxAge == -1 }, "empty defaults to max-age -1"},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			d := ParseDirectives(tt.header)
			if !tt.check(d) {
				t.Errorf("ParseDirectives(%q) failed check: %s", tt.header, tt.desc)
			}
		})
	}
}

func TestParseVary(t *testing.T) {
	tests := []struct {
		header string
		count  int
		star   bool
	}{
		{"", 0, false},
		{"Accept-Encoding", 1, false},
		{"Accept-Encoding, Accept-Language", 2, false},
		{"*", 1, true},
	}
	for _, tt := range tests {
		fields := ParseVary(tt.header)
		if len(fields) != tt.count {
			t.Errorf("ParseVary(%q) = %d fields, want %d", tt.header, len(fields), tt.count)
		}
		if tt.star && (len(fields) == 0 || fields[0] != "*") {
			t.Errorf("ParseVary(%q) should return [*]", tt.header)
		}
	}
}

func TestResponseCache_StoreAndLookup(t *testing.T) {
	rc := New(100)
	entry := Entry{
		Body:       []byte("test body"),
		StatusCode: 200,
		ETag:       ComputeETag([]byte("test body")),
		Directives: Directives{MaxAge: 3600},
		StoredAt:   time.Now(),
	}
	rc.Store("key1", entry)

	got, ok := rc.Lookup("key1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(got.Body) != "test body" {
		t.Errorf("expected body 'test body', got %q", got.Body)
	}
	if got.ETag != entry.ETag {
		t.Errorf("ETag mismatch: %s vs %s", got.ETag, entry.ETag)
	}
}

func TestResponseCache_NoStoreSkipped(t *testing.T) {
	rc := New(100)
	entry := Entry{
		Body:       []byte("secret"),
		Directives: Directives{NoStore: true},
	}
	rc.Store("key1", entry)
	if rc.Len() != 0 {
		t.Error("no-store entry should not be cached")
	}
}

func TestResponseCache_LRUEviction(t *testing.T) {
	rc := New(2)
	for i := 0; i < 3; i++ {
		rc.Store("key"+string(rune('A'+i)), Entry{
			Body:       []byte("body"),
			Directives: Directives{MaxAge: 3600},
			StoredAt:   time.Now(),
		})
	}
	if rc.Len() != 2 {
		t.Errorf("expected 2 entries after eviction, got %d", rc.Len())
	}
	if _, ok := rc.Lookup("keyA"); ok {
		t.Error("oldest entry should have been evicted")
	}
	if _, ok := rc.Lookup("keyC"); !ok {
		t.Error("newest entry should still exist")
	}
}

func TestEntry_IsFresh(t *testing.T) {
	tests := []struct {
		name  string
		entry Entry
		fresh bool
	}{
		{
			"fresh with max-age",
			Entry{Directives: Directives{MaxAge: 3600}, StoredAt: time.Now()},
			true,
		},
		{
			"stale max-age=0",
			Entry{Directives: Directives{MaxAge: 0}, StoredAt: time.Now().Add(-time.Second)},
			false,
		},
		{
			"no-cache always stale",
			Entry{Directives: Directives{NoCache: true, MaxAge: 3600}, StoredAt: time.Now()},
			false,
		},
		{
			"must-revalidate always stale",
			Entry{Directives: Directives{MustRevalidate: true, MaxAge: 3600}, StoredAt: time.Now()},
			false,
		},
		{
			"unset max-age (-1) stale",
			Entry{Directives: Directives{MaxAge: -1}, StoredAt: time.Now()},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.entry.IsFresh(); got != tt.fresh {
				t.Errorf("IsFresh() = %v, want %v", got, tt.fresh)
			}
		})
	}
}

func TestKey_CredentialIsolation(t *testing.T) {
	req := &http.Request{Header: http.Header{}}
	k1 := Key("http://example.com/", false, req, nil)
	k2 := Key("http://example.com/", true, req, nil)
	if k1 == k2 {
		t.Error("authed and anon keys must differ")
	}
}

func TestKey_VaryDimensions(t *testing.T) {
	req1 := &http.Request{Header: http.Header{"Accept-Language": {"en"}}}
	req2 := &http.Request{Header: http.Header{"Accept-Language": {"fr"}}}
	vary := []string{"Accept-Language"}
	k1 := Key("http://example.com/", false, req1, vary)
	k2 := Key("http://example.com/", false, req2, vary)
	if k1 == k2 {
		t.Error("different Vary values must produce different keys")
	}
}

func TestHasCredentials(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		want   bool
	}{
		{"no creds", http.Header{}, false},
		{"cookie", http.Header{"Cookie": {"session=abc"}}, true},
		{"auth", http.Header{"Authorization": {"Bearer tok"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{Header: tt.header}
			if got := HasCredentials(req); got != tt.want {
				t.Errorf("HasCredentials() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResponseCache_Touch(t *testing.T) {
	rc := New(100)
	entry := Entry{
		Body:       []byte("body"),
		StoredAt:   time.Now().Add(-time.Hour),
		Directives: Directives{MaxAge: 1800},
	}
	rc.Store("k", entry)

	got, _ := rc.Lookup("k")
	if got.IsFresh() {
		t.Fatal("should be stale before touch")
	}

	rc.Touch("k")
	got, _ = rc.Lookup("k")
	if !got.IsFresh() {
		t.Error("should be fresh after touch")
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
