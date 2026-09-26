package manifest

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRequestIdentityConcurrentAndArrivalOrdered(t *testing.T) {
	s := NewSession("alias.local", "https://target.example")
	if raw, err := hex.DecodeString(s.SessionID()); err != nil || len(raw) != 16 {
		t.Fatalf("invalid session identity: %q", s.SessionID())
	}
	if other := NewSession("alias.local", "https://target.example"); other.SessionID() == s.SessionID() {
		t.Fatal("independent sessions reused identity")
	}
	first, second := s.NewRequestID(), s.NewRequestID()
	s.RecordExchange(RequestEntry{RequestID: second, Method: "GET"})
	s.RecordExchange(RequestEntry{RequestID: first, Method: "GET"})
	if entries := s.Requests(); entries[0].RequestID != second || entries[1].RequestID != first {
		t.Fatal("completion order changed reserved request identities")
	}
	const count = 64
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.RecordExchange(RequestEntry{RequestID: s.NewRequestID(), Method: "vendor.sync"})
		}()
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, entry := range s.Requests() {
		if seen[entry.RequestID] || !strings.HasPrefix(entry.RequestID, s.SessionID()+":") || entry.Timestamp == "" {
			t.Fatalf("missing or reused identity: %+v", entry)
		}
		seen[entry.RequestID] = true
	}
	if len(seen) != count+2 {
		t.Fatalf("lost requests: %d", len(seen))
	}
}

func TestRequestIdentitySnapshotsAndPersistence(t *testing.T) {
	s := NewSession("alias.local", "https://target.example")
	delta := int64(3)
	entry := RequestEntry{
		RequestID: s.NewRequestID(), Method: "POST", Path: "/submit", ContextTag: "context", RequestTag: "request",
		Response: &ResponseMetrics{Source: "upstream", OriginalBodyTag: "original", RewrittenBodyTag: "rewritten", BodyComplete: true,
			Upstream: []BodyRead{{StatusCode: 422, DecodedBytes: 10, Complete: true}}, RewriteDeltaBytes: &delta},
	}
	s.RecordExchange(entry)
	entry.Method = "DELETE"
	entry.Response.BodyComplete = false
	entry.Response.Upstream[0].DecodedBytes = 999
	delta = 999
	first := s.Requests()[0]
	if first.Method != "POST" || !first.Response.BodyComplete || first.Response.Upstream[0].DecodedBytes != 10 || *first.Response.RewriteDeltaBytes != 3 {
		t.Fatalf("record retains caller memory: %+v", first)
	}
	first.Response.OriginalBodyTag = "changed"
	first.Response.Upstream[0].Complete = false
	*first.Response.RewriteDeltaBytes = 888
	second := s.Requests()[0]
	if second.Response.OriginalBodyTag != "original" || !second.Response.Upstream[0].Complete || *second.Response.RewriteDeltaBytes != 3 {
		t.Fatal("snapshot mutates stored measurements")
	}
	dir := t.TempDir()
	if err := s.Flush(dir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "blinder-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted ManifestFile
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.SessionID != s.SessionID() || len(persisted.Requests) != 1 || persisted.Requests[0].RequestID != entry.RequestID || persisted.Requests[0].Response.RewrittenBodyTag != "rewritten" || !persisted.Requests[0].Response.BodyComplete {
		t.Fatalf("persistence lost evidence identity: %+v", persisted)
	}
}
