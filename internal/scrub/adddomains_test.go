package scrub

import (
	"strings"
	"sync"
	"testing"
)

func TestAddDomains_NewDomainScrubbed(t *testing.T) {
	g := NewGate([]string{"original.com"}, nil, "target-001.local")

	result := g.Scrub("Visit extra.example.org now", "test")
	if !strings.Contains(result, "extra.example.org") {
		t.Fatal("unknown domain should not be scrubbed before AddDomains")
	}

	g.AddDomains([]string{"extra.example.org"})

	result = g.Scrub("Visit extra.example.org now", "test")
	if strings.Contains(result, "extra.example.org") {
		t.Errorf("added domain should be scrubbed, got: %s", result)
	}
}

func TestAddDomains_ChildDelegates(t *testing.T) {
	parent := NewGate([]string{"original.com"}, nil, "target-001.local")
	child := parent.ForRequest()

	child.AddDomains([]string{"delegated.example.org"})

	fresh := parent.ForRequest()
	result := fresh.Scrub("Visit delegated.example.org", "test")
	if strings.Contains(result, "delegated.example.org") {
		t.Errorf("domain added via child should be visible to new children, got: %s", result)
	}
}

func TestAddDomains_SkipsEmptyAndDuplicate(t *testing.T) {
	g := NewGate([]string{"existing.com"}, nil, "target-001.local")
	originalLen := len(g.targetDomains)

	g.AddDomains([]string{"", "existing.com", "", "existing.com"})

	if len(g.targetDomains) != originalLen {
		t.Errorf("empty and duplicate domains should not be added: had %d, now %d",
			originalLen, len(g.targetDomains))
	}
}

func TestAddDomains_CaughtByScrubNoDomains(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	g.AddDomains([]string{"target.example.org"})

	result := g.ScrubNoDomains("path/target.example.org/file", "test")
	if strings.Contains(result, "target.example.org") {
		t.Errorf("target domain patterns should be caught by ScrubNoDomains, got: %s", result)
	}
}

func TestAddDomains_DoesNotAffectCatchAllDomainRegex(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	g.AddDomains([]string{"target.example.org"})

	result := g.ScrubNoDomains("/css/custom.min.css", "test")
	if result != "/css/custom.min.css" {
		t.Errorf("ScrubNoDomains should not mangle filenames after AddDomains, got: %s", result)
	}
}

func TestAddDomains_CaseInsensitive(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	g.AddDomains([]string{"Example.Org"})

	result := g.Scrub("visit example.org today", "test")
	if strings.Contains(result, "example.org") {
		t.Errorf("added domain should match case-insensitively, got: %s", result)
	}
}

func TestAddDomains_ConcurrentSafety(t *testing.T) {
	g := NewGate([]string{"base.com"}, nil, "target-001.local")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			g.AddDomains([]string{strings.Repeat("a", n%26+1) + ".example.com"})
		}(i)
	}
	wg.Wait()

	result := g.Scrub("Visit base.com", "test")
	if strings.Contains(result, "base.com") {
		t.Error("original domain should still be scrubbed after concurrent AddDomains")
	}
}
