package scrub

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestShortTextAliasesPreserveDistinctUnicodeSources(t *testing.T) {
	gate := NewGate(nil, nil, "alias.local")
	seen := make(map[string]string)
	for ch := rune(0x100); ch < 0x800; ch++ {
		source := string(ch)
		tag := gate.ContentTag([]byte(source))
		text, unique := gate.ShortTextAlias(tag, len(source))
		if !unique || len(text) != len(source) || strings.ContainsAny(text, "<&>\"' \t\r\n") {
			t.Fatalf("invalid same-size reserved text for %q: %q, unique=%v", source, text, unique)
		}
		if prior, exists := seen[text]; exists {
			t.Fatalf("different sources %q / %q collapsed to %q", prior, source, text)
		}
		seen[text] = source
		if repeated, ok := gate.ForRequest().ShortTextAlias(tag, len(source)); !ok || repeated != text {
			t.Fatalf("request view remapped %q: %q / %q", source, text, repeated)
		}
	}
	if gate.ShortTextFallbackCount() != 0 {
		t.Fatal("non-exhausted alphabet reported fallbacks")
	}
}

func TestShortTextAlphabetExhaustionIsStableAndCounted(t *testing.T) {
	gate := NewGate(nil, nil, "alias.local")
	firstRequest := gate.ForRequest()
	seen := make(map[string]string)
	for i := range len(shortTextAlphabet) {
		tag := gate.ContentTag([]byte(fmt.Sprintf("source-%d", i)))
		text, unique := firstRequest.ShortTextAlias(tag, 1)
		if !unique || len(text) != 1 {
			t.Fatalf("failed before alphabet exhaustion at %d: %q, unique=%v", i, text, unique)
		}
		if _, exists := seen[text]; exists {
			t.Fatalf("reserved duplicate output %q", text)
		}
		seen[text] = tag
	}
	secondRequest := gate.ForRequest()
	tag := gate.ContentTag([]byte("source-after-capacity"))
	fallback, unique := secondRequest.ShortTextAlias(tag, 1)
	if unique || len(fallback) != 1 {
		t.Fatalf("alphabet exhaustion silently claimed uniqueness: %q, %v", fallback, unique)
	}
	for text, oldTag := range seen {
		if got, ok := secondRequest.ShortTextAlias(oldTag, 1); !ok || got != text {
			t.Fatalf("exhaustion changed reserved output: %q / %q", text, got)
		}
	}
	if repeated, ok := secondRequest.ShortTextAlias(tag, 1); ok || repeated != fallback {
		t.Fatalf("fallback remapped: %q / %q", fallback, repeated)
	}
	if firstRequest.ShortTextFallbackCount() != 0 || secondRequest.ShortTextFallbackCount() != 2 || gate.ShortTextFallbackCount() != 2 {
		t.Fatalf("request/session fallback counts wrong: %d / %d / %d", firstRequest.ShortTextFallbackCount(), secondRequest.ShortTextFallbackCount(), gate.ShortTextFallbackCount())
	}
	if len(gate.shortText.byTag) != len(shortTextAlphabet) || len(gate.shortText.used) != len(shortTextAlphabet) {
		t.Fatal("exhaustion grew or evicted reservations")
	}
}

func TestShortTextReservationBudgetDoesNotEvict(t *testing.T) {
	gate := NewGate(nil, nil, "alias.local")
	var firstTag, firstText string
	for i := range shortTextMaxReservations {
		tag := gate.ContentTag([]byte(fmt.Sprintf("budget-source-%d", i)))
		text, unique := gate.ShortTextAlias(tag, 8)
		if !unique || len(text) != 8 {
			t.Fatalf("reservation %d failed before memory cap", i)
		}
		if i == 0 {
			firstTag, firstText = tag, text
		}
	}
	tag := gate.ContentTag([]byte("budget-overflow"))
	fallback, unique := gate.ShortTextAlias(tag, 8)
	if unique || len(fallback) != 8 {
		t.Fatal("overflow was reserved or changed the byte budget")
	}
	if text, ok := gate.ShortTextAlias(firstTag, 8); !ok || text != firstText {
		t.Fatal("cap evicted the first source")
	}
	if text, ok := gate.ShortTextAlias(tag, 8); ok || text != fallback {
		t.Fatal("overflow fallback is not stable")
	}
	if len(gate.shortText.byTag) != shortTextMaxReservations || len(gate.shortText.used) != shortTextMaxReservations || gate.ShortTextFallbackCount() != 2 {
		t.Fatal("reservation cap/count not enforced")
	}
}

func TestShortTextAliasesFilterConfiguredIdentities(t *testing.T) {
	gate := NewGate(nil, []string{"a", "_", "-"}, "alias.local")
	for i := range 40 {
		tag := gate.ContentTag([]byte(fmt.Sprintf("filtered-%d", i)))
		text, unique := gate.ShortTextAlias(tag, 1)
		if !unique || gate.ResidualLeakCount(text) != 0 {
			t.Fatalf("reserved a configured identity: %q, unique=%v", text, unique)
		}
	}
	var tokens []string
	for _, ch := range shortTextAlphabet {
		tokens = append(tokens, string(ch))
	}
	blocked := NewGate(nil, tokens, "alias.local")
	tag := blocked.ContentTag([]byte("all-candidates-blocked"))
	text, unique := blocked.ShortTextAlias(tag, 8)
	if unique || text != strings.Repeat(" ", 8) || blocked.ShortTextFallbackCount() != 1 || len(blocked.shortText.byTag) != 0 {
		t.Fatalf("rejected candidates leaked or expanded: %q, %v", text, unique)
	}
}

func TestShortTextAliasesShareConcurrentSessionReservations(t *testing.T) {
	gate := NewGate(nil, nil, "alias.local")
	const sources = 200
	tags := make([]string, sources)
	for i := range tags {
		tags[i] = gate.ContentTag([]byte(fmt.Sprintf("concurrent-%d", i)))
	}
	type result struct {
		source int
		text   string
	}
	results := make(chan result, sources*4)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request := gate.ForRequest()
			for i, tag := range tags {
				text, unique := request.ShortTextAlias(tag, 2)
				if !unique {
					t.Errorf("concurrent source %d could not be reserved", i)
				}
				results <- result{i, text}
			}
		}()
	}
	wg.Wait()
	close(results)
	bySource := make(map[int]string)
	byText := make(map[string]int)
	for got := range results {
		if prior, ok := bySource[got.source]; ok && prior != got.text {
			t.Fatalf("source %d changed across request views", got.source)
		}
		if prior, ok := byText[got.text]; ok && prior != got.source {
			t.Fatalf("sources %d / %d share output", prior, got.source)
		}
		bySource[got.source], byText[got.text] = got.text, got.source
	}
	if len(gate.shortText.byTag) != sources || gate.ShortTextFallbackCount() != 0 {
		t.Fatal("concurrent allocation lost or duplicated reservations")
	}
}

func TestShortTextAliasesAreSessionPrivateAndBudgetScoped(t *testing.T) {
	first := NewGate(nil, nil, "alias.local")
	second := NewGate(nil, nil, "alias.local")
	source := []byte("same source in two sessions")
	tag := first.ContentTag(source)
	a, aOK := first.ShortTextAlias(tag, 8)
	b, bOK := second.ShortTextAlias(second.ContentTag(source), 8)
	if !aOK || !bOK || a == b {
		t.Fatal("independent sessions shared an eight-byte alias")
	}
	for n := 1; n <= 8; n++ {
		text, ok := first.ShortTextAlias(tag, n)
		if !ok || len(text) != n {
			t.Fatalf("budget %d inherited another output size: %q", n, text)
		}
		if first.RestoreBody(text) != text {
			t.Fatal("display output was registered for request restoration")
		}
	}
	for _, n := range []int{-1, 0, 9} {
		if text, ok := first.ShortTextAlias(tag, n); ok || text != "" {
			t.Fatalf("invalid budget %d accepted", n)
		}
	}
}
