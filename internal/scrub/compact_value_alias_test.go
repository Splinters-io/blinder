package scrub

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestCompactValueAliasesPreserveSourceByteBudget(t *testing.T) {
	long := strings.Repeat("LongIdentity", 257)
	g := NewGate(nil, []string{"AcmeCorp", "kelvin", long}, "alias.local")
	seen := make(map[string]string)
	for _, original := range []string{"AcmeCorp", "ACMECORP", "kelvin", "Kelvin", "Kelvin", long} {
		alias := g.Scrub(original, "value")
		if len(alias) != len(original) || !utf8.ValidString(alias) || alias == original {
			t.Fatalf("source budget or masking lost: %d bytes %q -> %d bytes %q", len(original), original, len(alias), alias)
		}
		if previous, found := seen[alias]; found {
			t.Fatalf("%q and %q share alias %q", previous, original, alias)
		}
		seen[alias] = original
		if restored := g.RestoreBody(alias); restored != original {
			t.Fatalf("exact source spelling lost: %q -> %q", original, restored)
		}
	}
}

func TestCompactValueAliasesFillAvailableSlotBeforeGrowing(t *testing.T) {
	g := NewGate(nil, []string{"AcmeX", "AcmeY"}, "alias.local")
	for i := 0; i < 16; i++ {
		if i != 11 {
			g.tokenAliases[fmt.Sprintf("[v:%x]", i)] = fmt.Sprintf("occupied-%d", i)
		}
	}
	if alias := g.Scrub("AcmeX", "value"); alias != "[v:b]" {
		t.Fatalf("available fixed-width alias was skipped: %q", alias)
	}
	alias := g.Scrub("AcmeY", "value")
	if len(alias) != 6 || g.RestoreBody(alias) != "AcmeY" {
		t.Fatalf("saturated namespace did not grow safely: %q", alias)
	}
	for i := 0; i < 16; i++ {
		want := fmt.Sprintf("occupied-%d", i)
		if i == 11 {
			want = "AcmeX"
		}
		if got := g.RestoreBody(fmt.Sprintf("[v:%x]", i)); got != want {
			t.Fatalf("existing inverse overwritten: %x -> %q, want %q", i, got, want)
		}
	}
}

func TestCompactValueAliasesTooShortRemainReversible(t *testing.T) {
	g := NewGate(nil, []string{"K"}, "alias.local")
	for _, original := range []string{"K", "k", "K"} {
		alias := g.Scrub(original, "value")
		if alias == original || len(alias) <= len(original) || g.RestoreBody(alias) != original {
			t.Fatalf("short source gained ambiguous alias: %q -> %q", original, alias)
		}
	}
}

func TestCompactValueAliasesKeepLiteralNamespaceAndJSONDistinct(t *testing.T) {
	g := NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	alias := g.Scrub("AcmeCorp", "register")
	for _, original := range []string{
		alias + " AcmeCorp " + alias,
		g.escapePrefix + "R " + alias + " AcmeCorp",
		"[v:a][v:ab][v:abcd] AcmeCorp",
	} {
		masked := g.Scrub(original, "literal")
		if restored := g.RestoreBody(masked); restored != original {
			t.Fatalf("literal namespace gained alias meaning: %q -> %q -> %q", original, masked, restored)
		}
		encoded, err := json.Marshal(map[string]string{"literal": masked, "value": alias})
		if err != nil {
			t.Fatal(err)
		}
		var restored map[string]string
		if err := json.Unmarshal(g.RestoreJSON(encoded), &restored); err != nil || restored["literal"] != original || restored["value"] != "AcmeCorp" {
			t.Fatalf("JSON restoration confused aliases with literals: %v %v", restored, err)
		}
	}
}

func TestCompactValueAliasesStableAcrossConcurrentRequestViews(t *testing.T) {
	g := NewGate(nil, []string{"AcmeCorp", "OtherOrg"}, "alias.local")
	want := g.Scrub("AcmeCorp OtherOrg", "initial")
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := g.ForRequest()
			got := r.Scrub("AcmeCorp OtherOrg", "concurrent")
			if got != want || r.RestoreBody(got) != "AcmeCorp OtherOrg" {
				t.Errorf("request-local mapping drifted: %q", got)
			}
		}()
	}
	wg.Wait()
}

func TestCompactValueAliasesUsePrivateSessionKey(t *testing.T) {
	const original = "PrivateIdentityValue"
	first := NewGate(nil, []string{original}, "alias.local")
	second := NewGate(nil, []string{original}, "alias.local")
	// Fix distinct private keys so this assertion does not rely on rand.Read.
	first.contentKey = [32]byte{1}
	second.contentKey = [32]byte{2}
	a, b := first.Scrub(original, "first"), second.Scrub(original, "second")
	if a == b || len(a) != len(original) || len(b) != len(original) {
		t.Fatalf("aliases did not use private session keys within the source budget: %q / %q", a, b)
	}
}
