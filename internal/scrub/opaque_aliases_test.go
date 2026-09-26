package scrub

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestOpaqueValueAliasRestoresWithoutRescanning(t *testing.T) {
	const generated, literal = "bn1-a-c29tZQ", "bn1-l-Ym4xLWE"
	for _, literalFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(literalFirst), func(t *testing.T) {
			g := NewGate(nil, []string{"AcmeCorp"}, "alias.local")
			if literalFirst {
				g.RegisterOpaqueValueAlias(literal, generated)
				g.RegisterOpaqueValueAlias(generated, "AcmeCorp")
			} else {
				g.RegisterOpaqueValueAlias(generated, "AcmeCorp")
				g.RegisterOpaqueValueAlias(literal, generated)
			}
			if got := g.RestoreBody(literal + " " + generated); got != generated+" AcmeCorp" {
				t.Fatalf("restored literal was rescanned: %q", got)
			}
			generic := g.Scrub("AcmeCorp", "test")
			if got := g.RestoreBody(generic + " " + literal); got != "AcmeCorp "+generated {
				t.Fatalf("generic and opaque inverse stages disagree: %q", got)
			}
			const markerAlias = "bn1-a-bWFya2Vy"
			original := g.escapePrefix + "R[v:literal]"
			g.RegisterOpaqueValueAlias(markerAlias, original)
			if got := g.RestoreBody(markerAlias); got != original {
				t.Fatalf("restored original escape was decoded: %q", got)
			}
		})
	}
}

func TestOpaqueValueLiteralNamespaceRoundTripsBeforeAndAfterRegistration(t *testing.T) {
	const alias = "bn1-a-c29tZQ"
	for _, tokens := range [][]string{nil, {"AcmeCorp"}, {"AcmeCorp", "O", "a"}} {
		g := NewGate(nil, tokens, "alias.local")
		original := alias + " AcmeCorp " + "prefix" + alias + "suffix"
		before := g.Scrub(original, "before-register")
		if !g.ContainsEscape(before) {
			t.Fatal("reserved literal namespace was not escaped before registration")
		}
		g.RegisterOpaqueValueAlias(alias, "different-original")
		after := g.Scrub(original, "after-register")
		for _, encoded := range []string{before, after} {
			if got := g.RestoreBody(encoded); got != original {
				t.Fatalf("tokens=%v: literal gained alias meaning: %q => %q", tokens, encoded, got)
			}
		}
		for depth := 0; depth < 8; depth++ {
			literal := g.escapePrefix + "O" + strings.Repeat("E", depth) + alias
			if got := g.RestoreBody(g.Scrub(literal, "self-escape")); got != literal {
				t.Fatalf("escape marker did not round-trip: %q => %q", literal, got)
			}
		}
	}
}

func TestOpaqueValueAliasesMatchOnlyMaximalTokens(t *testing.T) {
	g := NewGate(nil, nil, "alias.local")
	const alias, longer = "bn1-a-c29tZQ", "bn1-a-c29tZQ-extra"
	g.RegisterOpaqueValueAlias(alias, "first")
	g.RegisterOpaqueValueAlias(longer, "second")
	for _, input := range []string{alias, `"` + alias + `"`, "(" + alias + ")", alias + ";", alias + ":" + longer} {
		if !g.ContainsAlias(input) || g.RestoreBody(input) == input {
			t.Fatalf("whole opaque token not recognised: %q", input)
		}
	}
	if got := g.RestoreBody(longer); got != "second" {
		t.Fatalf("shorter alias stole longer token: %q", got)
	}
	for _, input := range []string{"x" + alias, alias + "x", "/" + alias, alias + "/", alias + "=", alias + "===", alias + "+suffix"} {
		if g.ContainsAlias(input) || g.RestoreBody(input) != input {
			t.Fatalf("partial opaque token was interpreted as an alias: %q", input)
		}
	}
}

func TestOpaqueValueAliasesRejectConflictingAndInvalidRegistrations(t *testing.T) {
	g := NewGate(nil, nil, "alias.local")
	const alias = "bn1-a-c29tZQ"
	if !g.RegisterOpaqueValueAlias(alias, "first") || !g.RegisterOpaqueValueAlias(alias, "first") || g.RegisterOpaqueValueAlias(alias, "second") {
		t.Fatal("registration did not preserve existing inverse mapping")
	}
	if got := g.RestoreBody(alias); got != "first" {
		t.Fatalf("conflict changed existing mapping: %q", got)
	}
	for _, bad := range []string{"", "unreserved", "bn1-a bad", "bn1-a[bad]", "bn1-a-bad===", "bn1-a-bad=tail"} {
		if g.RegisterOpaqueValueAlias(bad, "value") {
			t.Fatalf("invalid alias accepted: %q", bad)
		}
	}
}

func TestOpaqueValueAliasRequestSharingAndConcurrentUse(t *testing.T) {
	g := NewGate(nil, nil, "alias.local")
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			r := g.ForRequest()
			alias, original := fmt.Sprintf("bn1-a-token%d", i), fmt.Sprintf("value%d", i)
			if !r.RegisterOpaqueValueAlias(alias, original) || !g.ContainsAlias(alias) || g.RestoreBody(alias) != original || r.RestoreBody(alias) != original {
				t.Errorf("request/shared gate mapping failed for %q", alias)
			}
		}(i)
	}
	workers.Wait()
}
