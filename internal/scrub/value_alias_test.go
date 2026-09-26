package scrub

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestValueAliasesUseNeutralReversibleValues(t *testing.T) {
	g := NewGate(nil, []string{"AcmeCorp", "OtherOrg"}, "alias.local")
	seen := make(map[string]string)
	for _, original := range []string{"AcmeCorp", "ACMECORP", "OtherOrg"} {
		alias := g.Scrub(original, "value")
		if !strings.HasPrefix(alias, ValueAliasPrefix) || strings.Contains(strings.ToLower(alias), "redact") || strings.Contains(strings.ToLower(alias), "removed") {
			t.Fatalf("identity replacement describes a removal: %q", alias)
		}
		if previous, exists := seen[alias]; exists {
			t.Fatalf("%q and %q share alias %q", previous, original, alias)
		}
		seen[alias] = original
		if got := g.RestoreBody(alias); got != original {
			t.Fatalf("restored %q as %q", original, got)
		}
		if next := g.Scrub(original, "next-value"); next != alias {
			t.Fatalf("alias changed: %q -> %q", alias, next)
		}
	}
}

func TestValueAliasLiteralGrammarRoundTrips(t *testing.T) {
	for _, tokens := range [][]string{nil, {"AcmeCorp"}, {"AcmeCorp", "SecretProject"}} {
		g := NewGate(nil, tokens, "alias.local")
		marker := ValueAliasPrefix + "fixture]"
		for depth := 0; depth < 16; depth++ {
			original := marker + " " + marker + " AcmeCorp"
			transformed := g.Scrub(original, "value")
			if got := g.RestoreBody(transformed); got != original {
				t.Fatalf("tokens=%v depth=%d: input=%q transformed=%q restored=%q", tokens, depth, original, transformed, got)
			}
			marker = g.Scrub(marker, "next-marker")
		}
	}
}

func TestValueAliasesPreserveLegacyLiteralAppData(t *testing.T) {
	g := NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	g.Scrub("AcmeCorp", "register")
	for _, original := range []string{"[REDACTED]", "[REDACTED:fixture]", "[REDACTED:1153b4]", "[LITERAL:fixture]"} {
		if got := g.Scrub(original, "literal"); got != original {
			t.Fatalf("legacy literal changed: %q -> %q", original, got)
		}
		if got := g.RestoreBody(original); got != original {
			t.Fatalf("legacy literal restored as an alias: %q -> %q", original, got)
		}
	}
}

func TestValueAliasCollisionDoesNotOverwriteInverseMapping(t *testing.T) {
	g := NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	h := sha256.Sum256([]byte("AcmeCorp"))
	for size := 3; size <= len(h); size++ {
		g.tokenAliases[ValueAliasPrefix+hex.EncodeToString(h[:size])+"]"] = fmt.Sprintf("existing-%d", size)
	}
	fullCollision := fmt.Sprintf("%s%x-1]", ValueAliasPrefix, h)
	g.tokenAliases[fullCollision] = "existing-full-collision"
	before := make(map[string]string, len(g.tokenAliases))
	for alias, original := range g.tokenAliases {
		before[alias] = original
	}
	alias := g.Scrub("AcmeCorp", "value")
	if got := g.RestoreBody(alias); got != "AcmeCorp" {
		t.Fatalf("new alias did not restore: %q -> %q", alias, got)
	}
	for alias, original := range before {
		if got := g.RestoreBody(alias); got != original {
			t.Fatalf("existing alias overwritten: %q -> %q, want %q", alias, got, original)
		}
	}
}

func TestValueAliasesDoNotRescrubGeneratedValues(t *testing.T) {
	for _, tokens := range [][]string{
		{"AcmeCorp", "v"},
		{"AcmeCorp", "a", "1"},
		{"AcmeCorp", "R", "E"},
	} {
		g := NewGate(nil, tokens, "alias.local")
		for _, original := range []string{
			"AcmeCorp " + tokens[1],
			ValueAliasPrefix + "fixture] AcmeCorp " + tokens[1],
			g.escapePrefix + "R AcmeCorp " + tokens[1],
		} {
			transformed := g.Scrub(original, "value")
			if got := g.RestoreBody(transformed); got != original {
				t.Fatalf("tokens=%v: input=%q transformed=%q restored=%q", tokens, original, transformed, got)
			}
		}
	}
}
