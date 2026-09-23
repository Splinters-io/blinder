package scrub

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestGateUnicodeReplacement(t *testing.T) {
	for _, tc := range []struct{ input, token, want string }{
		{"İ AcmeCorp", "AcmeCorp", "İ [REDACTED]"},
		{"korp", "Korp", "[REDACTED]"},
		{"Korp", "korp", "[REDACTED]"},
		{"[a+b] [a+b]", "[a+b]", "[REDACTED] [REDACTED]"},
	} {
		t.Run(tc.token+tc.input, func(t *testing.T) {
			got := NewGate(nil, []string{tc.token}, "alias.local").Scrub(tc.input, "test")
			if got != tc.want || !utf8.ValidString(got) {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
		})
	}
}

func TestGateOverlappingTargetTerminates(t *testing.T) {
	if os.Getenv("BLINDER_GATE_CHILD") == "1" {
		gate := NewGate([]string{"alias.local", ""}, []string{""}, "alias.local")
		if got := gate.Scrub("https://alias.local", "test"); !strings.Contains(got, "host-") {
			t.Fatal(got)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGateOverlappingTargetTerminates$")
	cmd.Env = append(os.Environ(), "BLINDER_GATE_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scrubber did not terminate safely: %v %s", err, out)
	}
}

func FuzzGateUnicode(f *testing.F) {
	for _, seed := range []string{"İ AcmeCorp", "Korp", "acmecorp.io", "red [REDACTED]", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 8192 || !utf8.ValidString(input) {
			t.Skip()
		}
		got := NewGate([]string{"acmecorp.io"}, []string{"AcmeCorp", "korp", "red"}, "alias.local").Scrub(input, "fuzz")
		if !utf8.ValidString(got) {
			t.Fatalf("invalid UTF-8 from valid input: %q", got)
		}
	})
}
