package rewriter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestMalformedJSONDiagnosticRedactsIdentityAcrossQuoteFragments(t *testing.T) {
	for _, tc := range []struct{ identity, source string }{
		{`Acme"Corp`, `E_INPUT Acme"Corp`},
		{`The "Acme" Group`, `E_INPUT The "Acme" Group`},
	} {
		t.Run(tc.identity, func(t *testing.T) {
			gate := scrub.NewGate(nil, []string{tc.identity}, "alias.local")
			if gate.Scrub(tc.source, "fixture") == tc.source {
				t.Fatal("fixture identity does not match the configured gate")
			}
			got := RewriteBody([]byte(tc.source), "application/json", "/", gate, false).Body
			if strings.Contains(string(got), tc.identity) {
				t.Fatalf("fragment boundaries bypassed configured identity matching: %q", got)
			}
		})
	}
}

func TestMalformedJSONDiagnosticTruncatedQuoteAndBackslashParity(t *testing.T) {
	for _, tc := range []struct{ name, source, decoded string }{
		{"escaped_quote", `{"error":"AcmeCorp\"`, `AcmeCorp"`},
		{"escaped_backslash", `{"error":"AcmeCorp\\`, `AcmeCorp\`},
		{"backslash_then_quote", `{"error":"AcmeCorp\\\"`, `AcmeCorp\"`},
		{"unicode_quote", `{"error":"\u0041cmeCorp\u0022`, `AcmeCorp"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
			encoded, err := json.Marshal(gate.Scrub(tc.decoded, "fixture"))
			if err != nil {
				t.Fatal(err)
			}
			want := `{"error":` + string(encoded[:len(encoded)-1])
			got := RewriteBody([]byte(tc.source), "application/json", "/", gate, false).Body
			if string(got) != want {
				t.Fatalf("truncated escape parity changed: got %q want %q", got, want)
			}
		})
	}
}
