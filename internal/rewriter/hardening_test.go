package rewriter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestJSONMalformedDiagnosticsPreserved(t *testing.T) {
	for _, tc := range []struct{ source, prefix, suffix string }{
		{`{"company":"\u0041cmeCorp"`, `{"company":"`, `"`},
		{`{"safe":1}]`, `{"safe":1}]`, ``},
		{`{"safe":1} {"company":"\u0041cmeCorp"}`, `{"safe":1} {"company":"`, `"}`},
	} {
		t.Run(tc.source, func(t *testing.T) {
			gate := scrub.NewGate(nil, []string{"AcmeCorp", "OtherOrg"}, "alias.local")
			want := tc.prefix + gate.Scrub("AcmeCorp", "fixture") + tc.suffix
			if tc.suffix == "" {
				want = tc.source
			}
			got := RewriteBody([]byte(tc.source), "application/json", "/", gate, false).Body
			if string(got) != want || json.Valid(got) {
				t.Fatalf("malformed grammar/diagnostics changed: got %q want %q", got, want)
			}
		})
	}
}

func TestJSONAmbiguousEscapesStillFailClosed(t *testing.T) {
	for _, source := range []string{`{"company":"\u0041cmeCorp","bad":"\q"}`, `{"company":"\u0041cmeCorp\`, `\u0041cmeCorp`} {
		got := RewriteBody([]byte(source), "application/json", "/", scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local"), false).Body
		if string(got) != "null" {
			t.Fatalf("ambiguous escapes must fail closed, got %q", got)
		}
	}
}

func TestJSONDistinctAliasedKeysPreserveBothValues(t *testing.T) {
	gate := scrub.NewGate(nil, []string{"AcmeCorp", "OtherOrg"}, "alias.local")
	got := RewriteBody([]byte(`{"AcmeCorp":1,"OtherOrg":2}`), "application/json", "/", gate, false).Body
	if string(got) == "null" {
		t.Fatal("distinct aliased keys should produce valid JSON, not null")
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("output must be valid JSON: %v (got %s)", err, got)
	}
	if len(parsed) != 2 {
		t.Fatalf("both keys must be preserved: got %d keys in %s", len(parsed), got)
	}
	for _, v := range parsed {
		val, ok := v.(float64)
		if !ok || (val != 1 && val != 2) {
			t.Fatalf("values must be preserved: got %v in %s", v, got)
		}
	}
}

func FuzzJSONScrubbing(f *testing.F) {
	f.Add(`{"company":"\u0041cmeCorp","id":9007199254740993}`)
	f.Add(`{"AcmeCorp":1,"OtherOrg":2}`)
	f.Add(`{"company":"AcmeCorp"`)
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > 8192 {
			t.Skip()
		}
		got := RewriteBody([]byte(source), "application/json", "/", scrub.NewGate(nil, []string{"AcmeCorp", "OtherOrg"}, "alias.local"), false).Body
		if json.Valid([]byte(source)) && !json.Valid(got) {
			t.Fatalf("output must be valid JSON: %q", got)
		}
		if bytes.Contains(got, []byte("AcmeCorp")) {
			t.Fatalf("identity leaked: %q", got)
		}
	})
}
