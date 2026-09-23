package rewriter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestJSONFailsClosed(t *testing.T) {
	for _, source := range []string{
		`{"company":"\u0041cmeCorp"`,
		`{"safe":1}]`,
		`{"safe":1} {"company":"\u0041cmeCorp"}`,
		`{"AcmeCorp":1,"OtherOrg":2}`,
	} {
		t.Run(source, func(t *testing.T) {
			gate := scrub.NewGate(nil, []string{"AcmeCorp", "OtherOrg"}, "alias.local")
			got := RewriteBody([]byte(source), "application/json", "/", gate, false).Body
			if string(got) != "null" {
				t.Fatalf("ambiguous/invalid JSON must fail closed, got %s", got)
			}
		})
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
		if !json.Valid(got) {
			t.Fatalf("output must be valid JSON: %q", got)
		}
		if bytes.Contains(got, []byte("AcmeCorp")) {
			t.Fatalf("identity leaked: %q", got)
		}
	})
}
