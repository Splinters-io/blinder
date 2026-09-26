package jsonedit

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestDiagnosticPreservesGrammarAndEditsDecodedStrings(t *testing.T) {
	for _, tc := range []struct{ source, want string }{
		{`{"error":"SQLSTATE[42000] AcmeCorp"`, `{"error":"SQLSTATE[42000] alias"`},
		{`{"error":"SQLSTATE[42000] \u0041cmeCorp`, `{"error":"SQLSTATE[42000] alias`},
		{`{"error":"AcmeCorp"} {"error":"\u0041cmeCorp"}`, `{"error":"alias"} {"error":"alias"}`},
		{`{"safe":1}]`, `{"safe":1}]`},
		{"  { \"error\" : \"AcmeCorp\" }\nSQLSTATE[42000]: AcmeCorp\n", "  { \"error\" : \"alias\" }\nSQLSTATE[42000]: alias\n"},
		{`{"error":"keep\u0020this\/spelling"`, `{"error":"keep\u0020this\/spelling"`},
	} {
		t.Run(tc.source, func(t *testing.T) {
			input := []byte(tc.source)
			got, err := RewriteDiagnostic(input, func(s string) string { return strings.ReplaceAll(s, "AcmeCorp", "alias") })
			if err != nil || string(got) != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
			if string(input) != tc.source {
				t.Fatal("mutated source")
			}
		})
	}
}

func TestDiagnosticRejectsAmbiguousEscapesBeforeCallbacks(t *testing.T) {
	for _, source := range []string{`{"name":"AcmeCorp","bad":"\u004`, `{"bad":"\q"}`, `error \u0041cmeCorp`, `{"bad":"tail\`, "{\"bad\":\"raw\nnewline\"}"} {
		called := false
		got, err := RewriteDiagnostic([]byte(source), func(s string) string { called = true; return s })
		if !errors.Is(err, ErrInvalidJSON) || got != nil || called {
			t.Fatalf("source=%q got=%q err=%v called=%v", source, got, err, called)
		}
	}
}

func FuzzDiagnosticIdentityPreservesSource(f *testing.F) {
	for _, seed := range []string{`{"error":"unterminated`, `{"safe":1}]`, `{"a":"\u0061"} trailing`, `"quote\"slash\\"`, `{"bad":"\u00`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		got, err := RewriteDiagnostic(input, func(s string) string { return s })
		if err == nil && !bytes.Equal(got, input) {
			t.Fatalf("identity rewrite changed %q to %q", input, got)
		}
		if err != nil && got != nil {
			t.Fatal("partial output returned")
		}
	})
}

func BenchmarkDiagnosticSmallFragments(b *testing.B) {
	input := bytes.Repeat([]byte(`""`), 512*1024)
	b.SetBytes(int64(len(input)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, err := RewriteDiagnostic(input, nil)
		if err != nil || !bytes.Equal(out, input) {
			b.Fatal("diagnostic bytes changed", err)
		}
	}
}
