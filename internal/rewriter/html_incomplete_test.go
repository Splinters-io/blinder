package rewriter

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestHTMLIncompleteCommentsPreserveEnvelopeAndNeighbors(t *testing.T) {
	for _, tc := range []struct{ name, source, before, after string }{
		{"bogus-question", `<?E_INPUT &#00039; AcmeCorp SQLSTATE[42000]?>`, `<?E_INPUT &#00039; `, ` SQLSTATE[42000]?>`},
		{"bogus-bang", `<!E_INPUT AcmeCorp SQLSTATE[42000]>`, `<!E_INPUT `, ` SQLSTATE[42000]>`},
		{"bang-close", `<!-- E_INPUT AcmeCorp --!>`, `<!-- E_INPUT `, ` --!>`},
		{"unfinished", `<!-- E_INPUT AcmeCorp`, `<!-- E_INPUT `, ""},
		{"unfinished-dashes", `<!-- E_INPUT AcmeCorp --`, `<!-- E_INPUT `, " --"},
		{"nested-opening", `<!-- <!-- E_INPUT AcmeCorp -->`, `<!-- <!-- E_INPUT `, " -->"},
		{"encoded", `<!-- &#00039; &#65;cmeCorp &#x27; &lt;script&gt; -->`, `<!-- &#00039; `, ` &#x27; &lt;script&gt; -->`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
			got := rewriteHTMLComment([]byte(tc.source), gate)
			if !strings.HasPrefix(string(got), tc.before) || !strings.HasSuffix(string(got), tc.after) || !strings.Contains(string(got), scrub.ValueAliasPrefix) {
				t.Fatalf("diagnostic source/envelope changed: %q", got)
			}
			if gate.ResidualLeakCount(html.UnescapeString(string(got))) != 0 {
				t.Fatalf("identity exposed: %q", got)
			}
			if !isSingleHTMLToken(got, html.CommentToken) || gate.ReplacementCount() != 1 {
				t.Fatalf("parser boundary or scrub count changed: %q count=%d", got, gate.ReplacementCount())
			}
			if !strings.Contains(tc.source, "&#65;") && len(got) != len(tc.source) {
				t.Fatalf("plain identity comment expanded: %d -> %d", len(tc.source), len(got))
			}
		})
	}
}

func TestHTMLIncompleteEOFDoesNotRepairOrExecuteSource(t *testing.T) {
	for _, source := range []string{
		`<div data-note='AcmeCorp`,
		`<div data-note=AcmeCorp`,
		`<img src=x onerror='AcmeCorp`,
		`<script data-note="AcmeCorp`,
		`</p ignored='AcmeCorp`,
		`<div data-note='&#65;cmeCorp`,
	} {
		t.Run(source, func(t *testing.T) {
			const before = `<p>SQLSTATE[42000] before</p>`
			gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
			got := RewriteBody([]byte(before+source), "text/html", "/", gate, false).Body
			if !bytes.HasPrefix(got, []byte(before)) || len(got) <= len(before) || gate.ResidualLeakCount(html.UnescapeString(string(got))) != 0 {
				t.Fatalf("EOF evidence lost or leaked: %q", got)
			}
			if suffix := got[len(before):]; !isSingleHTMLToken(suffix, html.ErrorToken) {
				t.Fatalf("truncated source was repaired into a token: %q", suffix)
			}
			// An HTML parser discards the incomplete tag. Retaining it must not
			// introduce a script/img node compared with that same direct input.
			if incompleteElementCount(t, before+source) != incompleteElementCount(t, string(got)) {
				t.Fatalf("rewriting changed emitted element count: %q", got)
			}
		})
	}
}

func incompleteElementCount(t *testing.T, source string) int {
	t.Helper()
	z := html.NewTokenizer(strings.NewReader(source))
	count := 0
	for {
		switch z.Next() {
		case html.ErrorToken:
			if z.Err() != io.EOF {
				t.Fatal(z.Err())
			}
			return count
		case html.StartTagToken, html.SelfClosingTagToken:
			count++
		}
	}
}

func TestHTMLSourceSpanCharacterReferenceBoundaries(t *testing.T) {
	for _, tc := range []struct{ source, identity string }{
		{`&#x27; AcmeCorp &#00039;`, "AcmeCorp"},
		{`&#65;cmeCorp`, "AcmeCorp"},
		{`Acme&#x43;orp`, "AcmeCorp"},
		{`&notAcmeCorp;`, "AcmeCorp"},
		{`&NotEqualTilde;`, "≂"},
		{`&NotEqualTilde;`, "̸"},
		{`&amp;AcmeCorp`, "AcmeCorp"},
		{`AcmeCorp&amp;`, "AcmeCorp"},
		{`&unknown;AcmeCorp&unknown;`, "AcmeCorp"},
		{`AcmeCorp`, "AcmeCorp"},
	} {
		t.Run(tc.source+tc.identity, func(t *testing.T) {
			gate := scrub.NewGate(nil, []string{tc.identity}, "alias.local")
			got := scrubHTMLSourceSpan([]byte(tc.source), gate, "fixture")
			if restored := gate.RestoreBody(html.UnescapeString(string(got))); restored != html.UnescapeString(tc.source) {
				t.Fatalf("reference expansion lost content: %q -> %q -> %q", tc.source, got, restored)
			}
			if strings.Contains(string(got), tc.identity) || gate.ReplacementCount() != 1 {
				t.Fatalf("identity leaked or scrub repeated: %q count=%d", got, gate.ReplacementCount())
			}
		})
	}
}

func TestHTMLIncompleteDelimiterIdentityStaysConservative(t *testing.T) {
	for _, tc := range []struct{ source, identity string }{
		{`<?AcmeCorp?>`, "<?AcmeCorp"},
		{`<!-- AcmeCorp --!>`, "AcmeCorp --!>"},
		{`<AcmeCorp data-note='unfinished`, "<AcmeCorp"},
	} {
		t.Run(tc.source, func(t *testing.T) {
			gate := scrub.NewGate(nil, []string{tc.identity}, "alias.local")
			got := RewriteBody([]byte(tc.source), "text/html", "/", gate, false).Body
			if len(got) != 0 {
				t.Fatalf("unsafe boundary rewrite unexpectedly survived: %q", got)
			}
		})
	}
}
