package rewriter

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Splinters-io/blinder/internal/scrub"
	"golang.org/x/net/html"
)

func TestProseFillerDoesNotReintroduceConfiguredIdentities(t *testing.T) {
	const size = 256
	const tag = "configured-filler-identity"
	before := proseForLength(size, tag)
	words := strings.Fields(before)
	for _, tc := range []struct {
		name    string
		domains []string
		tokens  []string
	}{
		{name: "corpus word", tokens: []string{words[0]}},
		{name: "case folded word", tokens: []string{strings.ToUpper(words[0])}},
		{name: "multiword identity", tokens: []string{words[0] + " " + words[1]}},
		{name: "domain match", domains: []string{words[0]}},
		{name: "entire corpus excluded", tokens: append([]string(nil), proseWords...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := scrub.NewGate(tc.domains, tc.tokens, "alias.local")
			if gate.ResidualLeakCount(before) == 0 {
				t.Fatal("fixture does not reproduce a filler collision")
			}
			got := proseForBudget(size, tag, gate)
			if len(got) != size || !utf8.ValidString(got) || strings.TrimSpace(got) == "" {
				t.Fatalf("filler lost its visible byte budget: %q", got)
			}
			if got == before || gate.ResidualLeakCount(got) != 0 {
				t.Fatalf("generated filler reintroduced a configured identity: %q", got)
			}
			if again := proseForBudget(size, tag, gate.ForRequest()); again != got {
				t.Fatalf("request-local gate remapped filler: %q -> %q", got, again)
			}
		})
	}
}

func TestProseFillerChecksWordBoundariesAndBoundsFallback(t *testing.T) {
	// Every pair is excluded while every individual word remains available.
	// Filtering the vocabulary alone cannot satisfy this configuration.
	var tokens []string
	for _, first := range proseWords {
		for _, second := range proseWords {
			tokens = append(tokens, first+" "+second)
		}
	}
	gate := scrub.NewGate(nil, tokens, "alias.local")
	const size = 128
	got := proseForBudget(size, "all-word-pairs", gate)
	if len(got) != size || gate.ResidualLeakCount(got) != 0 || strings.TrimSpace(got) == "" {
		t.Fatalf("word-boundary collision was emitted: %q", got)
	}
	if again := proseForBudget(size, "all-word-pairs", gate); again != got {
		t.Fatal("bounded fallback changed on repetition")
	}

	// Exhausting the finite visible fallbacks keeps the source size as spaces,
	// without looping, inserting labels, or introducing an excluded character.
	tokens = append([]string(nil), proseWords...)
	for _, fill := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" {
		tokens = append(tokens, string(fill))
	}
	gate = scrub.NewGate(nil, tokens, "alias.local")
	got = proseForBudget(size, "exhausted-fillers", gate)
	if got != strings.Repeat(" ", size) || gate.ResidualLeakCount(got) != 0 {
		t.Fatalf("exhausted filler did not retain safe whitespace: %q", got)
	}
}

func TestProseFillerFallbackRetainsSourceDifferences(t *testing.T) {
	gate := scrub.NewGate(nil, append([]string(nil), proseWords...), "alias.local")
	seen := make(map[string]string)
	const size = 128
	for i := range 32 {
		tag := gate.ContentTag([]byte(fmt.Sprintf("different ordinary source %d", i)))
		got := proseForBudget(size, tag, gate)
		if len(got) != size || !utf8.ValidString(got) || strings.TrimSpace(got) == "" || gate.ResidualLeakCount(got) != 0 {
			t.Fatalf("fallback lost its safe visible byte budget: %q", got)
		}
		if previous, exists := seen[got]; exists {
			t.Fatalf("fallback collapsed distinct source tags %q and %q", previous, tag)
		}
		seen[got] = tag
		if again := proseForBudget(size, tag, gate.ForRequest()); again != got {
			t.Fatal("fallback changed across request gates")
		}
	}
}

func TestProseFillerCollisionGuardPreservesUnchangedOutputAndFitting(t *testing.T) {
	const tag = "unchanged-filler"
	const size = 256
	gate := newTestGate()
	if got := proseForBudget(size, tag, gate); got != proseForLength(size, tag) {
		t.Fatal("identity-free filler changed")
	}
	gate = scrub.NewGate(nil, append([]string(nil), proseWords...), "alias.local")
	text := proseForBudget(size, tag, gate)
	body := []byte("<p>\t" + text + "\n</p>")
	spans := []proseSpan{{start: 4, end: 4 + size, contentTag: tag}}
	for _, target := range []int{128, 384} {
		got := fitProseToBodyLength(body, spans, target, gate)
		if len(got) != target || !strings.HasPrefix(string(got), "<p>\t") || !strings.HasSuffix(string(got), "\n</p>") {
			t.Fatalf("fitted filler lost source boundaries or size: %q", got)
		}
		if gate.ResidualLeakCount(string(got)) != 0 {
			t.Fatalf("fitting reintroduced excluded filler: %q", got)
		}
	}
}

func TestProsePreservesHTMLTextByteBudget(t *testing.T) {
	for _, text := range []string{
		"A", "OK", "abc", "Ordinary prose with sufficient room for a few words.",
		"  café 日本語 &amp; music &#x1F642;  ",
		"\r\n\tSome ordinary prose\t\r\n", "\u2003Some prose\u2003",
		" &nbsp; &#32; ", "\n\t   ",
	} {
		t.Run(text, func(t *testing.T) {
			body := "<p>" + text + "</p>"
			gate := newTestGate()
			got := string(RewriteBody([]byte(body), "text/html", "/", gate, true).Body)
			if len(got) != len(body) || !utf8.ValidString(got) {
				t.Fatalf("source budget not preserved: %d -> %d: %q", len(body), len(got), got)
			}
			if strings.Contains(got, "REDACTED") || strings.Contains(got, "removed") || strings.Count(got, "<") != 2 {
				t.Fatalf("unexpected marker or markup in prose: %q", got)
			}
			trimmed := strings.TrimSpace(html.UnescapeString(text))
			if trimmed == "" {
				if got != body {
					t.Fatalf("whitespace-only token changed: %q", got)
				}
			} else if strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(got, "<p>"), "</p>")) == "" {
				t.Fatal("short ordinary text became invisible")
			}
			again := string(RewriteBody([]byte(body), "text/html", "/", gate, true).Body)
			if got != again {
				t.Fatal("filler is not deterministic")
			}
		})
	}

	const spaced = " \t\r\ntext with literal boundaries\r\n\t "
	got := string(RewriteBody([]byte("<p>"+spaced+"</p>"), "text/html", "/", newTestGate(), true).Body)
	if !strings.HasPrefix(got, "<p> \t\r\n") || !strings.HasSuffix(got, "\r\n\t </p>") {
		t.Fatalf("boundary whitespace changed: %q", got)
	}
}

func TestProseFittingKeepsShortChangesDistinct(t *testing.T) {
	gate := newTestGate()
	seen := make(map[string]string)
	for i := range 100 {
		tag := gate.ContentTag([]byte(fmt.Sprintf("long original source %d", i)))
		body := []byte("<p>\t" + proseForLength(40, tag) + "\n</p>")
		spans := []proseSpan{{start: 4, end: 44, contentTag: tag}}
		got := string(fitProseToBodyLength(body, spans, 11, gate))
		if len(got) != 11 || !strings.HasPrefix(got, "<p>\t") || !strings.HasSuffix(got, "\n</p>") {
			t.Fatalf("fitting damaged the byte budget or literal boundaries: %q", got)
		}
		if prior, ok := seen[got]; ok {
			t.Fatalf("short fitting collapsed tags %q / %q", prior, tag)
		}
		seen[got] = tag
		if again := string(fitProseToBodyLength(body, spans, 11, gate.ForRequest())); again != got {
			t.Fatalf("fitted source remapped: %q / %q", got, again)
		}
	}
	if gate.ShortTextFallbackCount() != 0 {
		t.Fatal("fitting unexpectedly exhausted short outputs")
	}
}

func TestProseShortFittingReportsExhaustion(t *testing.T) {
	gate := newTestGate().ForRequest()
	for i := range 65 {
		tag := gate.ContentTag([]byte(fmt.Sprintf("fitting source %d", i)))
		body := []byte("<p>" + proseForLength(40, tag) + "</p>")
		spans := []proseSpan{{start: 3, end: 43, contentTag: tag}}
		got := fitProseToBodyLength(body, spans, 8, gate)
		if len(got) != 8 {
			t.Fatalf("exhaustion altered the byte budget: %q", got)
		}
	}
	if gate.ShortTextFallbackCount() != 1 {
		t.Fatalf("short fitting did not report finite capacity: %d", gate.ShortTextFallbackCount())
	}
}

func TestProseShortTextKeepsRawEntityAndWhitespaceBudgets(t *testing.T) {
	gate := newTestGate()
	for _, raw := range []string{" \t&amp;\r\n", "\u2003&#65;\u2003", "\n\tĀ\r\n", "&#x123;", "A"} {
		tag := gate.ContentTag([]byte(raw))
		got := proseForHTMLText(raw, tag, gate)
		left, right := proseContentBounds(raw)
		if len(got) != len(raw) || !utf8.ValidString(got) || got[:left] != raw[:left] || got[right:] != raw[right:] {
			t.Fatalf("short raw token budget changed: %q -> %q", raw, got)
		}
		if again := proseForHTMLText(raw, tag, gate.ForRequest()); again != got {
			t.Fatal("raw token remapped across requests")
		}
	}
	const longer = "ordinary longer prose keeps its previous generation"
	tag := gate.ContentTag([]byte(longer))
	if got := proseForBudget(len(longer), tag, gate); got != proseForLength(len(longer), tag) {
		t.Fatal("short-text repair changed longer prose generation")
	}
}

func TestProsePreservesSlashEndedFormElements(t *testing.T) {
	const body = `<textarea name="message"/>keep this value</textarea><select><option/>keep this choice</option></select><p>replace ordinary prose</p>`
	got := string(RewriteBody([]byte(body), "text/html", "/", newTestGate(), true).Body)
	if !strings.Contains(got, "keep this value") || !strings.Contains(got, "keep this choice") || strings.Contains(got, "replace ordinary prose") {
		t.Fatalf("slash-ended form values became filler: %s", got)
	}
}

func TestProsePreservesFormValuesAndDiagnostics(t *testing.T) {
	gate := newTestGate()
	const body = `<form method="post"><textarea name="message">AcmeCorp &amp; café</textarea><select name="choice"><option>AcmeCorp &amp; café</option></select><input name="csrf" value="unchanged"></form><p>ordinary prose</p><div role="alert">E_INPUT: retry <strong>later</strong></div><code>expected=42</code>`
	got := string(RewriteBody([]byte(body), "text/html", "/", gate, true).Body)
	if strings.Contains(got, "ordinary prose") || strings.Contains(got, "AcmeCorp") {
		t.Fatalf("expected configured transformations missing: %s", got)
	}
	for _, fragment := range []string{`method="post"`, `name="csrf" value="unchanged"`, "E_INPUT: retry", "<strong>later</strong>", "<code>expected=42</code>"} {
		if !strings.Contains(got, fragment) {
			t.Fatalf("functional/diagnostic content missing: %s", fragment)
		}
	}
	doc, err := html.Parse(strings.NewReader(got))
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "textarea" || n.Data == "option") {
			for child := n.FirstChild; child != nil; child = child.NextSibling {
				if child.Type == html.TextNode {
					values[n.Data] += child.Data
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(doc)
	for _, tag := range []string{"textarea", "option"} {
		if restored := gate.RestoreBody(values[tag]); restored != "AcmeCorp & café" {
			t.Fatalf("%s no longer round-trips its submitted value: %q", tag, restored)
		}
	}
}

func TestProseDistinguishesEqualLengthSourcesWithinSession(t *testing.T) {
	gate := newTestGate()
	first := []byte("<p>\n\t" + strings.Repeat("AcmeCorp bright morning. ", 12) + "\t\n</p>")
	second := []byte("<p>\n\t" + strings.Repeat("AcmeCorp silent evening. ", 12) + "\t\n</p>")
	if len(first) != len(second) {
		t.Fatal("fixture source lengths differ")
	}
	a := RewriteBody(first, "text/html", "/", gate, true).Body
	b := RewriteBody(second, "text/html", "/", gate, true).Body
	if len(a) != len(first) || len(b) != len(second) || string(a) == string(b) {
		t.Fatalf("equal-length differences collapsed: %q / %q", a, b)
	}
	if strings.Contains(string(a), "AcmeCorp") || strings.Contains(string(b), "AcmeCorp") {
		t.Fatal("filler leaked configured identity")
	}
	again := RewriteBody(first, "text/html", "/", gate.ForRequest(), true).Body
	if string(again) != string(a) {
		t.Fatal("request-local view lost session-stable prose")
	}
	other := RewriteBody(first, "text/html", "/", newTestGate(), true).Body
	if string(other) == string(a) {
		t.Fatal("independent session emitted identical long prose")
	}
}

func TestProseResizingRetainsSourceDependentGeneration(t *testing.T) {
	gate := newTestGate()
	firstTag := gate.ContentTag([]byte(strings.Repeat("a", 240)))
	secondTag := gate.ContentTag([]byte(strings.Repeat("b", 240)))
	for _, target := range []int{180, 300} {
		makeBody := func(tag string) string {
			original := "<p>" + proseForLength(240, tag) + "</p>"
			spans := []proseSpan{{start: 3, end: 243, contentTag: tag}}
			resized := fitProseToBodyLength([]byte(original), spans, target+7, gate)
			if len(resized) != target+7 || !strings.HasPrefix(string(resized), "<p>") || !strings.HasSuffix(string(resized), "</p>") {
				t.Fatalf("invalid resized prose: %q", resized)
			}
			return string(resized)
		}
		first, second := makeBody(firstTag), makeBody(secondTag)
		if first == second {
			t.Fatalf("resize to %d erased source-dependent content", target)
		}
		if first != makeBody(firstTag) {
			t.Fatalf("resize to %d is not stable", target)
		}
	}
}

func TestWholeDocumentFitDoesNotCollapseEqualLengthChanges(t *testing.T) {
	gate := newTestGate()
	for _, prefix := range []string{"<title>X</title>", "<title>" + strings.Repeat("Long original title ", 20) + "</title>"} {
		first := prefix + "<p>" + strings.Repeat("The bright morning returns. ", 16) + "</p>"
		second := prefix + "<p>" + strings.Repeat("The silent evening returns. ", 16) + "</p>"
		if len(first) != len(second) {
			t.Fatal("fixture source lengths differ")
		}
		a := RewriteBody([]byte(first), "text/html", "/", gate, true).Body
		b := RewriteBody([]byte(second), "text/html", "/", gate, true).Body
		if len(a) != len(first) || len(b) != len(second) || string(a) == string(b) {
			t.Fatalf("whole-body fitting collapsed content: %q / %q", a, b)
		}
	}
}
