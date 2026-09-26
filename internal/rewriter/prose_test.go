package rewriter

import (
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/net/html"
)

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
			resized := fitProseToBodyLength([]byte(original), spans, target+7)
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
