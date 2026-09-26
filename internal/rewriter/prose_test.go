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
			got := string(RewriteBody([]byte(body), "text/html", "/", newTestGate(), true).Body)
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
			again := string(RewriteBody([]byte(body), "text/html", "/", newTestGate(), true).Body)
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
