package rewriter

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTitleMaskKeepsOriginalBodyBytes(t *testing.T) {
	for _, paranoid := range []bool{false, true} {
		for _, source := range []string{
			`<title>X</title>`, `<title></title>`, `<TiTlE>AcmeCorp café &amp; 日本語</TiTlE >`,
			"<title> \tAcmeCorp\r\n</title>", `<title>AcmeCorp`, `<title> &nbsp; &#32; </title>`,
			`<title>` + strings.Repeat("Long original title ", 30) + `</title>`,
		} {
			gate := newTestGate()
			got := string(RewriteBody([]byte(source), "text/html", "/", gate, paranoid).Body)
			if len(got) != len(source) || !utf8.ValidString(got) || strings.Contains(got, "AcmeCorp") || strings.Contains(got, "Long original title") || strings.Contains(got, "Transformed view") {
				t.Fatalf("paranoid=%v title/body budget lost: %q -> %q", paranoid, source, got)
			}
			if again := string(RewriteBody([]byte(source), "text/html", "/", gate, paranoid).Body); again != got {
				t.Fatal("same title changed within session")
			}
			if strings.Contains(source, "<TiTlE>") && (!strings.HasPrefix(got, "<TiTlE>") || !strings.HasSuffix(got, "</TiTlE >")) {
				t.Fatal("title source envelope changed")
			}
			if strings.HasSuffix(source, "Corp") && strings.Contains(got, "</title>") {
				t.Fatal("repaired an incomplete title")
			}
		}
	}
}

func TestTitleOnlyResponseChangesRetainBodySignal(t *testing.T) {
	gate := newTestGate()
	first := `<title>` + strings.Repeat("First synthetic title result. ", 8) + `</title>`
	second := strings.ReplaceAll(first, "First", "Other")
	a := RewriteBody([]byte(first), "text/html", "/", gate, true).Body
	b := RewriteBody([]byte(second), "text/html", "/", gate, true).Body
	if len(a) != len(first) || len(b) != len(second) || string(a) == string(b) {
		t.Fatalf("same-size title changes collapsed or changed size: %q / %q", a, b)
	}
}
