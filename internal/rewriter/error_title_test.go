package rewriter

import (
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestErrorTitlePreservesDiagnosticSource(t *testing.T) {
	for _, status := range []int{400, 422, 500, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			// The title is the only diagnostic. Preserve its exact spelling,
			// whitespace, and body size when no identity needs replacing.
			const source = "<!doctype html><TiTlE>SQLSTATE[42000]: syntax error &#x27;\r\n at input</TiTlE ><p>Try again.</p>"
			got := RewriteBody([]byte(source), "text/html", "/", newTestGate(), true, RewriteOpts{StatusCode: status}).Body
			if string(got) != source {
				t.Fatalf("error title/body diagnostic changed: got %q want %q", got, source)
			}
		})
	}
}

func TestErrorTitleMasksIdentityWithoutLosingDiagnostic(t *testing.T) {
	const source = `<title>AcmeCorp on target.example.com: SQLSTATE[42000]: unexpected &lt;script&gt; &amp; input</title><p>Retry.</p>`
	got := string(RewriteBody([]byte(source), "text/html", "/", newTestGate(), true, RewriteOpts{StatusCode: 500}).Body)
	decoded := html.UnescapeString(got)
	if strings.Contains(decoded, "AcmeCorp") || strings.Contains(decoded, "target.example.com") || !strings.Contains(decoded, "SQLSTATE[42000]: unexpected <script> & input") {
		t.Fatalf("identity or diagnostic title policy failed: %s", got)
	}
	if strings.Contains(got, "<script>") || strings.Count(got, "</title>") != 1 {
		t.Fatalf("title masking changed the HTML structure: %s", got)
	}
}

func TestErrorTitlePreservesTruncatedDiagnostic(t *testing.T) {
	const source = `<title>SQLSTATE[42000]: incomplete response`
	got := string(RewriteBody([]byte(source), "text/html", "/", newTestGate(), true, RewriteOpts{StatusCode: 500}).Body)
	if got != source {
		t.Fatalf("truncated error title lost: %q", got)
	}
}
