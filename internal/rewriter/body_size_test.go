package rewriter

import (
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Splinters-io/blinder/internal/captcha"
)

func TestBodySizeFitsWholeHTMLUsingOnlyProse(t *testing.T) {
	const protected = `<script>window.fixture = 42;</script><style>p { color: blue; }</style><pre>SQLSTATE[42000]: invalid input</pre><form method="post"><textarea name="q">literal &amp; café</textarea><select><option>keep this choice</option></select><input type="hidden" name="csrf" value="keep-this-token"></form>`
	for _, tc := range []struct{ name, prefix string }{
		{"shrink", `<title>X</title><div title="AcmeCorp">`},
		{"expand", `<title>` + strings.Repeat("Long page title ", 30) + `</title><!--` + strings.Repeat("comment ", 30) + `--><div>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := newTestGate()
			const first = "\n\tA paragraph of ordinary prose that can absorb size differences.\t\n"
			const second = "\u2003Another paragraph with café, 日本語, and &amp; entities.\u2003"
			body := tc.prefix + "<p>" + first + "</p><p>" + second + "</p>" + protected + "</div>"
			got := string(RewriteBody([]byte(body), "text/html", "/", gate, true).Body)
			if len(got) != len(body) || !utf8.ValidString(got) {
				t.Fatalf("body size/UTF-8 changed: %d -> %d: %s", len(body), len(got), got)
			}
			if !strings.Contains(got, protected) {
				t.Fatalf("size matching modified functional content: %s", got)
			}
			for _, edge := range []string{"<p>\n\t", "\t\n</p>", "<p>\u2003", "\u2003</p>"} {
				if !strings.Contains(got, edge) {
					t.Fatalf("size matching removed literal boundary whitespace: %q", edge)
				}
			}
			if strings.Contains(got, "ordinary prose") || strings.Contains(got, "AcmeCorp") {
				t.Fatal("existing transformations were undone")
			}
			if again := string(RewriteBody([]byte(body), "text/html", "/", gate, true).Body); again != got {
				t.Fatal("whole-body matching is not deterministic")
			}
		})
	}
}

func TestBodySizeDoesNotSacrificeDiagnosticsForExactLength(t *testing.T) {
	for _, tc := range []struct {
		name, body, contentType string
		status                  int
	}{
		{"too-small", `<p>A</p><pre>AcmeCorp: SQLSTATE[42000] invalid input</pre>`, "text/html", 200},
		{"no-prose", `<pre>AcmeCorp: SQLSTATE[42000] invalid input</pre>`, "text/html", 200},
		{"error-page", `<p>AcmeCorp: SQLSTATE[42000] invalid input</p>`, "text/html", 500},
		{"json", `{"error":"AcmeCorp: SQLSTATE[42000] invalid input","number":900719925474099312345}`, "application/json", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := string(RewriteBody([]byte(tc.body), tc.contentType, "/", newTestGate(), true, RewriteOpts{StatusCode: tc.status}).Body)
			if !strings.Contains(got, "SQLSTATE[42000] invalid input") || len(got) <= len(tc.body) {
				t.Fatalf("missing diagnostic or impossible size silently forced: %s", got)
			}
			if tc.name == "too-small" {
				first, _, _ := strings.Cut(strings.TrimPrefix(got, "<p>"), "</p>")
				if len(first) != 1 || strings.TrimSpace(first) == "" {
					t.Fatal("visible minimum prose removed to meet length")
				}
			}
			if tc.name == "json" && !strings.Contains(got, "900719925474099312345") {
				t.Fatal("JSON precision changed")
			}
		})
	}
}

func TestBodySizeFitsAfterProviderResourceURLExpansion(t *testing.T) {
	cfg, err := captcha.ParseConfig([]byte("version: 1\ncaptcha:\n  custom:\n    - name: fixture\n      resource_origins: [https://provider.test]\n"))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse("https://target.example.com/")
	const resource = "https://provider.test/api.js?x=one&onload=ready"
	want, handled := cfg.Matcher.RewriteResourceURL(resource, base, true)
	if !handled || len(want) <= len(resource) {
		t.Fatal("fixture must expand the provider URL")
	}
	body := `<title>X</title><p>` + strings.Repeat("Ordinary page content. ", 12) + `</p><script src="https://provider.test/api.js?x=one&amp;onload=ready"></script>`
	got := string(RewriteBody([]byte(body), "text/html", "/", newTestGate(), true, RewriteOpts{
		UpstreamBase: base,
		ResourceURL: func(raw string, base *url.URL) (string, bool) {
			return cfg.Matcher.RewriteResourceURL(raw, base, true)
		},
	}).Body)
	if len(got) != len(body) || !strings.Contains(got, `src="`+want+`"`) {
		t.Fatalf("fit ran before URL expansion or damaged the route: %d -> %d: %s", len(body), len(got), got)
	}
}

func TestBodySizeUsesAllAvailableProseWithoutErasingNodes(t *testing.T) {
	gate := newTestGate()
	// Identity expansion requires more bytes than either prose node alone
	// can supply. Title text no longer creates its own artificial expansion.
	delta := len(gate.Scrub("AcmeCorp", "fixture")) - len("AcmeCorp")
	if delta < 2 {
		t.Fatal("fixture needs an expanding identity alias")
	}
	budget := (delta+1)/2 + 1
	body := `<div title="AcmeCorp"><p>` + strings.Repeat("a", budget) + `</p><p>` + strings.Repeat("b", budget) + `</p></div>`
	got := string(RewriteBody([]byte(body), "text/html", "/", gate, true).Body)
	if len(got) != len(body) || strings.Count(got, "<p>") != 2 || strings.Contains(got, "<p></p>") {
		t.Fatalf("prose capacity not shared: %s", got)
	}
}
