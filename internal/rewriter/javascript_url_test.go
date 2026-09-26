package rewriter

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
	"golang.org/x/net/html"
)

func rewrittenLink(t *testing.T, body []byte) string {
	t.Helper()
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		switch z.Next() {
		case html.ErrorToken:
			t.Fatal("missing anchor href")
		case html.StartTagToken:
			token := z.Token()
			if token.Data == "a" {
				for _, a := range token.Attr {
					if a.Key == "href" {
						return a.Val
					}
				}
			}
		}
	}
}

func TestJavaScriptURLPreservesExecutableSyntaxAndMasksStrings(t *testing.T) {
	for _, raw := range []string{
		`javascript:window.audit='AcmeCorp';void(0)`,
		`javascript:window%2Eaudit=%27%41cmeCorp%27;void(0)`,
		" \tJaVa\nScRiPt:window.audit='AcmeCorp';void(0)\r ",
		`javascript:window.audit='AcmeCorp%25';void(0)`,
		`javascript:window.audit='AcmeCorp';//%0Avoid(0)`,
	} {
		t.Run(raw, func(t *testing.T) {
			g := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
			body := `<a href="` + html.EscapeString(raw) + `">go</a>`
			result := RewriteBody([]byte(body), "text/html", "/", g, false)
			got := rewrittenLink(t, result.Body)
			_, before, _ := javascriptURL(raw)
			_, after, ok := javascriptURL(got)
			if !ok || !strings.Contains(after, "window.audit=") || strings.Contains(after, "AcmeCorp") || g.RestoreBody(after) != before {
				t.Fatalf("code/data boundary changed: %q -> %q", before, after)
			}
		})
	}
}

func TestJavaScriptURLUnchangedSpellingAndNonURLAttributes(t *testing.T) {
	g := scrub.NewGate(nil, nil, "alias.local")
	const value = `javascript:window.audit=1;void(0)`
	result := RewriteBody([]byte(`<a href='`+value+`'>go</a>`), "text/html", "/", g, false)
	if string(result.Body) != `<a href='`+value+`'>go</a>` {
		t.Fatalf("unchanged source normalized: %s", result.Body)
	}
	if _, ok := rewriteJavaScriptURL("/javascript:window.audit=1", g, nil); ok {
		t.Fatal("relative path treated as code")
	}
}

func TestJavaScriptURLCSPBindsOriginalDecodedURL(t *testing.T) {
	for _, directive := range []string{"script-src", "script-src-elem", "default-src"} {
		g := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
		const raw = `javascript:window.audit='AcmeCorp';void(0)`
		out := RewriteBody([]byte(`<a href="`+raw+`">go</a>`), "text/html", "/", g, false)
		after := rewrittenLink(t, out.Body)
		beforeHash, afterHash := cspDigests(javascriptCSPSource(raw))[0], cspDigests(javascriptCSPSource(after))[0]
		if beforeHash == afterHash {
			t.Fatal("fixture did not rewrite")
		}
		header := http.Header{"Content-Security-Policy": {directive + " 'unsafe-hashes' 'sha256-" + beforeHash + "'"}}
		out.CSPHashes.RewriteHeaders(header)
		if !strings.Contains(header.Get("Content-Security-Policy"), "'sha256-"+afterHash+"'") {
			t.Fatalf("original permission lost: %v", header)
		}
		header.Set("Content-Security-Policy", directive+" 'unsafe-hashes' 'sha256-"+afterHash+"'")
		out.CSPHashes.RewriteHeaders(header)
		if !strings.Contains(header.Get("Content-Security-Policy"), "'sha256-AA=='") {
			t.Fatalf("transformed-only hash became permission: %v", header)
		}
	}
}

func TestJavaScriptURLHashScopeAndCollisionWhitespace(t *testing.T) {
	const before = `javascript:window.audit='AcmeCorp';void(0)`
	const after = `javascript:window.audit='[v:1234]';void(0)`
	c := &CSPHashes{}
	d := cspDigests([]byte(after))
	c.reserveDigests(d, d)
	suffix := c.record("script-navigation", 0, []byte(before), []byte(after))
	serialized, source, ok := javascriptURL(after + string(suffix))
	if !ok || serialized != after+string(suffix) || strings.TrimSpace(source) != strings.TrimPrefix(after, "javascript:") {
		t.Fatalf("collision separator changed URL execution or disappeared: %q", suffix)
	}
	policy := "script-src-elem 'unsafe-hashes' 'sha256-" + cspDigests([]byte(before))[0] + "'"
	if got := c.rewritePolicy(policy, 100); !strings.Contains(got, cspDigests(javascriptCSPSource(serialized))[0]) {
		t.Fatalf("later meta lost link permission: %s", got)
	}
	attrPolicy := "script-src-attr 'unsafe-hashes' 'sha256-" + cspDigests([]byte(before))[0] + "'"
	if got := c.rewritePolicy(attrPolicy, 0); got != attrPolicy {
		t.Fatalf("navigation changed attribute-only permission: %s", got)
	}
}

func TestJavaScriptURLPercentSpellingDoesNotGainCSPPermission(t *testing.T) {
	g := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	const raw = `javascript:window.audit=%27AcmeCorp%27;void(0)`
	out := RewriteBody([]byte(`<a href="`+raw+`">go</a>`), "text/html", "/", g, false)
	after := rewrittenLink(t, out.Body)
	denied := "script-src 'unsafe-hashes' 'sha256-" + cspDigests([]byte(raw))[0] + "'"
	if got := out.CSPHashes.rewritePolicy(denied, 0); got != denied {
		t.Fatalf("encoded-only denied hash gained rewritten grant: %s", got)
	}
	allowed := "script-src 'unsafe-hashes' 'sha256-" + cspDigests(javascriptCSPSource(raw))[0] + "'"
	if got := out.CSPHashes.rewritePolicy(allowed, 0); !strings.Contains(got, cspDigests(javascriptCSPSource(after))[0]) {
		t.Fatalf("decoded original grant lost: %s", got)
	}
}

func TestJavaScriptURLChromiumIsomorphicDecoding(t *testing.T) {
	for _, tc := range []struct{ encoded, decoded string }{
		{"\xff", "\ufffd"},
		{"%FF", "ÿ"}, {"%C3%A9", "é"}, {"%C3%A9%FF", "Ã©ÿ"}, {"%FF%C3%A9", "ÿÃ©"},
		{"%ED%A0%80", "í\u00a0\u0080"}, {"%C0%AF", "À¯"}, {"%ZZ%", "%ZZ%"}, {"%00", "\x00"},
	} {
		g := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
		original := "javascript:window.audit='AcmeCorp" + tc.encoded + "';void(0)"
		_, code, _ := javascriptURL(original)
		want := "window.audit='AcmeCorp" + tc.decoded + "';void(0)"
		if code != want {
			t.Fatalf("%q decoded to %q, want %q", tc.encoded, code, want)
		}
		rewritten, _ := rewriteJavaScriptURL(original, g, nil)
		_, after, _ := javascriptURL(rewritten)
		if g.RestoreBody(after) != want {
			t.Fatalf("rewriting changed URL decoding: %q", after)
		}
	}
}
