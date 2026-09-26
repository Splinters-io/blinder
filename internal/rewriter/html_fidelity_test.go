package rewriter

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestHTMLFidelityUnchangedSourceTokens(t *testing.T) {
	for _, source := range []string{
		"<!DOCTYPE HTML>\r\n<DiV\tCLASS = 'panel' data-note=plain>text</DiV \t>",
		`<INPUT DISABLED value=first VALUE='second' data-entity="one&#38;two"/><BR ><HR/>`,
		"<PRE>A&amp;B &#x27; &#39; &#00039; &nbsp; &notanentity;\r\n</PRE>",
		"<textarea name='q'>literal &amp; &#00038; &#x26; café\r\nsecond</textarea>",
		"<ScRiPt TYPE='text/javascript'>\r\nconst x = '&amp;';\r\n// keep line endings\r\n</ScRiPt >",
		"<STYLE media='all'>\r\np { content: '&amp;'; color: blue; }\r\n</STYLE >",
		"<div><!-- E_INPUT: SQLSTATE[42000] &#x27; near SELECT\r\n --></div>",
		`<p>before</p><?diagnostic E_INPUT?><!E_INPUT></><p>after</p>`,
		`<p>before</p><!-- E_INPUT --!><p>after</p>`,
		`<p>before</p><!-- E_INPUT without a closing delimiter`,
	} {
		t.Run(source, func(t *testing.T) {
			gate := scrub.NewGate(nil, nil, "alias.local")
			got := RewriteBody([]byte(source), "text/html", "/", gate, false).Body
			if string(got) != source {
				t.Fatalf("unchanged source was normalized:\n got %q\nwant %q", got, source)
			}
		})
	}
}

func TestHTMLFidelityChangedTokenLeavesNeighborsRaw(t *testing.T) {
	gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	source := "<DiV\tdata-note='AcmeCorp' keep='one&#38;two'>before &amp; after</DiV >\r\n<SPAN disabled data-x=plain>tail&#33;</SPAN >"
	got := string(RewriteBody([]byte(source), "text/html", "/", gate, false).Body)
	if !strings.HasPrefix(got, "<DiV\tdata-note='"+scrub.ValueAliasPrefix) || !strings.Contains(got, ` keep='one&#38;two'>`) {
		t.Fatalf("changed start tag did not retain the configured transformation: %s", got)
	}
	wantSuffix := "before &amp; after</DiV >\r\n<SPAN disabled data-x=plain>tail&#33;</SPAN >"
	if !strings.HasSuffix(got, wantSuffix) {
		t.Fatalf("neighboring unchanged tokens were normalized: %s", got)
	}
	if count := gate.ReplacementCount(); count != 1 {
		t.Fatalf("attribute planning scrubbed more than once: replacements=%d", count)
	}
}

func TestHTMLFidelityRawTagGuardDoesNotExposeIgnoredIdentity(t *testing.T) {
	gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	source := `<P>before</P data-note='&#65;cmeCorp'><SPAN>after</SPAN >`
	got := string(RewriteBody([]byte(source), "text/html", "/", gate, false).Body)
	if got != `<P>before</p><SPAN>after</SPAN >` {
		t.Fatalf("raw closing tag exposed ignored identity or changed following source: %s", got)
	}
	gate = scrub.NewGate(nil, []string{"<DiV\tid"}, "alias.local")
	source = "<DiV\tid=x>text</DiV >"
	got = string(RewriteBody([]byte(source), "text/html", "/", gate, false).Body)
	if strings.Contains(got, "<DiV\tid") || !strings.Contains(got, `<div id="x">`) {
		t.Fatalf("raw start tag preserved an identity spanning syntax: %s", got)
	}
}

func TestHTMLFidelityTruncatedSourceIsObservableWithoutDuplicateBytes(t *testing.T) {
	for _, source := range []string{
		`<P>before</P><DiV data-note='unfinished`,
		"<P>before</P><DiV\tdata-note=unfinished",
		`<P>before</P><DiV`,
		`<P>before</P></DiV ignored='unfinished`,
		`<P>before</P>plain text`,
		`<P>before</P><`,
		`<P>before</P>`,
	} {
		t.Run(source, func(t *testing.T) {
			gate := scrub.NewGate(nil, nil, "alias.local")
			got := RewriteBody([]byte(source), "text/html", "/", gate, false).Body
			if string(got) != source {
				t.Fatalf("EOF dropped or repeated source bytes:\n got %q\nwant %q", got, source)
			}
		})
	}
}

func TestHTMLFidelityTruncatedIdentityRetainsOmission(t *testing.T) {
	for _, identity := range []string{"AcmeCorp", "&#65;cmeCorp", "Acme&#x43;orp"} {
		t.Run(identity, func(t *testing.T) {
			gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
			const prefix = `<P>SQLSTATE[42000] before truncation</P>`
			source := prefix + `<DiV data-note='` + identity
			got := RewriteBody([]byte(source), "text/html", "/", gate, false).Body
			if string(got) != prefix {
				t.Fatalf("truncated identity exposed or diagnostics changed: %q", got)
			}
		})
	}
}

func TestHTMLFidelityCommentsDecodeIdentityWithoutCreatingMarkup(t *testing.T) {
	for _, encodedIdentity := range []string{"AcmeCorp", "&#65;cmeCorp", "Acme&#x43;orp"} {
		t.Run(encodedIdentity, func(t *testing.T) {
			gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
			source := "<!-- E_INPUT " + encodedIdentity + " SQLSTATE[42000] &lt;script&gt; --&gt; &lt;img src=x&gt; -->" + `<P data-x='keep'>after</P >`
			got := string(RewriteBody([]byte(source), "text/html", "/", gate, false).Body)
			if strings.Contains(html.UnescapeString(got), "AcmeCorp") || !strings.Contains(got, "SQLSTATE[42000]") {
				t.Fatalf("comment identity or diagnostic handling failed: %s", got)
			}
			if !strings.HasSuffix(got, `<P data-x='keep'>after</P >`) {
				t.Fatalf("following source changed: %s", got)
			}
			z := html.NewTokenizer(strings.NewReader(got))
			if z.Next() != html.CommentToken {
				t.Fatalf("transformed comment is no longer a comment: %s", got)
			}
			comment := string(z.Raw())
			if strings.Count(comment, "-->") != 1 || strings.Contains(comment, "<script>") || strings.Contains(comment, "<img") {
				t.Fatalf("decoded comment content changed its parser boundary: %q", comment)
			}
			if z.Next() != html.StartTagToken {
				t.Fatalf("comment ended before the following intended element: %s", got)
			}
			name, _ := z.TagName()
			if string(name) != "p" {
				t.Fatalf("comment content became an element: %s", got)
			}
			if gate.ReplacementCount() != 1 {
				t.Fatalf("comment scrub ran more than once: %d", gate.ReplacementCount())
			}
		})
	}
}

func TestHTMLFidelityUnusualCommentsRetainSafeOmissionOnChanges(t *testing.T) {
	for _, source := range []string{
		`<?E_INPUT AcmeCorp?>`, `<!E_INPUT &#65;cmeCorp>`, `<!-- E_INPUT AcmeCorp --!>`, `<!-- E_INPUT AcmeCorp`,
	} {
		t.Run(source, func(t *testing.T) {
			gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
			got := RewriteBody([]byte(source), "text/html", "/", gate, false).Body
			if len(got) != 0 {
				t.Fatalf("changed unusual comment should retain omission policy: %q", got)
			}
		})
	}
}

func TestHTMLFidelityCommentDelimiterIdentityResidualGuard(t *testing.T) {
	for _, identity := range []string{"<!--Acme", "Acme-->", "<!--Acme-->"} {
		t.Run(identity, func(t *testing.T) {
			gate := scrub.NewGate(nil, []string{identity}, "alias.local")
			const source = "<!--Acme-->"
			if gate.ResidualLeakCount(source) == 0 {
				t.Fatal("fixture identity does not cross the comment boundary")
			}
			got := RewriteBody([]byte(source), "text/html", "/", gate, false).Body
			if len(got) != 0 {
				t.Fatalf("comment delimiter preserved a configured identity: %q", got)
			}
		})
	}
}

func TestHTMLFidelityRetainsParanoidImageAndTitleRules(t *testing.T) {
	const diagnostic = `<PRE role='alert'>SQLSTATE[42000] &#x27; bad input</PRE >`
	const submitted = "<TEXTAREA name=q>unchanged &#00038;\r\nvalue</TEXTAREA >"
	source := `<TiTlE>Original title</TiTlE >` + `<IMG src='icon' alt='original'>` + diagnostic + submitted + `<p>` + strings.Repeat("Ordinary prose goes here. ", 20) + `</p>`
	got := string(RewriteBody([]byte(source), "text/html", "/", scrub.NewGate(nil, nil, "alias.local"), true).Body)
	if (!strings.HasPrefix(got, `<TiTlE>`) || !strings.Contains(got, `</TiTlE >`) || strings.Contains(got, "Original title")) || !strings.Contains(got, transparentGifDataURI) || !strings.Contains(got, `alt='[image]'`) {
		t.Fatalf("required image/title transforms were bypassed: %s", got)
	}
	if !strings.Contains(got, diagnostic) || !strings.Contains(got, submitted) {
		t.Fatalf("protected diagnostics/submitted values lost source fidelity: %s", got)
	}
	if strings.Contains(got, "Ordinary prose goes here") || len(got) != len(source) {
		t.Fatalf("paranoid replacement/body size fitting changed: %d -> %d: %s", len(source), len(got), got)
	}
}

func TestHTMLFidelitySRIChangesArePlannedOnce(t *testing.T) {
	gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	registrations := 0
	sr := &sriRewriter{registerVersion: func(upstreamURL, bodyVersion string) string {
		registrations++
		if upstreamURL != "https://target.test/asset" || bodyVersion != "version" {
			t.Fatalf("unexpected version registration: %q %q", upstreamURL, bodyVersion)
		}
		return "fixture-token"
	}}
	attrs := []tagAttr{{"src", "/asset#fragment"}, {"integrity", "sha384-old"}, {"data-note", "AcmeCorp"}}
	got, changed := rewriteTagAttrs("script", attrs, gate, nil, sriDecision{action: sriReplace, replacementHash: "sha384-new", bodyVersion: "version", resolvedURL: "https://target.test/asset#fragment"}, sr)
	if !changed || registrations != 1 || gate.ReplacementCount() != 1 {
		t.Fatalf("planned twice or lost changes: changed=%v registrations=%d replacements=%d", changed, registrations, gate.ReplacementCount())
	}
	if got[0].val != "/asset?__blv=fixture-token#fragment" || got[1].val != "sha384-new" {
		t.Fatalf("SRI planned values changed: %#v", got)
	}
	_, changed = rewriteTagAttrs("script", []tagAttr{{"integrity", "sha384-first"}, {"integrity", "sha384-second"}}, gate, nil, sriDecision{action: sriKeep, integrityVal: "sha384-second"}, nil)
	if !changed {
		t.Fatal("sriKeep incorrectly bypassed an actual duplicate-attribute change")
	}
}

func TestHTMLFidelitySRIStripAndBlockKeepFollowingSource(t *testing.T) {
	const following = `<P data-x='keep'>after&#33;</P >`
	t.Run("strip", func(t *testing.T) {
		source := `<ScRiPt SRC='/asset' INTEGRITY='sha384-old' CROSSORIGIN=anonymous></ScRiPt >` + following
		got := string(RewriteBody([]byte(source), "text/html", "/", scrub.NewGate(nil, nil, "alias.local"), false).Body)
		if strings.Contains(strings.ToLower(got), "integrity") || strings.Contains(strings.ToLower(got), "crossorigin") || !strings.HasSuffix(got, "</ScRiPt >"+following) {
			t.Fatalf("SRI strip or following raw source failed: %s", got)
		}
	})
	t.Run("block", func(t *testing.T) {
		jsBody := []byte(`const value = "real";`)
		pipeline, _, srv, gate, origins := sriTestSetup(t, jsBody, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(jsBody)
		})
		defer srv.Close()
		base, _ := url.Parse(srv.URL)
		request, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
		wrongIntegrity := "sha384-" + sha384hash([]byte("different"))
		source := `<ScRiPt SRC='/asset' INTEGRITY='` + wrongIntegrity + `'>window.mustNotExecute = true;</ScRiPt >` + following
		got := RewriteBody([]byte(source), "text/html", "/", gate, false, RewriteOpts{Origins: origins, SRIPipeline: pipeline, UpstreamBase: base, BaseRequest: request}).Body
		if string(got) != following {
			t.Fatalf("blocked element or following source leaked/changed: %s", got)
		}
	})
	t.Run("block_truncated_end_tag", func(t *testing.T) {
		jsBody := []byte(`const value = "real";`)
		pipeline, _, srv, gate, origins := sriTestSetup(t, jsBody, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(jsBody)
		})
		defer srv.Close()
		base, _ := url.Parse(srv.URL)
		request, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
		wrongIntegrity := "sha384-" + sha384hash([]byte("different"))
		const prefix = `<P data-x='keep'>before</P >`
		source := prefix + `<ScRiPt SRC='/asset' INTEGRITY='` + wrongIntegrity + `'>window.mustNotExecute = true;</ScRiPt ignored='unfinished`
		got := RewriteBody([]byte(source), "text/html", "/", gate, false, RewriteOpts{Origins: origins, SRIPipeline: pipeline, UpstreamBase: base, BaseRequest: request}).Body
		if string(got) != prefix {
			t.Fatalf("EOF preservation revived blocked source: %s", got)
		}
	})
}
