package rewriter

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func attrEditFixture(raw string) (string, []tagAttr) {
	z := html.NewTokenizer(strings.NewReader(raw))
	z.Next()
	name, hasAttrs := z.TagName()
	if !hasAttrs {
		return string(name), nil
	}
	return string(name), collectTagAttrs(z)
}

func TestHTMLQuotedAttrEditsPreserveExactSizeAndSource(t *testing.T) {
	gate := scrub.NewGate(nil, []string{"BrandToken"}, "alias.local")
	for _, source := range []string{
		`<INPUT DISABLED data-note='BrandToken'>`,
		"<DiV\tdata-note = 'BrandToken' keep='one&#38;two' literal=\"'\" encoded=\"&#39;\">",
		`<input data-note="BrandToken" disabled checked='yes' />`,
	} {
		t.Run(source, func(t *testing.T) {
			name, before := attrEditFixture(source)
			after := append([]tagAttr(nil), before...)
			for i := range after {
				after[i].val = gate.Scrub(after[i].val, "test:attr")
			}
			count := gate.ReplacementCount()
			got, ok := rewriteHTMLQuotedAttrs([]byte(source), name, before, after, gate)
			want := strings.ReplaceAll(source, "BrandToken", gate.Scrub("BrandToken", "test:expected"))
			if !ok || string(got) != want || len(got) != len(source) {
				t.Fatalf("unrelated source spelling or size changed: %q -> %q, want %q (accepted %v)", source, got, want, ok)
			}
			if gate.ReplacementCount() != count+1 {
				t.Fatal("surgical editing ran the scrubber again")
			}
		})
	}
}

func TestHTMLQuotedAttrEditsPreserveDecodedSemantics(t *testing.T) {
	for _, source := range []string{`<button data-note='old' keep="&#x27;">`, `<button data-note="old" keep='&#34;'>`} {
		name, before := attrEditFixture(source)
		after := append([]tagAttr(nil), before...)
		after[0].val = "one ' two \" three & four < five > six\r\n\t"
		got, ok := rewriteHTMLQuotedAttrs([]byte(source), name, before, after, nil)
		if !ok {
			t.Fatalf("valid quoted replacement rejected: %s", source)
		}
		_, actual := attrEditFixture(string(got))
		if len(actual) != len(after) || actual[0] != after[0] || actual[1] != after[1] {
			t.Fatalf("replacement changed parsed attribute values: %#v / %#v", actual, after)
		}
		if !bytes.Contains(got, []byte(source[strings.Index(source, " keep="):])) {
			t.Fatalf("untouched escaped attribute was normalized: %q", got)
		}
	}
}

func TestHTMLQuotedAttrEditsDeclineUnsafeOrAmbiguousCases(t *testing.T) {
	for _, source := range []string{
		`<div data-note='old' DATA-NOTE='second'>`,
		`<div data-note=old>`,
		`<div data-note='old'id='x'>`,
		`<div data-note='old' other=un'quoted>`,
		`<div data-note='old' / >`,
		"<div data-note='old' other='\x00'>",
		"<div data-note='old' other='\xff'>",
	} {
		t.Run(source, func(t *testing.T) {
			name, before := attrEditFixture(source)
			after := append([]tagAttr(nil), before...)
			if len(after) == 0 {
				t.Fatal("fixture has no parsed attributes")
			}
			after[0].val = "new"
			if got, ok := rewriteHTMLQuotedAttrs([]byte(source), name, before, after, nil); ok {
				t.Fatalf("unsafe source accepted: %q", got)
			}
		})
	}
	const source = `<input disabled data-note='old'>`
	name, before := attrEditFixture(source)
	for _, after := range [][]tagAttr{
		{{"disabled", "yes"}, {"data-note", "new"}},
		{{"disabled", ""}},
		{{"disabled", ""}, {"data-note", "new"}, {"extra", "x"}},
		{{"data-note", "new"}, {"disabled", ""}},
	} {
		if got, ok := rewriteHTMLQuotedAttrs([]byte(source), name, before, after, nil); ok {
			t.Fatalf("attribute-list/boolean change accepted: %q", got)
		}
	}
}

func TestHTMLQuotedAttrEditsDeclineResidualIdentity(t *testing.T) {
	const source = `<INPUT data-note='old'>`
	name, before := attrEditFixture(source)
	after := []tagAttr{{"data-note", "new"}}
	gate := scrub.NewGate(nil, []string{"<INPUT"}, "alias.local")
	if got, ok := rewriteHTMLQuotedAttrs([]byte(source), name, before, after, gate); ok {
		t.Fatalf("source envelope retained a configured identity: %q", got)
	}
}
