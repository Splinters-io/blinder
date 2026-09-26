package rewriter

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"

	"github.com/Splinters-io/blinder/internal/scrub"
)

// rewriteHTMLQuotedAttrs keeps the source spelling of a well-formed start tag
// when only existing quoted attribute values change. Ambiguous syntax or an
// attribute-list change returns false so the caller can use its serializer.
// It does not scrub again: before/after are the already computed transformation.
func rewriteHTMLQuotedAttrs(raw []byte, tagName string, before, after []tagAttr, gate *scrub.Gate) ([]byte, bool) {
	if len(before) != len(after) || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return nil, false
	}
	seen := make(map[string]bool, len(before))
	for i, attr := range before {
		if attr.key != after[i].key || seen[attr.key] {
			return nil, false
		}
		seen[attr.key] = true
	}
	tokenType, ok := htmlTagHasAttrs(raw, tagName, before)
	if !ok {
		return nil, false
	}
	type edit struct {
		start, end int
		value      string
	}
	var edits []edit
	i := 1 // '<'; the tokenizer check above rejects non-start tags.
	for i < len(raw) && !htmlAttrSpace(raw[i]) && raw[i] != '/' && raw[i] != '>' {
		i++
	}
	attributeIndex := 0
	for {
		beforeSpace := i
		for i < len(raw) && htmlAttrSpace(raw[i]) {
			i++
		}
		if i >= len(raw) {
			return nil, false
		}
		if raw[i] == '>' || raw[i] == '/' {
			if raw[i] == '/' {
				i++
			}
			if i != len(raw)-1 || raw[i] != '>' || attributeIndex != len(before) {
				return nil, false
			}
			break
		}
		// A missing separator is a parse error even if the tokenizer can
		// recover it. Preserve that case through the caller's existing path.
		if beforeSpace == i || attributeIndex >= len(before) {
			return nil, false
		}
		nameStart := i
		for i < len(raw) && !htmlAttrSpace(raw[i]) && raw[i] != '=' && raw[i] != '/' && raw[i] != '>' {
			if raw[i] == '\'' || raw[i] == '"' || raw[i] == '<' || raw[i] == '`' {
				return nil, false
			}
			i++
		}
		if !strings.EqualFold(string(raw[nameStart:i]), before[attributeIndex].key) {
			return nil, false
		}
		nameEnd := i
		for i < len(raw) && htmlAttrSpace(raw[i]) {
			i++
		}
		changed := before[attributeIndex].val != after[attributeIndex].val
		if i >= len(raw) {
			return nil, false
		}
		if raw[i] != '=' {
			if changed {
				return nil, false // Boolean attributes have no replaceable value.
			}
			i = nameEnd // Let the next iteration consume its own separator.
			attributeIndex++
			continue
		}
		i++
		for i < len(raw) && htmlAttrSpace(raw[i]) {
			i++
		}
		if i >= len(raw) {
			return nil, false
		}
		quote := raw[i]
		if quote == '\'' || quote == '"' {
			i++
			start := i
			for i < len(raw) && raw[i] != quote {
				i++
			}
			if i >= len(raw) {
				return nil, false
			}
			if changed {
				value, valid := htmlQuotedAttrValue(after[attributeIndex].val, quote)
				if !valid {
					return nil, false
				}
				edits = append(edits, edit{start, i, value})
			}
			i++
		} else {
			if changed {
				return nil, false
			}
			start := i
			for i < len(raw) && !htmlAttrSpace(raw[i]) && raw[i] != '>' {
				if strings.ContainsRune("\"'`=<", rune(raw[i])) {
					return nil, false
				}
				i++
			}
			if start == i {
				return nil, false
			}
		}
		attributeIndex++
	}
	if len(edits) == 0 {
		return nil, false
	}
	var out bytes.Buffer
	previous := 0
	for _, edit := range edits {
		out.Write(raw[previous:edit.start])
		out.WriteString(edit.value)
		previous = edit.end
	}
	out.Write(raw[previous:])
	candidate := out.Bytes()
	if resultingType, valid := htmlTagHasAttrs(candidate, tagName, after); !valid || resultingType != tokenType {
		return nil, false
	}
	if gate != nil && gate.ResidualLeakCount(html.UnescapeString(string(candidate))) != 0 {
		return nil, false
	}
	return candidate, true
}

func htmlTagHasAttrs(raw []byte, tagName string, attrs []tagAttr) (html.TokenType, bool) {
	z := html.NewTokenizer(bytes.NewReader(raw))
	tokenType := z.Next()
	if tokenType != html.StartTagToken && tokenType != html.SelfClosingTagToken || len(z.Raw()) != len(raw) {
		return tokenType, false
	}
	name, hasAttrs := z.TagName()
	if string(name) != tagName || hasAttrs != (len(attrs) > 0) {
		return tokenType, false
	}
	if hasAttrs {
		actual := collectTagAttrs(z)
		if len(actual) != len(attrs) {
			return tokenType, false
		}
		for i := range actual {
			if actual[i] != attrs[i] {
				return tokenType, false
			}
		}
	}
	return tokenType, true
}

func htmlAttrSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

func htmlQuotedAttrValue(value string, quote byte) (string, bool) {
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return "", false
	}
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '&':
			out.WriteString("&amp;")
		case '\r':
			out.WriteString("&#13;") // Literal CR would be normalized by the HTML parser.
		case quote:
			if quote == '\'' {
				out.WriteString("&#39;")
			} else {
				out.WriteString("&#34;")
			}
		default:
			out.WriteByte(value[i])
		}
	}
	return out.String(), true
}
