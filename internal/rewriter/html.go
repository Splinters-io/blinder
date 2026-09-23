package rewriter

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"

	"github.com/Splinters-io/blinder/internal/scrub"
)

const loremText = "Lorem ipsum dolor sit amet consectetur adipiscing elit"

var loremWords = strings.Fields(loremText)

func rewriteHTML(body []byte, gate *scrub.Gate, paranoid bool) []byte {
	z := html.NewTokenizer(bytes.NewReader(body))
	var out bytes.Buffer
	out.Grow(len(body))

	var rawTextTag string

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}

		switch tt {
		case html.CommentToken:

		case html.DoctypeToken:
			out.Write(append([]byte(nil), z.Raw()...))

		case html.TextToken:
			text := string(append([]byte(nil), z.Text()...))
			switch rawTextTag {
			case "script":
				out.Write(rewriteJS([]byte(text), gate, "html:script"))
			case "style":
				out.Write(rewriteCSS([]byte(text), gate, "html:style"))
			case "title":
				// Discarded; replacement emitted in the EndTagToken handler.
			default:
				if paranoid {
					trimmed := strings.TrimSpace(text)
					if len(trimmed) > 0 {
						out.WriteString(loremForLength(len(trimmed)))
					} else {
						out.WriteString(text)
					}
				} else {
					out.WriteString(html.EscapeString(gate.Scrub(text, "html:body")))
				}
			}

		case html.StartTagToken, html.SelfClosingTagToken:
			tn, hasAttr := z.TagName()
			tagName := string(tn)

			if tagName == "script" || tagName == "style" || tagName == "title" {
				rawTextTag = tagName
			}

			var attrs []tagAttr
			if hasAttr {
				attrs = collectTagAttrs(z)
			}

			out.WriteByte('<')
			out.WriteString(tagName)
			writeScrubbedAttrs(&out, tagName, attrs, gate)

			if tt == html.SelfClosingTagToken {
				out.WriteString(" /")
			}
			out.WriteByte('>')

		case html.EndTagToken:
			tn, _ := z.TagName()
			tagName := string(tn)

			if tagName == rawTextTag {
				if tagName == "title" {
					out.WriteString("[Blinder: title removed]")
				}
				rawTextTag = ""
			}

			out.WriteString("</")
			out.WriteString(tagName)
			out.WriteByte('>')
		}
	}

	return out.Bytes()
}

type tagAttr struct {
	key string
	val string
}

func collectTagAttrs(z *html.Tokenizer) []tagAttr {
	var attrs []tagAttr
	for {
		key, val, more := z.TagAttr()
		attrs = append(attrs, tagAttr{key: string(key), val: string(val)})
		if !more {
			break
		}
	}
	return attrs
}

func writeScrubbedAttrs(out *bytes.Buffer, tagName string, attrs []tagAttr, gate *scrub.Gate) {
	relVal := ""
	if tagName == "link" {
		for _, a := range attrs {
			if a.key == "rel" {
				relVal = a.val
				break
			}
		}
	}

	for _, a := range attrs {
		out.WriteByte(' ')
		out.WriteString(a.key)
		out.WriteString(`="`)
		out.WriteString(html.EscapeString(scrubAttrValue(tagName, a.key, a.val, relVal, gate)))
		out.WriteByte('"')
	}
}

func scrubAttrValue(tagName, attrName, attrVal, relVal string, gate *scrub.Gate) string {
	if tagName == "img" && attrName == "src" {
		return transparentGifDataURI
	}
	if tagName == "img" && attrName == "alt" {
		return "[image]"
	}

	ctx := "html:body"
	switch {
	case tagName == "base" && attrName == "href":
		ctx = "html:base"
	case tagName == "link" && attrName == "href" && strings.EqualFold(relVal, "canonical"):
		ctx = "html:canonical"
	case tagName == "meta" && attrName == "content":
		ctx = "html:meta"
	case strings.HasPrefix(attrName, "data-"):
		ctx = "html:data-attr"
	}

	return gate.Scrub(attrVal, ctx)
}

func loremForLength(n int) string {
	if n <= 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(n)
	wordIdx := 0
	for b.Len() < n {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(loremWords[wordIdx%len(loremWords)])
		wordIdx++
	}
	result := b.String()
	if len(result) > n {
		result = result[:n]
	}
	return result
}
