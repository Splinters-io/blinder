package rewriter

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"github.com/Splinters-io/blinder/internal/metadata"
	"github.com/Splinters-io/blinder/internal/scrub"
	"github.com/Splinters-io/blinder/internal/sri"
)

var sriDropAttrs = map[string]bool{
	"integrity":   true,
	"crossorigin": true,
}

const loremText = "Lorem ipsum dolor sit amet consectetur adipiscing elit"

var loremWords = strings.Fields(loremText)

type sriRewriter struct {
	pipeline        *sri.Pipeline
	upstreamBase    *url.URL
	effectiveBase   *url.URL
	baseReq         *http.Request
	registerVersion func(upstreamURL, bodyVersion string) string
	resourceURL     func(raw string, base *url.URL) (string, bool)
}

type sriAction int

const (
	sriNone    sriAction = iota
	sriStrip             // no pipeline, proxied: strip integrity + crossorigin
	sriReplace           // pipeline success: replace integrity, keep crossorigin
	sriKeep              // pipeline failure or unchanged bytes: keep both
	sriBlock             // verification failed: omit entire element to prevent execution
)

type sriDecision struct {
	action          sriAction
	replacementHash string
	integrityVal    string
	bodyVersion     string
	resolvedURL     string
}

func rewriteHTML(body []byte, gate *scrub.Gate, paranoid bool, origins *OriginMapper, sr *sriRewriter) []byte {
	z := html.NewTokenizer(bytes.NewReader(body))
	var out bytes.Buffer
	out.Grow(len(body))

	var rawTextTag string
	var suppressElement bool

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
			if suppressElement {
				continue
			}
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

			if tagName == "base" && sr != nil && sr.upstreamBase != nil {
				for _, a := range attrs {
					if a.key == "href" && a.val != "" {
						if baseHref, err := sr.upstreamBase.Parse(a.val); err == nil {
							sr.effectiveBase = baseHref
						}
						break
					}
				}
			}

			sriDec := decideSRIAction(tagName, attrs, sr, origins)
			if sriDec.action == sriBlock {
				if tagName == "script" {
					suppressElement = true
				}
				continue
			}

			out.WriteByte('<')
			out.WriteString(tagName)
			writeScrubbedAttrs(&out, tagName, attrs, gate, origins, sriDec, sr)

			if tt == html.SelfClosingTagToken {
				out.WriteString(" /")
			}
			out.WriteByte('>')

		case html.EndTagToken:
			tn, _ := z.TagName()
			tagName := string(tn)

			if tagName == rawTextTag {
				if tagName == "title" && !suppressElement {
					out.WriteString("[Blinder: title removed]")
				}
				rawTextTag = ""
			}

			if suppressElement {
				suppressElement = false
				continue
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

func decideSRIAction(tagName string, attrs []tagAttr, sr *sriRewriter, origins *OriginMapper) sriDecision {
	if tagName != "script" && tagName != "link" {
		return sriDecision{}
	}

	var resourceURL, integrityVal, crossoriginVal string
	for _, a := range attrs {
		if (tagName == "script" && a.key == "src") || (tagName == "link" && a.key == "href") {
			resourceURL = a.val
		}
		if a.key == "integrity" {
			integrityVal = a.val
		}
		if a.key == "crossorigin" {
			crossoriginVal = a.val
		}
	}

	if resourceURL == "" {
		return sriDecision{integrityVal: integrityVal}
	}
	if sr != nil && sr.resourceURL != nil {
		base := sr.upstreamBase
		if sr.effectiveBase != nil {
			base = sr.effectiveBase
		}
		if _, handled := sr.resourceURL(resourceURL, base); handled {
			return sriDecision{action: sriKeep, integrityVal: integrityVal}
		}
	}

	resolvedURL := resourceURL
	if sr != nil {
		base := sr.upstreamBase
		if sr.effectiveBase != nil {
			base = sr.effectiveBase
		}
		resolvedURL = resolveResourceURL(resourceURL, base)
	}

	if !isProxiedResource(resolvedURL, origins) {
		return sriDecision{integrityVal: integrityVal}
	}

	if integrityVal != "" && sr != nil && sr.pipeline != nil {
		ct := guessContentTypeFromTag(tagName)
		pageOrigin := sr.upstreamBase
		result := sr.pipeline.Process(resolvedURL, integrityVal, ct, crossoriginVal, pageOrigin, sr.baseReq)
		if result != nil && result.VerificationFailed {
			return sriDecision{action: sriBlock, integrityVal: integrityVal}
		}
		if result != nil && result.UpstreamValid {
			if result.BytesModified {
				return sriDecision{action: sriReplace, replacementHash: result.ReplacementHash, integrityVal: integrityVal, bodyVersion: result.BodyVersion, resolvedURL: resolvedURL}
			}
			return sriDecision{action: sriKeep, integrityVal: integrityVal, bodyVersion: result.BodyVersion, resolvedURL: resolvedURL}
		}
		return sriDecision{action: sriKeep, integrityVal: integrityVal}
	}

	if integrityVal != "" {
		return sriDecision{action: sriStrip, integrityVal: integrityVal}
	}

	return sriDecision{}
}

func writeScrubbedAttrs(out *bytes.Buffer, tagName string, attrs []tagAttr, gate *scrub.Gate, origins *OriginMapper, sri sriDecision, sr *sriRewriter) {
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
		if tagName == "script" || tagName == "link" {
			if a.key == "integrity" {
				switch sri.action {
				case sriStrip:
					continue
				case sriReplace:
					out.WriteByte(' ')
					out.WriteString(`integrity="`)
					out.WriteString(html.EscapeString(sri.replacementHash))
					out.WriteByte('"')
					continue
				case sriKeep:
					out.WriteByte(' ')
					out.WriteString(`integrity="`)
					out.WriteString(html.EscapeString(sri.integrityVal))
					out.WriteByte('"')
					continue
				}
			}
			if a.key == "crossorigin" && sri.action == sriStrip {
				continue
			}
		}

		out.WriteByte(' ')
		out.WriteString(a.key)
		out.WriteString(`="`)
		var val string
		handled := false
		if sr != nil && sr.resourceURL != nil && isURLAttr(tagName, a.key) {
			base := sr.upstreamBase
			if sr.effectiveBase != nil {
				base = sr.effectiveBase
			}
			val, handled = sr.resourceURL(a.val, base)
		}
		if !handled {
			val = scrubAttrValue(tagName, a.key, a.val, relVal, gate, origins)
		}
		if sri.bodyVersion != "" && sr != nil && sr.registerVersion != nil &&
			((tagName == "script" && a.key == "src") || (tagName == "link" && a.key == "href")) {
			regURL := sri.resolvedURL
			if idx := strings.IndexByte(regURL, '#'); idx >= 0 {
				regURL = regURL[:idx]
			}
			token := sr.registerVersion(regURL, sri.bodyVersion)
			base := val
			frag := ""
			if idx := strings.IndexByte(val, '#'); idx >= 0 {
				base = val[:idx]
				frag = val[idx:]
			}
			if strings.Contains(base, "?") {
				val = base + "&__blv=" + token + frag
			} else {
				val = base + "?__blv=" + token + frag
			}
		}
		out.WriteString(html.EscapeString(val))
		out.WriteByte('"')
	}
}

func isProxiedResource(rawURL string, origins *OriginMapper) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	if parsed.Host == "" {
		return true
	}
	if origins == nil {
		return true
	}
	if parsed.Scheme != "" {
		return origins.IsKnownFullOrigin(parsed)
	}
	return origins.IsKnownOrigin(parsed.Host)
}

func resolveResourceURL(rawURL string, base *url.URL) string {
	if base == nil {
		return rawURL
	}
	resolved, err := base.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return resolved.String()
}

func guessContentTypeFromTag(tagName string) string {
	if tagName == "script" {
		return "application/javascript"
	}
	return "text/css"
}

func scrubAttrValue(tagName, attrName, attrVal, relVal string, gate *scrub.Gate, origins *OriginMapper) string {
	if tagName == "img" && attrName == "src" {
		return transparentGifDataURI
	}
	if tagName == "img" && attrName == "alt" {
		return "[image]"
	}

	if origins != nil && isURLAttr(tagName, attrName) {
		rewritten := origins.RewriteUpstreamURL(attrVal)
		if rewritten != attrVal {
			return gate.Scrub(rewritten, "html:"+attrName)
		}
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

func isURLAttr(tagName, attrName string) bool {
	switch attrName {
	case "href", "src", "action", "formaction", "poster", "cite":
		return true
	}
	return false
}

func extractHTMLMetadata(body []byte) *metadata.Result {
	z := html.NewTokenizer(bytes.NewReader(body))
	r := &metadata.Result{Format: "html"}

	var inTitle bool
	var titleBuf bytes.Buffer
	depth := 0

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}

		switch tt {
		case html.StartTagToken:
			tn, hasAttr := z.TagName()
			tagName := string(tn)
			depth++

			if tagName == "title" {
				inTitle = true
				titleBuf.Reset()
			}

			if tagName == "body" {
				goto done
			}

			if tagName == "meta" && hasAttr {
				attrs := collectTagAttrs(z)
				var name, property, content string
				for _, a := range attrs {
					switch a.key {
					case "name":
						name = strings.ToLower(a.val)
					case "property":
						property = strings.ToLower(a.val)
					case "content":
						content = a.val
					}
				}
				if content != "" {
					switch {
					case name == "author" || property == "article:author":
						r.Identity.Author = content
					case name == "generator":
						r.Producer = content
					}
				}
			}

		case html.TextToken:
			if inTitle {
				titleBuf.Write(z.Text())
			}

		case html.EndTagToken:
			tn, _ := z.TagName()
			if string(tn) == "title" && inTitle {
				r.Identity.Title = strings.TrimSpace(titleBuf.String())
				inTitle = false
			}
			depth--
		}
	}

done:
	if r.Identity.Title == "" && r.Identity.Author == "" && r.Producer == "" {
		return nil
	}
	return r
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
