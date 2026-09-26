package rewriter

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"github.com/Splinters-io/blinder/internal/metadata"
	"github.com/Splinters-io/blinder/internal/scrub"
	"github.com/Splinters-io/blinder/internal/sri"
)

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

func rewriteHTML(body []byte, gate *scrub.Gate, paranoid, preserveTitle bool, origins *OriginMapper, sr *sriRewriter) []byte {
	z := html.NewTokenizer(bytes.NewReader(body))
	var out bytes.Buffer
	out.Grow(len(body))

	var rawTextTag string
	var suppressElement bool
	var diagnosticElements []diagnosticElement
	var proseSpans []proseSpan

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			// On EOF the tokenizer may expose a final incomplete tag that it
			// could not emit as a normal token. Keep harmless source truncation
			// observable without guessing how to rewrite its broken grammar.
			// Next advances Raw's start, so an ordinary EOF has an empty span;
			// already emitted text is not repeated. Never revive an SRI block.
			if z.Err() == io.EOF && !suppressElement {
				raw := append([]byte(nil), z.Raw()...)
				decoded := html.UnescapeString(string(raw))
				if gate.Scrub(decoded, "html:truncated") == decoded && gate.ResidualLeakCount(decoded) == 0 {
					out.Write(raw)
				}
			}
			break
		}
		// Token decoding lowercases tag names, unescapes attributes/text and
		// normalizes newlines in the tokenizer's backing buffer. Keep source
		// bytes before any of those operations for unchanged-token passthrough.
		raw := append([]byte(nil), z.Raw()...)

		switch tt {
		case html.CommentToken:
			if !suppressElement {
				out.Write(rewriteHTMLComment(raw, gate))
			}

		case html.DoctypeToken:
			out.Write(raw)

		case html.TextToken:
			if suppressElement {
				continue
			}
			switch rawTextTag {
			case "script":
				out.Write(rewriteJS(raw, gate, "html:script", origins))
			case "style":
				out.Write(rewriteCSS(raw, gate, "html:style", origins))
			case "title":
				// An error response may carry its only diagnostic in the title.
				// Apply identity masking there just as in the rest of its body.
				if !preserveTitle {
					// Ordinary page titles are replaced at their end tag.
					break
				}
				fallthrough
			default:
				text := string(z.Text())
				if paranoid && !inDiagnosticElement(diagnosticElements) {
					if strings.TrimSpace(text) != "" {
						left, right := proseContentBounds(string(raw))
						proseSpans = append(proseSpans, proseSpan{out.Len() + left, out.Len() + right})
						out.WriteString(proseForHTMLText(string(raw)))
					} else {
						out.Write(raw)
					}
				} else {
					transformed := gate.Scrub(text, "html:body")
					if transformed == text {
						out.Write(raw)
					} else {
						out.WriteString(html.EscapeString(transformed))
					}
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
			diagnosticElements = enterDiagnosticElement(diagnosticElements, tagName, attrs, tt == html.SelfClosingTagToken)

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

			transformedAttrs, changed := rewriteTagAttrs(tagName, attrs, gate, origins, sriDec, sr)
			if !changed && gate.ResidualLeakCount(html.UnescapeString(string(raw))) == 0 {
				out.Write(raw)
				continue
			}
			out.WriteByte('<')
			out.WriteString(tagName)
			writeTagAttrs(&out, transformedAttrs)

			if tt == html.SelfClosingTagToken {
				out.WriteString(" /")
			}
			out.WriteByte('>')

		case html.EndTagToken:
			tn, _ := z.TagName()
			tagName := string(tn)
			for i := len(diagnosticElements) - 1; i >= 0; i-- {
				if diagnosticElements[i].tag == tagName {
					diagnosticElements = diagnosticElements[:i]
					break
				}
			}

			if tagName == rawTextTag {
				if tagName == "title" && !suppressElement && !preserveTitle {
					out.WriteString("Transformed view")
				}
				rawTextTag = ""
			}

			if suppressElement {
				suppressElement = false
				continue
			}

			// Closing-tag attributes are ignored by browsers and were dropped
			// by the previous serializer. Do not newly expose their identities
			// when retaining unusual but otherwise unchanged closing-tag syntax.
			decoded := html.UnescapeString(string(raw))
			if gate.Scrub(decoded, "html:end-tag") == decoded {
				out.Write(raw)
			} else if closing := "</" + tagName + ">"; gate.ResidualLeakCount(closing) == 0 {
				out.WriteString(closing)
			}
		}
	}

	return fitProseToBodyLength(out.Bytes(), proseSpans, len(body))
}

// Comments carry diagnostic and parser-relevant source. Ordinary comments have
// an envelope we can preserve while scrubbing an entity-decoded interior. A
// changed interior is escaped so it cannot introduce markup or a closing '-->'.
// Bogus/unterminated comment syntax is preserved only when no replacement is
// needed; otherwise retain the previous omission policy instead of guessing a
// new syntactic envelope. A residual check also covers configured identities
// spanning the interior/envelope boundary without rescanning generated aliases.
func rewriteHTMLComment(raw []byte, gate *scrub.Gate) []byte {
	const prefix, suffix = "<!--", "-->"
	source := string(raw)
	if strings.HasPrefix(source, prefix) && strings.HasSuffix(source, suffix) && len(source) >= len(prefix)+len(suffix) {
		interior := source[len(prefix) : len(source)-len(suffix)]
		decoded := html.UnescapeString(interior)
		transformed := gate.Scrub(decoded, "html:comment")
		candidate := source
		if transformed != decoded {
			candidate = prefix + html.EscapeString(transformed) + suffix
		}
		if gate.ResidualLeakCount(html.UnescapeString(candidate)) != 0 {
			return nil
		}
		return []byte(candidate)
	}
	decoded := html.UnescapeString(source)
	if transformed := gate.Scrub(decoded, "html:comment"); transformed != decoded || gate.ResidualLeakCount(decoded) != 0 {
		return nil
	}
	return raw
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

// Compute changes once: scrubbing records findings and version registration has
// side effects, so a separate speculative pass would duplicate both.
func rewriteTagAttrs(tagName string, attrs []tagAttr, gate *scrub.Gate, origins *OriginMapper, sri sriDecision, sr *sriRewriter) ([]tagAttr, bool) {
	result := make([]tagAttr, 0, len(attrs))
	changed := false
	appendAttr := func(original tagAttr, value string) {
		result = append(result, tagAttr{key: original.key, val: value})
		changed = changed || original.val != value
	}
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
					changed = true
					continue
				case sriReplace:
					appendAttr(a, sri.replacementHash)
					continue
				case sriKeep:
					appendAttr(a, sri.integrityVal)
					continue
				}
			}
			if a.key == "crossorigin" && sri.action == sriStrip {
				changed = true
				continue
			}
		}

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
		appendAttr(a, val)
	}
	return result, changed
}

func writeTagAttrs(out *bytes.Buffer, attrs []tagAttr) {
	for _, a := range attrs {
		out.WriteByte(' ')
		out.WriteString(a.key)
		out.WriteString(`="`)
		out.WriteString(html.EscapeString(a.val))
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

	if attrName == "style" {
		return string(rewriteCSS([]byte(attrVal), gate, "html:style-attr", origins))
	}
	if origins != nil && isURLAttr(tagName, attrName) {
		return scrubResourceURL(attrVal, gate, "html:"+attrName, origins)
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
