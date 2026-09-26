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
	outputIdentities map[string]string
	cspPolicies      []string
	pipeline         *sri.Pipeline
	upstreamBase     *url.URL
	effectiveBase    *url.URL
	baseReq          *http.Request
	registerVersion  func(upstreamURL, bodyVersion string) string
	resourceURL      func(raw string, base *url.URL) (string, bool)
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
	effectiveBase                   *url.URL
	action                          sriAction
	replacementHash                 string
	integrityVal                    string
	bodyVersion                     string
	resolvedURL                     string
	integrityChanges                []sri.IntegrityChange
	originalSHA256, rewrittenSHA256 string
}

func rewriteHTML(body []byte, gate *scrub.Gate, paranoid, preserveTitle bool, origins *OriginMapper, sr *sriRewriter, policyHashes ...*CSPHashes) []byte {
	hashes := &CSPHashes{}
	if len(policyHashes) > 0 && policyHashes[0] != nil {
		hashes = policyHashes[0]
	}
	decisions := prepareSRIDecisions(body, sr, origins, hashes)
	z := html.NewTokenizer(bytes.NewReader(body))
	var sourceOffset int
	var out bytes.Buffer
	out.Grow(len(body))

	var rawTextTag string
	var externalScript bool
	var suppressElement bool
	var diagnosticElements []diagnosticElement
	var proseSpans []proseSpan
	var policies []cspMetaSpan

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
		tokenOffset := sourceOffset
		sourceOffset += len(raw)

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
				rewritten := rewriteJS(raw, gate, "html:script", origins)
				if !externalScript {
					rewritten = append(rewritten, hashes.record("script", out.Len(), cspRawText(raw), cspRawText(rewritten))...)
				}
				out.Write(rewritten)
			case "style":
				rewritten := rewriteCSS(raw, gate, "html:style", origins)
				rewritten = append(rewritten, hashes.record("style", out.Len(), cspRawText(raw), cspRawText(rewritten))...)
				out.Write(rewritten)
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
			if tagName == "script" {
				externalScript = false
				for _, a := range attrs {
					if a.key == "src" {
						externalScript = true
						break
					}
				}
			}
			diagnosticElements = enterDiagnosticElement(diagnosticElements, tagName, attrs, tt == html.SelfClosingTagToken)

			sriDec, prepared := decisions[tokenOffset]
			if prepared && sr != nil {
				sr.effectiveBase = sriDec.effectiveBase
			}
			if !prepared {
				sriDec = decideSRIAction(tagName, attrs, sr, origins)
			}
			if tagName == "script" {
				if sriDec.action != sriReplace && sriDec.action != sriBlock {
					for _, entry := range sri.ParseIntegrity(sriDec.integrityVal) {
						token := entry.Algorithm + "-" + entry.DigestValue
						sriDec.integrityChanges = append(sriDec.integrityChanges, sri.IntegrityChange{Original: token, Replacement: token})
					}
				}
				hashes.recordIntegrity(out.Len(), sriDec.integrityChanges)
			}
			if sriDec.action == sriBlock {
				if tagName == "script" {
					suppressElement = true
				}
				continue
			}

			transformedAttrs, changed := rewriteTagAttrs(tagName, attrs, gate, origins, sriDec, sr)
			seenAttrs := make(map[string]bool)
			for _, a := range attrs {
				if seenAttrs[a.key] {
					continue
				}
				seenAttrs[a.key] = true
				kind := ""
				if a.key == "style" {
					kind = "style-attr"
				} else if strings.HasPrefix(a.key, "on") {
					kind = "script-attr"
				}
				if kind != "" {
					for i, transformed := range transformedAttrs {
						if transformed.key == a.key {
							suffix := hashes.record(kind, out.Len(), cspUTF8([]byte(a.val)), cspUTF8([]byte(transformed.val)))
							if len(suffix) > 0 {
								transformedAttrs[i].val += string(suffix)
								changed = true
							}
							break
						}
					}
				}
			}
			// Meta policies are left at their original document position. Delay
			// serialising their final hashes until subsequent source is known.
			if isCSPMeta(tagName, attrs) {
				start := out.Len()
				writeHTMLStartTag(&out, tagName, transformedAttrs, tt == html.SelfClosingTagToken)
				policies = append(policies, cspMetaSpan{start: start, end: out.Len(), attrs: transformedAttrs, selfClosing: tt == html.SelfClosingTagToken})
				continue
			}
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

	rewritten, proseSpans := rewriteCSPMetaSpans(out.Bytes(), proseSpans, policies, hashes)
	return fitProseToBodyLength(rewritten, proseSpans, len(body))
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

// Prepare external resources before rewriting inline text, reserving their
// output hash identities. This lets an inline source that converges onto an
// external resource's bytes receive the same harmless collision suffix as two
// inline sources. Decisions and fetches are made exactly once, in source order.
func prepareSRIDecisions(body []byte, sr *sriRewriter, origins *OriginMapper, hashes *CSPHashes) map[int]sriDecision {
	hashes.reserveOriginalHTML(body)
	if sr == nil {
		return nil
	}
	state := *sr
	state.cspPolicies = append([]string(nil), sr.cspPolicies...)
	if hashes.outputs == nil {
		hashes.outputs = make(map[string]string)
	}
	state.outputIdentities = hashes.outputs
	decisions := make(map[int]sriDecision)
	z := html.NewTokenizer(bytes.NewReader(body))
	offset := 0
	var document cspDocumentState
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		position := offset
		offset += len(z.Raw())
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken && tt != html.EndTagToken {
			document.observe(tt, "", z.Raw())
			continue
		}
		name, hasAttrs := z.TagName()
		tag := string(name)
		inHead := document.observe(tt, tag, nil)
		if tt == html.EndTagToken {
			continue
		}
		var attrs []tagAttr
		if hasAttrs {
			attrs = collectTagAttrs(z)
		}
		if document.templateDepth == 0 {
			if tag == "base" && !document.baseSeen && state.upstreamBase != nil {
				for _, a := range attrs {
					if a.key == "href" {
						// Even an empty, invalid or policy-blocked first href
						// consumes the document's base element choice.
						document.baseSeen = true
						value := strings.TrimFunc(a.val, cspASCIIWhitespace)
						if base, err := state.upstreamBase.Parse(value); err == nil && base.Scheme != "data" && base.Scheme != "javascript" && cspAllowsBase(state.cspPolicies, base, state.upstreamBase) {
							state.effectiveBase = base
						}
						break
					}
				}
			}
			if inHead && isCSPMeta(tag, attrs) {
				for _, a := range attrs {
					if a.key == "content" {
						state.cspPolicies = append(state.cspPolicies, a.val)
						break
					}
				}
			}
		}
		var decision sriDecision
		if document.templateDepth > 0 {
			decision.action = sriKeep
			for _, a := range attrs {
				if a.key == "integrity" {
					decision.integrityVal = a.val
					break
				}
			}
		} else {
			decision = decideSRIAction(tag, attrs, &state, origins)
		}
		decision.effectiveBase = state.effectiveBase
		if tag == "base" {
			// The base element's own relative href resolves against the
			// fallback document URL, not against the base it just installed.
			decision.effectiveBase = nil
		}
		decisions[position] = decision
		if decision.originalSHA256 != "" {
			hashes.outputs[decision.rewrittenSHA256] = decision.originalSHA256
		}
	}
	return decisions
}

func decideSRIAction(tagName string, attrs []tagAttr, sr *sriRewriter, origins *OriginMapper) sriDecision {
	if tagName != "script" && tagName != "link" {
		return sriDecision{}
	}

	var resourceURL, integrityVal, crossoriginVal, nonceVal, typeVal, relVal string
	noModule := false
	seen := make(map[string]bool)
	for _, a := range attrs {
		if seen[a.key] {
			continue
		}
		seen[a.key] = true
		if a.key == "nomodule" { noModule = true }
		if a.key == "nonce" {
			nonceVal = a.val
		}
		if a.key == "type" {
			typeVal = a.val
		}
		if a.key == "rel" {
			relVal = a.val
		}
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

	// Do not invent speculative fetches for inert script data blocks or
	// links whose destination is not supported by this SRI pipeline.
	if tagName == "script" && (!sriScriptType(typeVal) || noModule && !strings.EqualFold(strings.TrimFunc(typeVal, cspASCIIWhitespace), "module")) || tagName == "link" && !sriHasRel(relVal, "stylesheet") {
		return sriDecision{action: sriKeep, integrityVal: integrityVal}
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
		// CSP nonceability rejects dangling-markup shapes even when an
		// attribute happens to contain a policy's nonce string.
		for _, a := range attrs {
			lower := strings.ToLower(a.key + " " + a.val)
			if strings.Contains(lower, "<script") || strings.Contains(lower, "<style") {
				nonceVal = ""
				break
			}
		}
		resource, err := url.Parse(resolvedURL)
		if err != nil || !CSPAllowsExternal(sr.cspPolicies, resource, sr.upstreamBase, tagName, nonceVal, integrityVal) {
			// Retain the element so the browser produces the original CSP
			// violation/error. Do not turn a policy denial into an upstream GET.
			return sriDecision{action: sriKeep, integrityVal: integrityVal}
		}
		ct := guessContentTypeFromTag(tagName)
		pageOrigin := sr.upstreamBase
		result := sr.pipeline.Process(resolvedURL, integrityVal, ct, crossoriginVal, pageOrigin, sr.baseReq, sr.outputIdentities)
		if result != nil && result.VerificationFailed {
			return sriDecision{action: sriBlock, integrityVal: integrityVal}
		}
		if result != nil && result.UpstreamValid {
			if result.BytesModified {
				return sriDecision{action: sriReplace, replacementHash: result.ReplacementHash, integrityChanges: result.IntegrityChanges, originalSHA256: result.OriginalSHA256, rewrittenSHA256: result.RewrittenSHA256, integrityVal: integrityVal, bodyVersion: result.BodyVersion, resolvedURL: resolvedURL}
			}
			return sriDecision{action: sriKeep, integrityVal: integrityVal, bodyVersion: result.BodyVersion, resolvedURL: resolvedURL, integrityChanges: result.IntegrityChanges, originalSHA256: result.OriginalSHA256, rewrittenSHA256: result.RewrittenSHA256}
		}
		return sriDecision{action: sriKeep, integrityVal: integrityVal}
	}

	if integrityVal != "" {
		return sriDecision{action: sriStrip, integrityVal: integrityVal}
	}

	return sriDecision{}
}

func sriHasRel(value, wanted string) bool {
	for _, token := range strings.FieldsFunc(value, cspASCIIWhitespace) {
		if strings.EqualFold(token, wanted) {
			return true
		}
	}
	return false
}

func sriScriptType(value string) bool {
	value = strings.ToLower(strings.TrimFunc(value, cspASCIIWhitespace))
	switch value {
	case "", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript",
		"application/x-javascript", "application/x-ecmascript", "text/javascript1.0", "text/javascript1.1",
		"text/javascript1.2", "text/javascript1.3", "text/javascript1.4", "text/javascript1.5", "text/jscript", "text/livescript", "text/x-javascript", "text/x-ecmascript":
		return true
	}
	return false
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
		if a.key == "http-equiv" && isCSPMeta(tagName, attrs) {
			appendAttr(a, a.val)
			continue
		}
		if tagName == "iframe" && a.key == "sandbox" {
			tokens := strings.FieldsFunc(a.val, cspASCIIWhitespace)
			changedFlag := false
			for i, token := range tokens {
				if !cspControlKeyword("sandbox", strings.ToLower(token)) {
					tokens[i] = gate.Scrub(token, "html:sandbox")
					changedFlag = changedFlag || tokens[i] != token
				}
			}
			value := a.val
			if changedFlag {
				value = strings.Join(tokens, " ")
			}
			appendAttr(a, value)
			continue
		}
		if a.key == "nonce" {
			appendAttr(a, RewriteCSPNonce(a.val, gate))
			continue
		}
		if a.key == "content" && isCSPMeta(tagName, attrs) {
			appendAttr(a, rewriteCSP(a.val, gate, "", origins))
			continue
		}
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
	if strings.HasPrefix(attrName, "on") {
		return string(rewriteJS([]byte(attrVal), gate, "html:event-handler", origins))
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
