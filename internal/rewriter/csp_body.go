package rewriter

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/Splinters-io/blinder/internal/sri"
	"golang.org/x/net/html"
)

// CSPHashes records the relationship between source text before and after this
// representation's rewrite. A policy hash is translated only when it authorised
// the original text. This is deliberately not a list of all output hashes to
// add to a policy: that would authorise originally blocked code.
type CSPHashes struct {
	changes []cspHashChange
	outputs map[string]string
}

type cspHashChange struct {
	kind                string
	position            int
	original, rewritten [3]string
}

func cspDigests(source []byte) [3]string {
	sha256sum := sha256.Sum256(source)
	sha384sum := sha512.Sum384(source)
	sha512sum := sha512.Sum512(source)
	return [3]string{base64.StdEncoding.EncodeToString(sha256sum[:]), base64.StdEncoding.EncodeToString(sha384sum[:]), base64.StdEncoding.EncodeToString(sha512sum[:])}
}

// HTML's input stream normalises CR/CRLF and replaces NUL in raw text before
// CSP hashes the element's UTF-8 text content. Character references in script
// and style raw text are not decoded.
func cspRawText(source []byte) []byte {
	source = cspUTF8(source)
	source = bytes.ReplaceAll(source, []byte("\r\n"), []byte("\n"))
	source = bytes.ReplaceAll(source, []byte("\r"), []byte("\n"))
	return bytes.ReplaceAll(source, []byte{0}, []byte("\ufffd"))
}

func (c *CSPHashes) record(kind string, position int, original, rewritten []byte) []byte {
	if c == nil {
		return nil
	}
	before, after := cspDigests(original), cspDigests(rewritten)
	if c.outputs == nil {
		c.outputs = make(map[string]string)
	}
	var suffix, rawSuffix []byte
	for c.outputConflict(before, after) {
		// Routing can collapse distinct source strings to identical output.
		// Keep their CSP identities distinct using trailing whitespace, which
		// does not change JS/CSS execution. Only collisions cost bytes.
		if rawSuffix == nil {
			rawSuffix = []byte{'\n'}
			digest := sha256.Sum256(original)
			for _, b := range digest {
				for bit := 7; bit >= 0; bit-- {
					if b&(1<<bit) == 0 {
						rawSuffix = append(rawSuffix, ' ')
					} else {
						rawSuffix = append(rawSuffix, '\t')
					}
				}
			}
		} else {
			rawSuffix = append(rawSuffix, ' ')
		}
		suffix = rawSuffix
		if kind == "script-navigation" {
			// Literal trailing whitespace is stripped by URL parsing. Encode
			// it so navigation keeps both the code and its CSP identity.
			suffix = []byte(strings.TrimPrefix(encodeJavaScriptURL(string(suffix)), "javascript:"))
		}
		candidate := append(append([]byte(nil), rewritten...), rawSuffix...)
		after = cspDigests(candidate)
	}
	c.reserveDigests(before, after)
	c.changes = append(c.changes, cspHashChange{kind: kind, position: position, original: before, rewritten: after})
	return suffix
}

var cspAlgorithms = [3]string{"sha256", "sha384", "sha512"}

func (c *CSPHashes) outputConflict(before, after [3]string) bool {
	if previous, ok := c.outputs[after[0]]; ok && previous != before[0] {
		return true
	}
	for i, algorithm := range cspAlgorithms {
		if previous, ok := c.outputs[algorithm+"-"+after[i]]; ok && previous != before[i] {
			return true
		}
	}
	return false
}

func (c *CSPHashes) reserveDigests(before, after [3]string) {
	if c.outputs == nil {
		c.outputs = make(map[string]string)
	}
	c.outputs[after[0]] = before[0]
	for i, algorithm := range cspAlgorithms {
		c.outputs[algorithm+"-"+after[i]] = before[i]
	}
}

// Reserve unchanged identities before considering any transformed output.
// Denied and unprocessed external references still carry their original SRI:
// rewriting another permitted source onto that digest must not authorise them.
// All algorithms matter, including weaker integrity entries which SRI itself
// does not use for body verification but CSP requires for metadata membership.
func (c *CSPHashes) reserveOriginalHTML(body []byte) {
	if c.outputs == nil {
		c.outputs = make(map[string]string)
	}
	reserve := func(source []byte) { digests := cspDigests(source); c.reserveDigests(digests, digests) }
	z := html.NewTokenizer(bytes.NewReader(body))
	rawTag, external := "", false
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return
		}
		raw := append([]byte(nil), z.Raw()...)
		if tt == html.TextToken {
			if rawTag == "style" || rawTag == "script" && !external {
				reserve(cspRawText(raw))
			}
			continue
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken && tt != html.EndTagToken {
			continue
		}
		tn, hasAttrs := z.TagName()
		tag := string(tn)
		if tt == html.EndTagToken {
			if tag == rawTag {
				rawTag = ""
			}
			continue
		}
		var attrs []tagAttr
		if hasAttrs {
			attrs = collectTagAttrs(z)
		}
		if tag == "script" || tag == "style" {
			rawTag = tag
		}
		if tag == "script" {
			external = false
			for _, a := range attrs {
				if a.key == "src" {
					external = true
					break
				}
			}
		}
		seen := make(map[string]bool)
		for _, a := range attrs {
			if seen[a.key] {
				continue
			}
			seen[a.key] = true
			if a.key == "style" || strings.HasPrefix(a.key, "on") {
				reserve(cspUTF8([]byte(a.val)))
			}
			if isURLAttr(tag, a.key) {
				if source := javascriptCSPSource(a.val); source != nil {
					reserve(source)
				}
			}
			if tag == "script" && external && a.key == "integrity" {
				for _, entry := range sri.ParseIntegrity(a.val) {
					digest := base64.StdEncoding.EncodeToString(entry.Digest)
					c.outputs[entry.Algorithm+"-"+digest] = digest
					if entry.Algorithm == "sha256" {
						c.outputs[digest] = digest
					}
				}
			}
		}
	}
}

// External script CSP compares integrity metadata, rather than hashing an
// inline text node. Retain each entry (including weaker/invalid entries): CSP
// requires all supported entries even though SRI verifies only the strongest.
func (c *CSPHashes) recordIntegrity(position int, changes []sri.IntegrityChange) {
	for _, change := range changes {
		before, after := sri.ParseIntegrity(change.Original), sri.ParseIntegrity(change.Replacement)
		if len(before) != 1 || len(after) != 1 || before[0].Algorithm != after[0].Algorithm {
			continue
		}
		index := map[string]int{"sha256": 0, "sha384": 1, "sha512": 2}[before[0].Algorithm]
		item := cspHashChange{kind: "script", position: position}
		item.original[index] = base64.StdEncoding.EncodeToString(before[0].Digest)
		item.rewritten[index] = base64.StdEncoding.EncodeToString(after[0].Digest)
		c.changes = append(c.changes, item)
	}
}

func cspHashKind(directive, kind string) bool {
	switch directive {
	case "default-src":
		return true
	case "script-src":
		return strings.HasPrefix(kind, "script")
	case "style-src":
		return strings.HasPrefix(kind, "style")
	case "script-src-elem":
		return kind == "script" || kind == "script-navigation"
	case "style-src-elem":
		return kind == "style"
	case "script-src-attr":
		return kind == "script-attr"
	case "style-src-attr":
		return kind == "style-attr"
	}
	return false
}

func (c *CSPHashes) rewriteHash(token, directive string, after int) []string {
	if !cspNonceHashRe.MatchString(token) {
		return []string{token}
	}
	parts := strings.SplitN(token[1:len(token)-1], "-", 2)
	algorithm := strings.ToLower(parts[0])
	index := -1
	switch algorithm {
	case "sha256":
		index = 0
	case "sha384":
		index = 1
	case "sha512":
		index = 2
	}
	if index < 0 {
		return []string{token}
	}
	digest := strings.NewReplacer("-", "+", "_", "/").Replace(parts[1])
	// Accept omitted padding without repairing malformed extra padding. A
	// rejected original expression must not become a valid output permission.
	encoding := base64.StdEncoding
	if !strings.Contains(digest, "=") {
		encoding = base64.RawStdEncoding
	}
	decoded, err := encoding.DecodeString(digest)
	if err != nil {
		return []string{token}
	}
	digest = base64.StdEncoding.EncodeToString(decoded)
	var replacements []string
	seen := make(map[string]bool)
	collides := false
	for _, change := range c.changes {
		if (change.position < after && !strings.HasSuffix(change.kind, "-attr") && change.kind != "script-navigation") || !cspHashKind(directive, change.kind) {
			continue
		}
		if change.original[index] == digest {
			replacement := "'" + algorithm + "-" + change.rewritten[index] + "'"
			if !seen[replacement] {
				replacements = append(replacements, replacement)
				seen[replacement] = true
			}
		}
		if change.rewritten[index] == digest {
			collides = true
		}
	}
	if len(replacements) > 0 {
		return replacements
	}
	if collides {
		// Keep a syntactically valid hash-source, so unsafe-inline remains
		// disabled, but use an impossible digest length. No sentinel body can
		// satisfy a one-byte SHA-256/384/512 digest. Leaving the original here
		// would let masking turn an invalid upstream hash into a valid one.
		return []string{"'" + algorithm + "-AA=='"}
	}
	return []string{token}
}

func (c *CSPHashes) rewritePolicy(policy string, after int) string {
	if c == nil || len(c.changes) == 0 {
		return policy
	}
	policies := strings.Split(policy, ",")
	for i, policy := range policies {
		directives := strings.Split(policy, ";")
		for j, directive := range directives {
			if cspHasNonASCII(directive) {
				continue
			}
			fields := strings.FieldsFunc(directive, cspASCIIWhitespace)
			if len(fields) < 2 {
				continue
			}
			name := strings.ToLower(fields[0])
			if !cspHashKind(name, "script") && !cspHashKind(name, "style") && !cspHashKind(name, "script-attr") && !cspHashKind(name, "style-attr") {
				continue
			}
			result := fields[:1:1]
			for _, token := range fields[1:] {
				result = append(result, c.rewriteHash(token, name, after)...)
			}
			directives[j] = strings.Join(result, " ")
		}
		policies[i] = strings.Join(directives, ";")
	}
	return strings.Join(policies, ",")
}

// RewriteHeaders preserves separate enforcing and report-only policy fields.
// Call after URL/nonce translation, before caching or computing response sizes.
func (c *CSPHashes) RewriteHeaders(headers http.Header) {
	if c == nil {
		return
	}
	for name, values := range headers {
		if !strings.EqualFold(name, "Content-Security-Policy") && !strings.EqualFold(name, "Content-Security-Policy-Report-Only") {
			continue
		}
		for i, value := range values {
			values[i] = c.rewritePolicy(value, 0)
		}
	}
}

type cspMetaSpan struct {
	start, end  int
	attrs       []tagAttr
	selfClosing bool
}

func isCSPMeta(tag string, attrs []tagAttr) bool {
	if tag != "meta" {
		return false
	}
	for _, a := range attrs {
		if a.key == "http-equiv" {
			return strings.EqualFold(a.val, "content-security-policy")
		}
	}
	return false
}

func writeHTMLStartTag(out *bytes.Buffer, tag string, attrs []tagAttr, selfClosing bool) {
	out.WriteByte('<')
	out.WriteString(tag)
	writeTagAttrs(out, attrs)
	if selfClosing {
		out.WriteString(" /")
	}
	out.WriteByte('>')
}

func rewriteCSPMetaSpans(body []byte, prose []proseSpan, metas []cspMetaSpan, hashes *CSPHashes) ([]byte, []proseSpan) {
	if len(metas) == 0 {
		return body, prose
	}
	var out bytes.Buffer
	previous, delta := 0, 0
	proseIndex := 0
	for _, meta := range metas {
		for proseIndex < len(prose) && prose[proseIndex].start < meta.start {
			prose[proseIndex].start += delta
			prose[proseIndex].end += delta
			proseIndex++
		}
		out.Write(body[previous:meta.start])
		before := out.Len()
		for i, a := range meta.attrs {
			if a.key == "content" {
				meta.attrs[i].val = hashes.rewritePolicy(a.val, meta.end)
			}
		}
		writeHTMLStartTag(&out, "meta", meta.attrs, meta.selfClosing)
		delta += out.Len() - before - (meta.end - meta.start)
		previous = meta.end
	}
	out.Write(body[previous:])
	for ; proseIndex < len(prose); proseIndex++ {
		prose[proseIndex].start += delta
		prose[proseIndex].end += delta
	}
	return out.Bytes(), prose
}
