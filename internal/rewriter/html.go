package rewriter

import (
	"regexp"
	"strings"

	"github.com/Splinters-io/blinder/internal/scrub"
)

var (
	htmlCommentRe  = regexp.MustCompile(`<!--[\s\S]*?-->`)
	titleRe        = regexp.MustCompile(`(?i)(<title[^>]*>)([\s\S]*?)(</title>)`)
	metaContentRe  = regexp.MustCompile(`(?i)(<meta[^>]*content\s*=\s*")((?:[^"\\]|\\.)*)("[^>]*>)`)
	imgSrcRe       = regexp.MustCompile(`(?i)(<img[^>]*\bsrc\s*=\s*")((?:[^"\\]|\\.)*)("[^>]*)`)
	imgAltRe       = regexp.MustCompile(`(?i)(\balt\s*=\s*")([^"]*)(")`)
	dataAttrRe     = regexp.MustCompile(`(?i)(\bdata-[a-z0-9-]+\s*=\s*")([^"]*)(")`)

	baseHrefRe     = regexp.MustCompile(`(?i)(<base[^>]*\bhref\s*=\s*")((?:[^"\\]|\\.)*)("[^>]*>)`)
	linkCanonRe    = regexp.MustCompile(`(?i)(<link[^>]*\brel\s*=\s*"canonical"[^>]*\bhref\s*=\s*")((?:[^"\\]|\\.)*)("[^>]*>)`)
)

const loremText = "Lorem ipsum dolor sit amet consectetur adipiscing elit"

var loremWords = strings.Fields(loremText)

func rewriteHTML(body []byte, gate *scrub.Gate, paranoid bool) []byte {
	s := string(body)

	s = htmlCommentRe.ReplaceAllString(s, "")

	s = titleRe.ReplaceAllStringFunc(s, func(match string) string {
		parts := titleRe.FindStringSubmatch(match)
		if len(parts) < 4 {
			return match
		}
		return parts[1] + "[Blinder: title removed]" + parts[3]
	})

	s = baseHrefRe.ReplaceAllStringFunc(s, func(match string) string {
		parts := baseHrefRe.FindStringSubmatch(match)
		if len(parts) < 4 {
			return match
		}
		return parts[1] + gate.Scrub(parts[2], "html:base") + parts[3]
	})

	s = linkCanonRe.ReplaceAllStringFunc(s, func(match string) string {
		parts := linkCanonRe.FindStringSubmatch(match)
		if len(parts) < 4 {
			return match
		}
		return parts[1] + gate.Scrub(parts[2], "html:canonical") + parts[3]
	})

	s = metaContentRe.ReplaceAllStringFunc(s, func(match string) string {
		parts := metaContentRe.FindStringSubmatch(match)
		if len(parts) < 4 {
			return match
		}
		return parts[1] + gate.Scrub(parts[2], "html:meta") + parts[3]
	})

	s = imgSrcRe.ReplaceAllStringFunc(s, func(match string) string {
		parts := imgSrcRe.FindStringSubmatch(match)
		if len(parts) < 4 {
			return match
		}
		replaced := parts[1] + transparentGifDataURI + parts[3]
		replaced = imgAltRe.ReplaceAllStringFunc(replaced, func(altMatch string) string {
			altParts := imgAltRe.FindStringSubmatch(altMatch)
			if len(altParts) < 4 {
				return altMatch
			}
			return altParts[1] + "[image]" + altParts[3]
		})
		return replaced
	})

	s = dataAttrRe.ReplaceAllStringFunc(s, func(match string) string {
		parts := dataAttrRe.FindStringSubmatch(match)
		if len(parts) < 4 {
			return match
		}
		return parts[1] + gate.Scrub(parts[2], "html:data-attr") + parts[3]
	})

	if paranoid {
		s = replaceTextNodes(s, gate)
	}
	s = gate.Scrub(s, "html:body")

	return []byte(s)
}

func replaceTextNodes(html string, gate *scrub.Gate) string {
	var b strings.Builder
	b.Grow(len(html))

	inTag := false
	textStart := 0

	for i := 0; i < len(html); i++ {
		if html[i] == '<' {
			if !inTag && i > textStart {
				text := html[textStart:i]
				trimmed := strings.TrimSpace(text)
				if len(trimmed) > 0 {
					b.WriteString(loremForLength(len(trimmed)))
				} else {
					b.WriteString(text)
				}
			}
			inTag = true
			b.WriteByte('<')
		} else if html[i] == '>' && inTag {
			inTag = false
			b.WriteByte('>')
			textStart = i + 1
		} else if inTag {
			b.WriteByte(html[i])
		}
	}

	if textStart < len(html) && !inTag {
		text := html[textStart:]
		trimmed := strings.TrimSpace(text)
		if len(trimmed) > 0 {
			b.WriteString(loremForLength(len(trimmed)))
		} else {
			b.WriteString(text)
		}
	}

	return b.String()
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
