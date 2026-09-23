package rewriter

import (
	"regexp"

	"github.com/Splinters-io/blinder/internal/scrub"
)

var cssURLRe = regexp.MustCompile(`(?i)(url\s*\(\s*['"]?)((?:[^)'"\\]|\\.)*)(['"]?\s*\))`)

func rewriteCSS(body []byte, gate *scrub.Gate, path string) []byte {
	s := string(body)

	s = cssURLRe.ReplaceAllStringFunc(s, func(match string) string {
		parts := cssURLRe.FindStringSubmatch(match)
		if len(parts) < 4 {
			return match
		}
		return parts[1] + gate.Scrub(parts[2], "css:url:"+path) + parts[3]
	})

	return gate.ScrubBytes([]byte(s), "css:body:"+path)
}
