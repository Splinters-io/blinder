package rewriter

import (
	"regexp"
	"strings"

	"github.com/Splinters-io/blinder/internal/scrub"
)

var cssURLRe = regexp.MustCompile(`(?i)(url\s*\(\s*['"]?)((?:[^)'"\\]|\\.)*)(['"]?\s*\))`)

func rewriteCSS(body []byte, gate *scrub.Gate, path string) []byte {
	s := string(body)

	locs := cssURLRe.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return gate.ScrubBytes(body, "css:body:"+path)
	}

	var out strings.Builder
	out.Grow(len(s))
	lastEnd := 0

	for _, loc := range locs {
		if loc[0] > lastEnd {
			out.WriteString(gate.Scrub(s[lastEnd:loc[0]], "css:body:"+path))
		}
		match := s[loc[0]:loc[1]]
		parts := cssURLRe.FindStringSubmatch(match)
		if len(parts) >= 4 {
			out.WriteString(parts[1])
			out.WriteString(gate.Scrub(parts[2], "css:url:"+path))
			out.WriteString(parts[3])
		} else {
			out.WriteString(match)
		}
		lastEnd = loc[1]
	}

	if lastEnd < len(s) {
		out.WriteString(gate.Scrub(s[lastEnd:], "css:body:"+path))
	}

	return []byte(out.String())
}
