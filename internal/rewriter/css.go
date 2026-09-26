package rewriter

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Splinters-io/blinder/internal/scrub"
)

var cssURLRe = regexp.MustCompile(`(?i)(url\s*\(\s*['"]?)((?:[^)'"\\]|\\.)*)(['"]?\s*\))`)
var cssImportRe = regexp.MustCompile(`(?i)(@import\s+['"])((?:[^'"\\]|\\.)*)(['"])`)

func rewriteCSS(body []byte, gate *scrub.Gate, path string, originMaps ...*OriginMapper) []byte {
	var origins *OriginMapper
	if len(originMaps) > 0 {
		origins = originMaps[0]
	}
	s := string(body)

	locs := cssURLRe.FindAllStringSubmatchIndex(s, -1)
	locs = append(locs, cssImportRe.FindAllStringSubmatchIndex(s, -1)...)
	sort.Slice(locs, func(i, j int) bool { return locs[i][0] < locs[j][0] })
	if len(locs) == 0 {
		return gate.ScrubBytes(body, "css:body:"+path)
	}

	var out strings.Builder
	out.Grow(len(s))
	lastEnd := 0

	for _, loc := range locs {
		if loc[0] < lastEnd {
			continue
		}
		if loc[0] > lastEnd {
			out.WriteString(gate.Scrub(s[lastEnd:loc[0]], "css:body:"+path))
		}
		if len(loc) >= 8 {
			prefix := s[loc[2]:loc[3]]
			out.WriteString(prefix)
			value := s[loc[4]:loc[5]]
			// In an unquoted url(), trailing CSS whitespace belongs to the
			// syntax, not the resource path. Parsing it as URL data would turn
			// url(.../image  ) into a request for /image%20%20.
			trailing := ""
			if !strings.HasSuffix(prefix, "\"") && !strings.HasSuffix(prefix, "'") {
				end := len(strings.TrimRight(value, " \t\r\n\f"))
				trailing, value = value[end:], value[:end]
			}
			if strings.ContainsRune(value, '\\') {
				out.WriteString(gate.Scrub(value, "css:url:"+path))
			} else {
				out.WriteString(scrubResourceURL(value, gate, "css:url:"+path, origins))
			}
			out.WriteString(trailing)
			out.WriteString(s[loc[6]:loc[7]])
		} else {
			out.WriteString(s[loc[0]:loc[1]])
		}
		lastEnd = loc[1]
	}

	if lastEnd < len(s) {
		out.WriteString(gate.Scrub(s[lastEnd:], "css:body:"+path))
	}

	return []byte(out.String())
}
