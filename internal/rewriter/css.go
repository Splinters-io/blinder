package rewriter

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Splinters-io/blinder/internal/scrub"
)

var cssURLRe = regexp.MustCompile(`(?i)(url\s*\(\s*['"]?)((?:[^)'"\\]|\\.)*)(['"]?\s*\))`)
var cssImportRe = regexp.MustCompile(`(?i)(@import\s+['"])((?:[^'"\\]|\\.)*)(['"])`)
var cssSelectorRe = regexp.MustCompile(`([.#])([a-zA-Z_-][a-zA-Z0-9_-]*)`)

func rewriteCSS(body []byte, gate *scrub.Gate, path string, originMaps ...*OriginMapper) []byte {
	var origins *OriginMapper
	paranoid := false
	for _, om := range originMaps {
		if om != nil {
			origins = om
		}
	}
	return rewriteCSSInner(body, gate, path, origins, paranoid)
}

func rewriteCSSParanoid(body []byte, gate *scrub.Gate, path string, origins *OriginMapper, paranoid bool) []byte {
	return rewriteCSSInner(body, gate, path, origins, paranoid)
}

func rewriteCSSInner(body []byte, gate *scrub.Gate, path string, origins *OriginMapper, paranoid bool) []byte {
	s := string(body)

	locs := cssURLRe.FindAllStringSubmatchIndex(s, -1)
	locs = append(locs, cssImportRe.FindAllStringSubmatchIndex(s, -1)...)
	sort.Slice(locs, func(i, j int) bool { return locs[i][0] < locs[j][0] })

	scrubCSS := func(text string) string {
		scrubbed := gate.Scrub(text, "css:body:"+path)
		if paranoid {
			scrubbed = aliasCSSSelectorNames(scrubbed, gate)
		}
		return scrubbed
	}

	if len(locs) == 0 {
		return []byte(scrubCSS(s))
	}

	var out strings.Builder
	out.Grow(len(s))
	lastEnd := 0

	for _, loc := range locs {
		if loc[0] < lastEnd {
			continue
		}
		if loc[0] > lastEnd {
			out.WriteString(scrubCSS(s[lastEnd:loc[0]]))
		}
		if len(loc) >= 8 {
			prefix := s[loc[2]:loc[3]]
			out.WriteString(prefix)
			value := s[loc[4]:loc[5]]
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
		out.WriteString(scrubCSS(s[lastEnd:]))
	}

	return []byte(out.String())
}

var cssGroupAtRules = map[string]bool{
	"media": true, "supports": true, "document": true,
	"layer": true, "container": true, "scope": true,
}

func aliasCSSSelectorNames(css string, gate *scrub.Gate) string {
	var out strings.Builder
	out.Grow(len(css))
	// Stack: true = declaration block (don't alias), false = group block (alias OK).
	var declStack []bool
	inDecl := false
	pendingGroup := false
	i := 0
	for i < len(css) {
		if css[i] == '@' {
			start := i + 1
			for start < len(css) && (css[start] >= 'a' && css[start] <= 'z' || css[start] >= 'A' && css[start] <= 'Z' || css[start] == '-') {
				start++
			}
			keyword := strings.ToLower(css[i+1 : start])
			if cssGroupAtRules[keyword] {
				pendingGroup = true
			}
			out.WriteByte(css[i])
			i++
			continue
		}
		if css[i] == '{' {
			if pendingGroup {
				declStack = append(declStack, false)
				inDecl = false
				pendingGroup = false
			} else {
				declStack = append(declStack, true)
				inDecl = true
			}
			out.WriteByte(css[i])
			i++
			continue
		}
		if css[i] == '}' {
			if len(declStack) > 0 {
				declStack = declStack[:len(declStack)-1]
			}
			if len(declStack) > 0 {
				inDecl = declStack[len(declStack)-1]
			} else {
				inDecl = false
			}
			pendingGroup = false
			out.WriteByte(css[i])
			i++
			continue
		}
		if !inDecl && (css[i] == '.' || css[i] == '#') {
			loc := cssSelectorRe.FindStringIndex(css[i:])
			if loc != nil && loc[0] == 0 {
				prefix := css[i : i+1]
				name := css[i+1 : i+loc[1]]
				out.WriteString(prefix + aliasName(name, gate))
				i += loc[1]
				continue
			}
		}
		out.WriteByte(css[i])
		i++
	}
	return out.String()
}
