package rewriter

import "strings"

// RewriteCSPOrigins translates URL source tokens without changing policy
// boundaries, hashes, nonces, keywords, or application-defined control names.
// The callback must leave sources it cannot faithfully translate unchanged.
func RewriteCSPOrigins(policy string, mapSource func(string) string) string {
	if mapSource == nil {
		return policy
	}
	return RewriteCSPURLs(policy, func(_ string, source string) string { return mapSource(source) })
}

// RewriteCSPURLs additionally supplies the directive, so report endpoints can
// retain one destination while source permissions may name equivalent aliases.
func RewriteCSPURLs(policy string, mapSource func(directive, source string) string) string {
	if mapSource == nil {
		return policy
	}
	var out strings.Builder
	start := 0
	for end := 0; end <= len(policy); end++ {
		if end != len(policy) && policy[end] != ';' && policy[end] != ',' {
			continue
		}
		directive := policy[start:end]
		fields := strings.FieldsFunc(directive, cspASCIIWhitespace)
		if len(fields) < 2 || cspHasNonASCII(directive) || (!cspSourceDirectives[strings.ToLower(fields[0])] && !strings.EqualFold(fields[0], "report-uri")) {
			out.WriteString(directive)
		} else {
			index := 0
			for i := 0; i < len(directive); {
				if cspASCIIWhitespace(rune(directive[i])) {
					out.WriteByte(directive[i])
					i++
					continue
				}
				j := i + 1
				for j < len(directive) && !cspASCIIWhitespace(rune(directive[j])) {
					j++
				}
				token := directive[i:j]
				if index > 0 {
					token = mapSource(strings.ToLower(fields[0]), token)
				}
				out.WriteString(token)
				index++
				i = j
			}
		}
		if end < len(policy) {
			out.WriteByte(policy[end])
		}
		start = end + 1
	}
	return out.String()
}
