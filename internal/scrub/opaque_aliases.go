package scrub

import "strings"

// OpaqueValueAliasPrefix reserves a base64-compatible namespace for values
// which cannot use the ordinary bracketed identity aliases (CSP nonces, for
// example). Scrub escapes literal occurrences even before the first value is
// registered, so later registrations cannot reinterpret an earlier literal.
const OpaqueValueAliasPrefix = "bn1-"

// RegisterOpaqueValueAlias records a caller-generated alias in the reserved
// namespace. A duplicate mapping is harmless; a conflicting mapping is rejected
// without replacing the existing inverse. The alias must be one complete
// base64/base64url token. Original values are not interpreted as aliases.
func (g *Gate) RegisterOpaqueValueAlias(alias, original string) bool {
	if g.parent != nil {
		return g.parent.RegisterOpaqueValueAlias(alias, original)
	}
	if !strings.HasPrefix(alias, OpaqueValueAliasPrefix) || opaqueTokenEnd(alias, 0) != len(alias) || len(alias)-len(strings.TrimRight(alias, "=")) > 2 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if previous, exists := g.opaqueAliases[alias]; exists {
		return previous == original
	}
	if g.opaqueAliases == nil {
		g.opaqueAliases = make(map[string]string)
	}
	g.opaqueAliases[alias] = original
	return true
}

func isOpaqueTokenByte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '/' || b == '_' || b == '-'
}

func opaqueTokenEnd(input string, start int) int {
	i := start
	for i < len(input) && isOpaqueTokenByte(input[i]) {
		i++
	}
	if i == start {
		return start
	}
	for i < len(input) && input[i] == '=' {
		i++
	}
	return i
}

// Call while holding g.mu. Scan maximal tokens rather than matching alias
// prefixes inside a larger application value.
func (g *Gate) containsOpaqueAlias(input string) bool {
	if len(g.opaqueAliases) == 0 {
		return false
	}
	for i := 0; i < len(input); {
		end := opaqueTokenEnd(input, i)
		if end == i {
			i++
			continue
		}
		if _, exists := g.opaqueAliases[input[i:end]]; exists {
			return true
		}
		i = end
	}
	return false
}

// Call after generic restoration while holding g.mu. Escapes and opaque aliases
// are consumed in one pass: neither a decoded literal nor an emitted original
// is rescanned. This also preserves an original that itself resembles an escape.
func (g *Gate) restoreOpaqueAliasesAndMarkers(input string) string {
	if len(g.opaqueAliases) == 0 {
		return g.unescapeMarkers(input)
	}
	var out strings.Builder
	last := 0
	for i := 0; i < len(input); {
		end := opaqueTokenEnd(input, i)
		if end == i {
			i++
			continue
		}
		if original, exists := g.opaqueAliases[input[i:end]]; exists {
			out.WriteString(g.unescapeMarkers(input[last:i]))
			out.WriteString(original)
			last = end
		}
		i = end
	}
	if last == 0 {
		return g.unescapeMarkers(input)
	}
	out.WriteString(g.unescapeMarkers(input[last:]))
	return out.String()
}
