package scrub

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/Splinters-io/blinder/internal/jsonedit"
)

var (
	domainRe = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
	emailRe  = regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`)
	ipv4Re   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re   = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|(?i)\b(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}\b|(?i)::(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,5}::\b`)
)

// ValueAliasPrefix identifies reversible opaque identity values. It carries no
// removal or status wording; ordinary display prose is handled by the rewriter.
const ValueAliasPrefix = "[v:"

const testNetIPv4 = "203.0.113.1"
const testNetIPv6 = "2001:db8::1"

type LeakEntry struct {
	Context string
	Type    string
	Detail  string
	Count   int
}

type cookieValueMapping struct {
	original string
	scrubbed string
}

type Gate struct {
	parent           *Gate // Per-request counters; aliases and aggregate findings stay shared.
	targetDomains    []string
	identityTokens   []string
	domainPatterns   []*regexp.Regexp
	tokenPatterns    []*regexp.Regexp
	aliasDomain      string
	escapePrefix     string
	preserveDomains  map[string]bool
	preserveURLCheck func(fullURL string) bool
	mu               sync.Mutex
	leaks            map[string]*LeakEntry
	aliases          map[string]string               // alias → real domain
	cookieAliases    map[string]string               // alias → original cookie name
	cookieValues     map[string][]cookieValueMapping // aliased cookie name → value mappings
	tokenAliases     map[string]string               // alias → original token text
	emailAliases     map[string]string               // alias → original email
	ipv4Aliases      map[string]string               // alias → original IPv4
	ipv6Aliases      map[string]string               // alias → original IPv6
	opaqueAliases    map[string]string               // grammar-constrained alias → original value
}

// ForRequest keeps replacement counts isolated from concurrent requests while
// retaining session-wide domain and cookie mappings.
func (g *Gate) ForRequest() *Gate {
	return &Gate{
		parent: g, targetDomains: g.targetDomains, identityTokens: g.identityTokens,
		domainPatterns: g.domainPatterns, tokenPatterns: g.tokenPatterns,
		aliasDomain: g.aliasDomain, escapePrefix: g.escapePrefix,
		preserveDomains:  g.preserveDomains,
		preserveURLCheck: g.preserveURLCheck,
		leaks:            make(map[string]*LeakEntry),
	}
}

func (g *Gate) ReplacementCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	total := 0
	for _, entry := range g.leaks {
		total += entry.Count
	}
	return total
}

func NewGate(targetDomains []string, identityTokens []string, aliasDomain string) *Gate {
	domains := make([]string, len(targetDomains))
	copy(domains, targetDomains)

	tokens := make([]string, len(identityTokens))
	copy(tokens, identityTokens)

	nonceData := []byte(aliasDomain)
	for _, t := range tokens {
		nonceData = append(nonceData, 0)
		nonceData = append(nonceData, []byte(t)...)
	}
	nh := sha256.Sum256(nonceData)

	g := &Gate{
		targetDomains:  domains,
		identityTokens: tokens,
		aliasDomain:    aliasDomain,
		escapePrefix:   "[~" + hex.EncodeToString(nh[:6]) + ":",
		leaks:          make(map[string]*LeakEntry),
		aliases:        make(map[string]string),
		cookieAliases:  make(map[string]string),
		cookieValues:   make(map[string][]cookieValueMapping),
		tokenAliases:   make(map[string]string),
		emailAliases:   make(map[string]string),
		ipv4Aliases:    make(map[string]string),
		ipv6Aliases:    make(map[string]string),
		opaqueAliases:  make(map[string]string),
	}
	for _, domain := range domains {
		g.domainPatterns = append(g.domainPatterns, literalPattern(domain))
	}
	for _, token := range tokens {
		g.tokenPatterns = append(g.tokenPatterns, literalPattern(token))
	}
	return g
}

func (g *Gate) SetPreserveURLCheck(fn func(fullURL string) bool) {
	if g.parent != nil {
		g.parent.SetPreserveURLCheck(fn)
		return
	}
	g.preserveURLCheck = fn
}

func (g *Gate) PreserveDomains(domains []string) {
	if g.parent != nil {
		g.parent.PreserveDomains(domains)
		return
	}
	if g.preserveDomains == nil {
		g.preserveDomains = make(map[string]bool)
	}
	for _, d := range domains {
		g.preserveDomains[strings.ToLower(d)] = true
	}
}

func literalPattern(value string) *regexp.Regexp {
	if value == "" {
		return nil
	}
	// Match against the original UTF-8 bytes. Lowercasing can change byte
	// lengths, so offsets from a lowercased copy cannot safely slice the input.
	return regexp.MustCompile("(?i)" + regexp.QuoteMeta(value))
}

func (g *Gate) escapeMarkers(input string) string {
	prefix := g.escapePrefix
	const target = ValueAliasPrefix
	if !strings.Contains(input, prefix) && !strings.Contains(input, target) && !strings.Contains(input, OpaqueValueAliasPrefix) {
		return input
	}
	var out strings.Builder
	out.Grow(len(input) + 64)
	i := 0
	for i < len(input) {
		if i+len(prefix) <= len(input) && input[i:i+len(prefix)] == prefix {
			out.WriteString(prefix)
			out.WriteByte('E')
			i += len(prefix)
		} else if i+len(target) <= len(input) && input[i:i+len(target)] == target {
			out.WriteString(prefix)
			out.WriteByte('R')
			i += len(target)
		} else if strings.HasPrefix(input[i:], OpaqueValueAliasPrefix) {
			out.WriteString(prefix)
			out.WriteByte('O')
			i += len(OpaqueValueAliasPrefix)
		} else {
			out.WriteByte(input[i])
			i++
		}
	}
	return out.String()
}

func (g *Gate) unescapeMarkers(input string) string {
	prefix := g.escapePrefix
	if !strings.Contains(input, prefix) {
		return input
	}
	var out strings.Builder
	out.Grow(len(input))
	i := 0
	for i < len(input) {
		if i+len(prefix) <= len(input) && input[i:i+len(prefix)] == prefix {
			i += len(prefix)
			if i < len(input) {
				switch input[i] {
				case 'R':
					out.WriteString(ValueAliasPrefix)
					i++
				case 'E':
					out.WriteString(prefix)
					i++
				case 'O':
					out.WriteString(OpaqueValueAliasPrefix)
					i++
				default:
					out.WriteString(prefix)
				}
			} else {
				out.WriteString(prefix)
			}
		} else {
			out.WriteByte(input[i])
			i++
		}
	}
	return out.String()
}

func (g *Gate) Scrub(input string, context string) string {
	result := g.escapeMarkers(input)

	for i, pattern := range g.domainPatterns {
		if pattern == nil {
			continue
		}
		domain := g.targetDomains[i]
		result = pattern.ReplaceAllStringFunc(result, func(string) string {
			g.recordLeak(context, "target_domain", domain)
			return g.aliasDomainAndRecord(domain)
		})
	}

	result = g.scrubIdentityTokens(result, context)

	result = emailRe.ReplaceAllStringFunc(result, func(email string) string {
		parts := strings.SplitN(email, "@", 2)
		if len(parts) != 2 {
			return email
		}
		domain := parts[1]
		if IsSafeDomain(domain) {
			return email
		}
		g.recordLeak(context, "email", email)
		return g.aliasEmail(email, domain)
	})

	result = ipv4Re.ReplaceAllStringFunc(result, func(ipStr string) string {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return ipStr
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return ipStr
		}
		g.recordLeak(context, "public_ipv4", ipStr)
		return g.aliasIPv4(ipStr)
	})

	result = ipv6Re.ReplaceAllStringFunc(result, func(ipStr string) string {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return ipStr
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return ipStr
		}
		g.recordLeak(context, "public_ipv6", ipStr)
		return g.aliasIPv6(ipStr)
	})

	root := g
	if g.parent != nil {
		root = g.parent
	}
	if root.preserveURLCheck != nil {
		result = g.scrubDomainsURLAware(result, context)
	} else {
		result = domainRe.ReplaceAllStringFunc(result, func(domain string) string {
			if IsSafeDomain(domain) {
				return domain
			}
			if domain == g.aliasDomain || strings.HasSuffix(domain, "."+g.aliasDomain) {
				return domain
			}
			if g.isPreservedDomain(domain) {
				return domain
			}
			g.recordLeak(context, "domain", domain)
			return g.aliasDomainAndRecord(domain)
		})
	}

	return result
}

// scrubIdentityTokens applies configured patterns only to source text. Each
// replacement and literal escape sequence stays opaque to subsequent patterns,
// even when a configured identity is "v", a hex digit, or part of the nonce.
func (g *Gate) scrubIdentityTokens(input, context string) string {
	if len(g.tokenPatterns) == 0 {
		return input
	}
	type segment struct {
		text   string
		opaque bool
	}
	var segments []segment
	remaining := input
	for {
		index := strings.Index(remaining, g.escapePrefix)
		if index < 0 {
			segments = append(segments, segment{text: remaining})
			break
		}
		segments = append(segments, segment{text: remaining[:index]})
		end := index + len(g.escapePrefix)
		if end < len(remaining) && (remaining[end] == 'E' || remaining[end] == 'R' || remaining[end] == 'O') {
			end++
		}
		segments = append(segments, segment{text: remaining[index:end], opaque: true})
		remaining = remaining[end:]
	}
	for _, pattern := range g.tokenPatterns {
		if pattern == nil {
			continue
		}
		var next []segment
		for _, part := range segments {
			if part.opaque {
				next = append(next, part)
				continue
			}
			last := 0
			for _, match := range pattern.FindAllStringIndex(part.text, -1) {
				next = append(next, segment{text: part.text[last:match[0]]})
				g.recordLeak(context, "identity_token", "[configured token]")
				next = append(next, segment{text: g.aliasToken(part.text[match[0]:match[1]]), opaque: true})
				last = match[1]
			}
			next = append(next, segment{text: part.text[last:]})
		}
		segments = next
	}
	var out strings.Builder
	out.Grow(len(input))
	for _, part := range segments {
		out.WriteString(part.text)
	}
	return out.String()
}

func (g *Gate) ScrubBytes(input []byte, context string) []byte {
	return []byte(g.Scrub(string(input), context))
}

func (g *Gate) Leaks() []LeakEntry {
	g.mu.Lock()
	defer g.mu.Unlock()

	entries := make([]LeakEntry, 0, len(g.leaks))
	for _, e := range g.leaks {
		entries = append(entries, LeakEntry{
			Context: e.Context,
			Type:    e.Type,
			Detail:  e.Detail,
			Count:   e.Count,
		})
	}
	return entries
}

func (g *Gate) recordLeak(context, typ, detail string) {
	key := context + "|" + typ + "|" + detail
	g.mu.Lock()
	if entry, ok := g.leaks[key]; ok {
		entry.Count++
	} else {
		g.leaks[key] = &LeakEntry{
			Context: context,
			Type:    typ,
			Detail:  detail,
			Count:   1,
		}
	}
	g.mu.Unlock()
	if g.parent != nil {
		g.parent.recordLeak(context, typ, detail)
	}
}

func (g *Gate) aliasDomainAndRecord(domain string) string {
	if g.parent != nil {
		return g.parent.aliasDomainAndRecord(domain)
	}
	alias := AliasDomain(domain, g.aliasDomain)
	g.mu.Lock()
	g.aliases[alias] = strings.ToLower(domain)
	g.mu.Unlock()
	return alias
}

func (g *Gate) AliasCookieNameAndRecord(name string) string {
	if g.parent != nil {
		return g.parent.AliasCookieNameAndRecord(name)
	}
	alias := AliasCookieName(name)
	g.mu.Lock()
	g.cookieAliases[alias] = name
	g.mu.Unlock()
	return alias
}

func (g *Gate) OriginalCookieName(alias string) string {
	if g.parent != nil {
		return g.parent.OriginalCookieName(alias)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if original, ok := g.cookieAliases[alias]; ok {
		return original
	}
	return alias
}

func (g *Gate) Aliases() map[string]string {
	if g.parent != nil {
		return g.parent.Aliases()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	result := make(map[string]string, len(g.aliases))
	for k, v := range g.aliases {
		result[k] = v
	}
	return result
}

func cookieValueKey(aliasedName, origin string) string {
	return aliasedName + "\x00" + origin
}

func (g *Gate) RecordCookieValue(aliasedName, original, scrubbed, origin string) string {
	if g.parent != nil {
		return g.parent.RecordCookieValue(aliasedName, original, scrubbed, origin)
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	key := cookieValueKey(aliasedName, origin)
	for _, m := range g.cookieValues[key] {
		if m.original == original {
			return m.scrubbed
		}
	}

	unique := scrubbed
	h := sha256.Sum256([]byte(original))
	for hashLen := 3; hashLen <= 32; hashLen++ {
		collision := false
		for _, m := range g.cookieValues[key] {
			if m.scrubbed == unique {
				collision = true
				break
			}
		}
		if !collision {
			break
		}
		unique = scrubbed + ":" + hex.EncodeToString(h[:hashLen])
	}

	updated := make([]cookieValueMapping, len(g.cookieValues[key]), len(g.cookieValues[key])+1)
	copy(updated, g.cookieValues[key])
	g.cookieValues[key] = append(updated, cookieValueMapping{original: original, scrubbed: unique})
	return unique
}

func (g *Gate) ResidualLeakCount(scrubbed string) int {
	count := 0
	for _, pattern := range g.domainPatterns {
		if pattern != nil {
			count += len(pattern.FindAllString(scrubbed, -1))
		}
	}
	for _, pattern := range g.tokenPatterns {
		if pattern != nil {
			count += len(pattern.FindAllString(scrubbed, -1))
		}
	}
	return count
}

func (g *Gate) RestoreCookieValue(aliasedName, currentValue, origin string) string {
	if g.parent != nil {
		return g.parent.RestoreCookieValue(aliasedName, currentValue, origin)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	key := cookieValueKey(aliasedName, origin)
	for _, m := range g.cookieValues[key] {
		if currentValue == m.scrubbed {
			return m.original
		}
	}
	return currentValue
}

func (g *Gate) RestoreCookieHeader(header, origin string) string {
	var parts []string
	for _, pair := range strings.Split(header, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eqIdx := strings.IndexByte(pair, '=')
		if eqIdx < 0 {
			parts = append(parts, pair)
			continue
		}
		aliasedName := pair[:eqIdx]
		value := pair[eqIdx+1:]
		originalName := g.OriginalCookieName(aliasedName)
		originalValue := g.RestoreCookieValue(aliasedName, value, origin)
		parts = append(parts, originalName+"="+originalValue)
	}
	return strings.Join(parts, "; ")
}

func (g *Gate) aliasToken(original string) string {
	if g.parent != nil {
		return g.parent.aliasToken(original)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for alias, orig := range g.tokenAliases {
		if orig == original {
			return alias
		}
	}
	h := sha256.Sum256([]byte(original))
	for size := 3; size <= len(h); size++ {
		alias := ValueAliasPrefix + hex.EncodeToString(h[:size]) + "]"
		if _, exists := g.tokenAliases[alias]; !exists {
			g.tokenAliases[alias] = original
			return alias
		}
	}
	// Even a full digest collision must not overwrite an existing inverse map.
	for suffix := 1; ; suffix++ {
		alias := fmt.Sprintf("%s%x-%d]", ValueAliasPrefix, h, suffix)
		if _, exists := g.tokenAliases[alias]; !exists {
			g.tokenAliases[alias] = original
			return alias
		}
	}
}

func (g *Gate) aliasEmail(original, domain string) string {
	if g.parent != nil {
		return g.parent.aliasEmail(original, domain)
	}
	domainAlias := g.aliasDomainAndRecord(domain)
	g.mu.Lock()
	defer g.mu.Unlock()
	for alias, orig := range g.emailAliases {
		if orig == original {
			return alias
		}
	}
	n := len(g.emailAliases) + 1
	alias := fmt.Sprintf("user%d@%s", n, domainAlias)
	g.emailAliases[alias] = original
	return alias
}

func (g *Gate) aliasIPv4(original string) string {
	if g.parent != nil {
		return g.parent.aliasIPv4(original)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for alias, orig := range g.ipv4Aliases {
		if orig == original {
			return alias
		}
	}
	n := len(g.ipv4Aliases) + 1
	alias := fmt.Sprintf("203.0.113.%d", n)
	g.ipv4Aliases[alias] = original
	return alias
}

func (g *Gate) aliasIPv6(original string) string {
	if g.parent != nil {
		return g.parent.aliasIPv6(original)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for alias, orig := range g.ipv6Aliases {
		if orig == original {
			return alias
		}
	}
	n := len(g.ipv6Aliases) + 1
	alias := fmt.Sprintf("2001:db8::%d", n)
	g.ipv6Aliases[alias] = original
	return alias
}

func (g *Gate) RestoreBody(input string) string {
	if g.parent != nil {
		return g.parent.RestoreBody(input)
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	result := input
	for alias, original := range g.tokenAliases {
		result = strings.ReplaceAll(result, alias, original)
	}
	for alias, original := range g.emailAliases {
		result = strings.ReplaceAll(result, alias, original)
	}
	for alias, original := range g.ipv4Aliases {
		result = strings.ReplaceAll(result, alias, original)
	}
	for alias, original := range g.ipv6Aliases {
		result = strings.ReplaceAll(result, alias, original)
	}
	for alias, original := range g.aliases {
		result = strings.ReplaceAll(result, alias, original)
	}

	result = g.restoreOpaqueAliasesAndMarkers(result)

	return result
}

func (g *Gate) ContainsAlias(input string) bool {
	if g.parent != nil {
		return g.parent.ContainsAlias(input)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for alias := range g.tokenAliases {
		if strings.Contains(input, alias) {
			return true
		}
	}
	for alias := range g.emailAliases {
		if strings.Contains(input, alias) {
			return true
		}
	}
	for alias := range g.ipv4Aliases {
		if strings.Contains(input, alias) {
			return true
		}
	}
	for alias := range g.ipv6Aliases {
		if strings.Contains(input, alias) {
			return true
		}
	}
	for alias := range g.aliases {
		if strings.Contains(input, alias) {
			return true
		}
	}
	return g.containsOpaqueAlias(input)
}

func (g *Gate) scrubDomainsURLAware(input, context string) string {
	root := g
	if g.parent != nil {
		root = g.parent
	}

	locs := domainRe.FindAllStringIndex(input, -1)
	if len(locs) == 0 {
		return input
	}

	var b strings.Builder
	b.Grow(len(input))
	last := 0
	for _, loc := range locs {
		domain := input[loc[0]:loc[1]]
		b.WriteString(input[last:loc[0]])

		switch {
		case IsSafeDomain(domain):
			b.WriteString(domain)
		case domain == g.aliasDomain || strings.HasSuffix(domain, "."+g.aliasDomain):
			b.WriteString(domain)
		case g.isPreservedDomain(domain):
			b.WriteString(domain)
		default:
			fullURL := extractURLAroundDomain(input, loc[0], loc[1])
			if fullURL != "" && root.preserveURLCheck(fullURL) {
				b.WriteString(domain)
			} else {
				g.recordLeak(context, "domain", domain)
				b.WriteString(g.aliasDomainAndRecord(domain))
			}
		}
		last = loc[1]
	}
	b.WriteString(input[last:])
	return b.String()
}

func extractURLAroundDomain(input string, domStart, domEnd int) string {
	schemeEnd := domStart
	scheme := ""
	if schemeEnd >= 8 && input[schemeEnd-8:schemeEnd] == "https://" {
		scheme = "https://"
	} else if schemeEnd >= 7 && input[schemeEnd-7:schemeEnd] == "http://" {
		scheme = "http://"
	}
	if scheme == "" {
		return ""
	}

	end := domEnd
	for end < len(input) {
		c := input[end]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
			c == '"' || c == '\'' || c == '<' || c == '>' ||
			c == ')' || c == ']' {
			break
		}
		end++
	}
	return scheme + input[domStart:end]
}

func (g *Gate) isPreservedDomain(domain string) bool {
	root := g
	if g.parent != nil {
		root = g.parent
	}
	if root.preserveDomains == nil {
		return false
	}
	lower := strings.ToLower(domain)
	if root.preserveDomains[lower] {
		return true
	}
	for d := range root.preserveDomains {
		if strings.HasSuffix(lower, "."+d) {
			return true
		}
	}
	return false
}

func (g *Gate) ContainsEscape(input string) bool {
	return strings.Contains(input, g.escapePrefix)
}

func (g *Gate) Seed() []byte {
	data := []byte(g.aliasDomain)
	for _, d := range g.targetDomains {
		data = append(data, 0)
		data = append(data, []byte(d)...)
	}
	for _, t := range g.identityTokens {
		data = append(data, 0)
		data = append(data, []byte(t)...)
	}
	return data
}

func (g *Gate) RestoreJSON(input []byte) []byte {
	out, err := g.RestoreJSONWithOpaqueKeys(input, nil)
	if err != nil {
		return nil
	}
	return out
}

// RestoreJSONWithOpaqueKeys edits only changed string tokens, restoring aliases
// and optionally resource origins. Opaque fields retain their complete source
// value at any nesting depth.
// Pre-existing duplicate keys are preserved; newly colliding keys are rejected.
// An optional decoded-string restorer composes route restoration with aliases
// without parsing or serializing the enclosing JSON document a second time.
func (g *Gate) RestoreJSONWithOpaqueKeys(input []byte, opaqueKeys map[string]bool, restorers ...func(string) string) ([]byte, error) {
	if g.parent != nil {
		return g.parent.RestoreJSONWithOpaqueKeys(input, opaqueKeys, restorers...)
	}
	restore := g.RestoreBody
	if len(restorers) > 0 && restorers[0] != nil {
		restore = restorers[0]
	}
	out, err := jsonedit.Rewrite(input, restore, func(key string) bool {
		return opaqueKeys[key]
	})
	if errors.Is(err, jsonedit.ErrInvalidJSON) {
		// Retain the existing malformed-request behaviour. Never truncate a
		// valid first value followed by extra content into an accepted document.
		dec := json.NewDecoder(bytes.NewReader(input))
		var first json.RawMessage
		if decodeErr := dec.Decode(&first); decodeErr == nil {
			return input, nil
		}
		return []byte(restore(string(input))), nil
	}
	return out, err
}

func (g *Gate) RestoreJSONValue(v interface{}) interface{} {
	if g.parent != nil {
		return g.parent.RestoreJSONValue(v)
	}
	result, ok := g.restoreJSONValue(v)
	if !ok {
		return nil
	}
	return result
}

func (g *Gate) restoreJSONValue(v interface{}) (interface{}, bool) {
	switch val := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for key, value := range val {
			restoredKey := g.RestoreBody(key)
			if _, exists := result[restoredKey]; exists {
				return nil, false
			}
			rv, ok := g.restoreJSONValue(value)
			if !ok {
				return nil, false
			}
			result[restoredKey] = rv
		}
		return result, true
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			rv, ok := g.restoreJSONValue(item)
			if !ok {
				return nil, false
			}
			result[i] = rv
		}
		return result, true
	case json.Number:
		return val, true
	case string:
		return g.RestoreBody(val), true
	default:
		return v, true
	}
}
