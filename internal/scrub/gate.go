package scrub

import (
	"net"
	"regexp"
	"strings"
	"sync"
)

var (
	domainRe = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
	emailRe  = regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`)
	ipv4Re   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re   = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|(?i)\b(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}\b|(?i)::(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,5}::\b`)
)

const testNetIPv4 = "203.0.113.1"
const testNetIPv6 = "2001:db8::1"

type LeakEntry struct {
	Context string
	Type    string
	Detail  string
	Count   int
}

type Gate struct {
	parent         *Gate // Per-request counters; aliases and aggregate findings stay shared.
	targetDomains  []string
	identityTokens []string
	domainPatterns []*regexp.Regexp
	tokenPatterns  []*regexp.Regexp
	aliasDomain    string
	mu             sync.Mutex
	leaks          map[string]*LeakEntry
	aliases        map[string]string // alias → real domain
	cookieAliases  map[string]string // alias → original cookie name
}

// ForRequest keeps replacement counts isolated from concurrent requests while
// retaining session-wide domain and cookie mappings.
func (g *Gate) ForRequest() *Gate {
	return &Gate{
		parent: g, targetDomains: g.targetDomains, identityTokens: g.identityTokens,
		domainPatterns: g.domainPatterns, tokenPatterns: g.tokenPatterns,
		aliasDomain: g.aliasDomain, leaks: make(map[string]*LeakEntry),
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

	g := &Gate{
		targetDomains:  domains,
		identityTokens: tokens,
		aliasDomain:    aliasDomain,
		leaks:          make(map[string]*LeakEntry),
		aliases:        make(map[string]string),
		cookieAliases:  make(map[string]string),
	}
	for _, domain := range domains {
		g.domainPatterns = append(g.domainPatterns, literalPattern(domain))
	}
	for _, token := range tokens {
		g.tokenPatterns = append(g.tokenPatterns, literalPattern(token))
	}
	return g
}

func literalPattern(value string) *regexp.Regexp {
	if value == "" {
		return nil
	}
	// Match against the original UTF-8 bytes. Lowercasing can change byte
	// lengths, so offsets from a lowercased copy cannot safely slice the input.
	return regexp.MustCompile("(?i)" + regexp.QuoteMeta(value))
}

func (g *Gate) Scrub(input string, context string) string {
	result := input

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

	for _, pattern := range g.tokenPatterns {
		if pattern == nil {
			continue
		}
		result = pattern.ReplaceAllStringFunc(result, func(string) string {
			g.recordLeak(context, "identity_token", "[configured token]")
			return "[REDACTED]"
		})
	}

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
		alias := g.aliasDomainAndRecord(domain)
		return "user@" + alias
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
		return testNetIPv4
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
		return testNetIPv6
	})

	result = domainRe.ReplaceAllStringFunc(result, func(domain string) string {
		if IsSafeDomain(domain) {
			return domain
		}
		if domain == g.aliasDomain || strings.HasSuffix(domain, "."+g.aliasDomain) {
			return domain
		}
		g.recordLeak(context, "domain", domain)
		return g.aliasDomainAndRecord(domain)
	})

	return result
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
