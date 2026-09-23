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
	targetDomains  []string
	identityTokens []string
	aliasDomain    string
	mu             sync.Mutex
	leaks          map[string]*LeakEntry
	aliases        map[string]string // alias → real domain
	cookieAliases  map[string]string // alias → original cookie name
}

func NewGate(targetDomains []string, identityTokens []string, aliasDomain string) *Gate {
	domains := make([]string, len(targetDomains))
	copy(domains, targetDomains)

	tokens := make([]string, len(identityTokens))
	copy(tokens, identityTokens)

	return &Gate{
		targetDomains:  domains,
		identityTokens: tokens,
		aliasDomain:    aliasDomain,
		leaks:          make(map[string]*LeakEntry),
		aliases:        make(map[string]string),
		cookieAliases:  make(map[string]string),
	}
}

func (g *Gate) Scrub(input string, context string) string {
	result := input

	for _, domain := range g.targetDomains {
		domainLower := strings.ToLower(domain)
		for {
			idx := strings.Index(strings.ToLower(result), domainLower)
			if idx < 0 {
				break
			}
			alias := g.aliasDomainAndRecord(domain)
			g.recordLeak(context, "target_domain", domain)
			result = result[:idx] + alias + result[idx+len(domain):]
		}
	}

	for _, token := range g.identityTokens {
		tokenLower := strings.ToLower(token)
		var b strings.Builder
		b.Grow(len(result))
		remaining := result
		remainingLower := strings.ToLower(remaining)
		for {
			idx := strings.Index(remainingLower, tokenLower)
			if idx < 0 {
				b.WriteString(remaining)
				break
			}
			g.recordLeak(context, "identity_token", token)
			b.WriteString(remaining[:idx])
			b.WriteString("[REDACTED]")
			remaining = remaining[idx+len(token):]
			remainingLower = remainingLower[idx+len(token):]
		}
		result = b.String()
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
	defer g.mu.Unlock()
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
}

func (g *Gate) aliasDomainAndRecord(domain string) string {
	alias := AliasDomain(domain, g.aliasDomain)
	g.mu.Lock()
	g.aliases[alias] = strings.ToLower(domain)
	g.mu.Unlock()
	return alias
}

func (g *Gate) AliasCookieNameAndRecord(name string) string {
	alias := AliasCookieName(name)
	g.mu.Lock()
	g.cookieAliases[alias] = name
	g.mu.Unlock()
	return alias
}

func (g *Gate) OriginalCookieName(alias string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if original, ok := g.cookieAliases[alias]; ok {
		return original
	}
	return alias
}

func (g *Gate) Aliases() map[string]string {
	g.mu.Lock()
	defer g.mu.Unlock()
	result := make(map[string]string, len(g.aliases))
	for k, v := range g.aliases {
		result[k] = v
	}
	return result
}
