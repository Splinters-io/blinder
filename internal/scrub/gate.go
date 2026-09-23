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
	}
}

func (g *Gate) Scrub(input string, context string) string {
	result := input

	for _, domain := range g.targetDomains {
		lower := strings.ToLower(result)
		domainLower := strings.ToLower(domain)
		for {
			idx := strings.Index(strings.ToLower(result), domainLower)
			if idx < 0 {
				break
			}
			alias := AliasDomain(domain, g.aliasDomain)
			g.recordLeak(context, "target_domain", domain)
			result = result[:idx] + alias + result[idx+len(domain):]
		}
		_ = lower
	}

	for _, token := range g.identityTokens {
		lower := strings.ToLower(result)
		tokenLower := strings.ToLower(token)
		for {
			idx := strings.Index(lower, tokenLower)
			if idx < 0 {
				break
			}
			g.recordLeak(context, "identity_token", token)
			result = result[:idx] + "[REDACTED]" + result[idx+len(token):]
			lower = strings.ToLower(result)
		}
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
		alias := AliasDomain(domain, g.aliasDomain)
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
		return AliasDomain(domain, g.aliasDomain)
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
