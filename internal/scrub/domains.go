package scrub

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

var safeDomains = map[string]bool{
	"googleapis.com":       true,
	"cloudflare.com":       true,
	"w3.org":               true,
	"schema.org":           true,
	"iana.org":             true,
	"cloudflare-dns.com":   true,
	"gstatic.com":          true,
	"google.com":           true,
	"jquery.com":           true,
	"jsdelivr.net":         true,
	"bootstrapcdn.com":     true,
	"cdnjs.cloudflare.com": true,
}

var safeSuffixes = []string{
	".local",
	".localhost",
	".test",
	".example",
	".example.com",
	".example.net",
	".example.org",
	".invalid",
}

func IsSafeDomain(domain string) bool {
	lower := strings.ToLower(domain)
	if safeDomains[lower] {
		return true
	}
	for _, suffix := range safeSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	for safe := range safeDomains {
		if strings.HasSuffix(lower, "."+safe) {
			return true
		}
	}
	return false
}

func AliasDomain(domain string, aliasSuffix string) string {
	h := sha256.Sum256([]byte(strings.ToLower(domain)))
	return fmt.Sprintf("host-%x.%s", h[:4], aliasSuffix)
}

func AliasOrigin(scheme, host, port, aliasSuffix string) string {
	origin := strings.ToLower(scheme) + "\x00" + strings.ToLower(host)
	if port != "" && !isDefaultPort(scheme, port) {
		origin += "\x00" + port
	}
	h := sha256.Sum256([]byte(origin))
	return fmt.Sprintf("host-%x.%s", h[:4], aliasSuffix)
}

func isDefaultPort(scheme, port string) bool {
	return (strings.EqualFold(scheme, "https") && port == "443") ||
		(strings.EqualFold(scheme, "http") && port == "80")
}

func AliasCookieName(name string) string {
	h := sha256.Sum256([]byte(name))
	return fmt.Sprintf("ck_%x", h[:4])
}
