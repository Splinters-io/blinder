package rewriter

import (
	"net/url"
	"strings"

	"github.com/Splinters-io/blinder/internal/scrub"
)

// scrubCSPSourceURL rewrites a CSP source token using only statically known
// origins. Unknown origins pass through to the scrubber without triggering
// dynamic discovery — CSP sources are policy declarations, not resource
// references.
func scrubCSPSourceURL(value string, gate *scrub.Gate, origins *OriginMapper) string {
	mapped := origins.RewriteKnownUpstreamURL(value)
	if mapped == value {
		mapped = origins.RewriteWebSocketURL(value)
	}
	known := mapped != value
	if !known && origins != nil {
		if u, err := url.Parse(mapped); err == nil && u.User == nil && u.Opaque == "" {
			known = origins.IsKnownFullOrigin(u)
			if u.Scheme == "wss" {
				known = origins.Resolve(u.Host) != nil
			}
		}
	}
	if !known {
		return gate.Scrub(value, "csp")
	}
	start := strings.Index(mapped, "://")
	if start >= 0 {
		start += 3
	} else if strings.HasPrefix(mapped, "//") {
		start = 2
	} else {
		return gate.Scrub(value, "csp")
	}
	if end := strings.IndexAny(mapped[start:], "/?#"); end >= 0 {
		boundary := start + end
		return mapped[:boundary] + gate.ScrubNoDomains(mapped[boundary:], "csp")
	}
	return mapped
}

// scrubResourceURL translates a registered resource before masking its data.
// Generated routing authorities are infrastructure, not target identity text:
// rescanning them can corrupt an IP alias or a hostname containing an identity.
// Paths, queries and fragments still pass through the reversible scrubber.
func scrubResourceURL(value string, gate *scrub.Gate, context string, origins *OriginMapper) string {
	mapped := origins.RewriteUpstreamURL(value)
	if mapped == value {
		mapped = origins.RewriteWebSocketURL(value)
	}
	known := mapped != value
	if !known && origins != nil {
		if u, err := url.Parse(mapped); err == nil && u.User == nil && u.Opaque == "" {
			known = origins.IsKnownFullOrigin(u)
			if u.Scheme == "wss" {
				known = origins.Resolve(u.Host) != nil
			}
		}
	}
	if !known {
		if isRelativePath(value) {
			return gate.ScrubNoDomains(value, context)
		}
		return gate.Scrub(value, context)
	}
	start := strings.Index(mapped, "://")
	if start >= 0 {
		start += 3
	} else if strings.HasPrefix(mapped, "//") {
		start = 2
	} else {
		return gate.ScrubNoDomains(value, context)
	}
	if end := strings.IndexAny(mapped[start:], "/?#"); end >= 0 {
		boundary := start + end
		return mapped[:boundary] + gate.ScrubNoDomains(mapped[boundary:], context)
	}
	return mapped
}

func isRelativePath(value string) bool {
	return len(value) > 0 && (value[0] == '/' || value[0] == '?' || value[0] == '#') ||
		strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../")
}
