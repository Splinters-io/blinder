package rewriter

import (
	"net/url"
	"strings"

	"github.com/Splinters-io/blinder/internal/scrub"
)

// scrubResourceURL translates a registered resource before masking its data.
// Generated routing authorities are infrastructure, not target identity text:
// rescanning them can corrupt an IP alias or a hostname containing an identity.
// Paths, queries and fragments still pass through the reversible scrubber.
func scrubResourceURL(value string, gate *scrub.Gate, context string, origins *OriginMapper) string {
	protoRelative := false
	mapped := origins.RewriteUpstreamURL(value)
	if mapped == value && strings.HasPrefix(value, "//") {
		full := origins.RewriteUpstreamURL("https:" + value)
		if full != "https:"+value {
			mapped = full
			protoRelative = true
		}
	}
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
		return gate.Scrub(value, context)
	}
	start := strings.Index(mapped, "://")
	if start < 0 {
		return gate.Scrub(value, context)
	}
	start += 3
	result := mapped
	if end := strings.IndexAny(mapped[start:], "/?#"); end >= 0 {
		boundary := start + end
		result = mapped[:boundary] + gate.ScrubNoDomains(mapped[boundary:], context)
	}
	if protoRelative {
		result = strings.TrimPrefix(result, "https:")
	}
	return result
}
