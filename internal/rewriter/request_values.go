package rewriter

import (
	"net/url"
	"strings"

	"github.com/Splinters-io/blinder/internal/scrub"
)

// RestoreResourceValue reverses one decoded functional value. Complete local
// resource origins are restored before aliases, retaining upstream scheme and
// port. A local route with an unrecognized scheme/port must not be partially
// restored by substituting its hostname alone.
func RestoreResourceValue(value string, gate *scrub.Gate, origins *OriginMapper) string {
	mapped := origins.RestoreResourceURL(value)
	protectAuthority := mapped != value
	if !protectAuthority && origins != nil {
		if u, err := url.Parse(value); err == nil && u.Host != "" && u.Scheme != "" {
			_, protectAuthority = origins.routes[strings.ToLower(u.Hostname())]
		}
	}
	if protectAuthority {
		if start := strings.Index(mapped, "://"); start >= 0 {
			start += 3
			if end := strings.IndexAny(mapped[start:], "/?#"); end >= 0 {
				boundary := start + end
				return mapped[:boundary] + gate.RestoreBody(mapped[boundary:])
			}
			return mapped
		}
	}
	return gate.RestoreBody(value)
}
