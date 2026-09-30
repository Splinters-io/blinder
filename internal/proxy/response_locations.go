package proxy

import (
	"net/http"
	"net/url"
	"strings"
)

// Keep same-upstream navigation on the browser's validated entry origin. A
// loopback visitor must not be redirected onto the canonical alias: it may not
// resolve or have client trust, and host-only session cookies would be lost.
// Run after cache/header processing so the shared representation never stores
// one visitor's entry origin for the next visitor.
func (s *Server) localizeResponseLocations(headers http.Header, requestHost string, upstream *url.URL) {
	requestUpstream := s.origins.Load().Resolve(requestHost)
	if upstream == nil || requestUpstream == nil || !sameOrigin(requestUpstream, upstream) {
		return
	}
	for _, name := range []string{"Location", "Content-Location"} {
		for i, value := range headers.Values(name) {
			u, err := url.Parse(value)
			if err != nil || !strings.EqualFold(u.Scheme, "https") || u.User != nil || u.Opaque != "" {
				continue
			}
			locationUpstream := s.origins.Load().Resolve(u.Host)
			if locationUpstream == nil || !sameOrigin(locationUpstream, upstream) {
				continue
			}
			// Retain an absolute HTTPS URL even when its path starts with //;
			// shortening it to a relative reference would change its authority.
			u.Host = requestHost
			headers[name][i] = u.String()
		}
	}
}
