package captcha

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// ProviderRoute keeps CAPTCHA resources on a browser origin distinct from both
// the target and the operator. The alias is stable for the complete upstream
// origin, including scheme and effective port. It does not reproduce upstream
// registrable-domain or domain-cookie relationships.
type ProviderRoute struct {
	Upstream *url.URL
	Local    *url.URL
}

// ProviderRoutes is immutable after construction. Resource regexes remain the
// authority for individual URLs; registering an origin never grants its whole
// URL namespace.
type ProviderRoutes struct {
	matcher    *Matcher
	routes     []ProviderRoute
	byUpstream map[string]int
	byLocal    map[string]int
	byHost     map[string]int
}

func NewProviderRoutes(m *Matcher, localScheme, listen string) (*ProviderRoutes, error) {
	if localScheme != "http" && localScheme != "https" {
		return nil, fmt.Errorf("CAPTCHA local scheme must be http or https")
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, fmt.Errorf("CAPTCHA listen address: %w", err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, fmt.Errorf("CAPTCHA listen address requires an allocated port")
	}
	port = strconv.Itoa(portNumber)
	r := &ProviderRoutes{matcher: m, byUpstream: make(map[string]int), byLocal: make(map[string]int), byHost: make(map[string]int)}
	if m == nil {
		return r, nil
	}
	seen := make(map[string]*url.URL)
	for _, p := range m.providers {
		if p.TorPolicy == TorPolicyDirect {
			continue
		}
		for _, raw := range p.ResourceOrigins {
			u, err := parseResourceOrigin(raw)
			if err != nil {
				return nil, fmt.Errorf("CAPTCHA provider %q: %w", p.Name, err)
			}
			seen[u.String()] = u
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		digest := sha256.Sum256([]byte(key))
		host := "captcha-" + hex.EncodeToString(digest[:16]) + ".localhost"
		if _, exists := r.byHost[host]; exists {
			return nil, fmt.Errorf("CAPTCHA provider alias collision")
		}
		local := &url.URL{Scheme: localScheme, Host: host}
		if port != effectivePort(local) {
			local.Host = net.JoinHostPort(host, port)
		}
		i := len(r.routes)
		r.routes = append(r.routes, ProviderRoute{Upstream: seen[key], Local: local})
		r.byUpstream[key], r.byLocal[local.String()], r.byHost[host] = i, i, i
	}
	return r, nil
}

func (r *ProviderRoutes) AliasHosts() []string {
	if r == nil {
		return nil
	}
	out := make([]string, len(r.routes))
	for i, route := range r.routes {
		out[i] = route.Local.Hostname()
	}
	return out
}

func (r *ProviderRoutes) Routes() []ProviderRoute {
	if r == nil {
		return nil
	}
	out := make([]ProviderRoute, len(r.routes))
	for i, route := range r.routes {
		upstream, local := *route.Upstream, *route.Local
		out[i] = ProviderRoute{Upstream: &upstream, Local: &local}
	}
	return out
}

func (r *ProviderRoutes) RewriteURL(raw string, base *url.URL) (string, bool) {
	if r == nil || r.matcher == nil {
		return raw, false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw, false
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	key, ok := resourceURLOrigin(u)
	if !ok || !r.matcher.ShouldRouteResource(u) {
		return raw, false
	}
	i, ok := r.byUpstream[key]
	if !ok {
		return raw, false
	}
	u.Scheme, u.Host = r.routes[i].Local.Scheme, r.routes[i].Local.Host
	return u.String(), true
}

// IsAliasHost recognizes registered hosts even when the supplied port is wrong.
// This lets the caller reject an invalid provider request before target routing.
func (r *ProviderRoutes) IsAliasHost(authority string) bool {
	if r == nil {
		return false
	}
	host := authority
	if strings.Contains(authority, ":") {
		var err error
		host, _, err = net.SplitHostPort(authority)
		if err != nil {
			// A malformed port must not turn a recognized provider host into a
			// target request. Provider aliases contain no colons themselves.
			host = strings.SplitN(authority, ":", 2)[0]
		}
	}
	_, ok := r.byHost[strings.ToLower(host)]
	return ok
}

func (r *ProviderRoutes) Resolve(req *http.Request) (*url.URL, bool) {
	if r == nil || r.matcher == nil || req == nil || req.URL == nil {
		return nil, false
	}
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	local, err := parseResourceOrigin(scheme + "://" + req.Host)
	if err != nil {
		return nil, false
	}
	i, ok := r.byLocal[local.String()]
	if !ok || req.URL.User != nil || req.URL.Opaque != "" {
		return nil, false
	}
	if req.URL.Scheme != "" && !strings.EqualFold(req.URL.Scheme, scheme) {
		return nil, false
	}
	if req.URL.Host != "" {
		absolute, err := parseResourceOrigin(scheme + "://" + req.URL.Host)
		if err != nil || absolute.String() != local.String() {
			return nil, false
		}
	}
	u := *req.URL
	u.Scheme, u.Host = r.routes[i].Upstream.Scheme, r.routes[i].Upstream.Host
	if !r.matcher.ShouldRouteResource(&u) {
		return nil, false
	}
	return &u, true
}

// MapOrigin translates a serialized origin only. It deliberately leaves null,
// wildcard, malformed, and unrelated origins unchanged.
func (r *ProviderRoutes) MapOrigin(raw string, toUpstream bool) string {
	if r == nil {
		return raw
	}
	u, err := parseResourceOrigin(raw)
	if err != nil || u.String() != raw {
		return raw
	}
	if toUpstream {
		if i, ok := r.byLocal[u.String()]; ok {
			return r.routes[i].Upstream.String()
		}
	} else if i, ok := r.byUpstream[u.String()]; ok {
		return r.routes[i].Local.String()
	}
	return raw
}

func resourceURLOrigin(u *url.URL) (string, bool) {
	if u == nil || u.User != nil || u.Opaque != "" {
		return "", false
	}
	origin, err := parseResourceOrigin(u.Scheme + "://" + u.Host)
	if err != nil {
		return "", false
	}
	return origin.String(), true
}

// parseResourceOrigin accepts only a complete HTTP(S) origin, never a URL prefix
// or wildcard. Default ports and case have one canonical spelling for hashing.
func parseResourceOrigin(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	invalid := func() (*url.URL, error) { return nil, fmt.Errorf("invalid resource origin %q", raw) }
	if err != nil || u == nil || u.Opaque != "" || u.User != nil || u.Host == "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return invalid()
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return invalid()
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.ContainsAny(host, "%*\\") {
		return invalid()
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.String()
	} else {
		if len(host) > 253 || strings.Contains(host, ":") {
			return invalid()
		}
		for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return invalid()
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return invalid()
				}
			}
		}
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return invalid()
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return invalid()
		}
		port = strconv.Itoa(n)
		if u.Scheme == "http" && port == "80" || u.Scheme == "https" && port == "443" {
			port = ""
		}
	}
	u.Host = host
	if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	}
	return u, nil
}
