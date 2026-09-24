package rewriter

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// OriginRoute pairs an upstream URL with the alias hostname the proxy serves it
// under.
type OriginRoute struct {
	Upstream *url.URL
	Alias    string
}

// OriginMapper translates between local alias origins and upstream target
// origins. It is immutable after construction and shared by HTTP and WebSocket
// paths. For multi-origin deployments, each upstream has its own alias hostname
// and the mapper routes between them.
type OriginMapper struct {
	clientToUpstream map[string]url.URL
	upstreamToLocal  map[string]string
	routes           map[string]*url.URL
	localAddr        string
}

// NewOriginMapper builds an origin mapper for the primary target and any extra
// upstream origins. Each extra origin is served under its own alias hostname.
// Unrelated, opaque and malformed origins reach the target unchanged.
func NewOriginMapper(target *url.URL, listen, alias string, extras ...OriginRoute) *OriginMapper {
	m := &OriginMapper{
		clientToUpstream: make(map[string]url.URL),
		upstreamToLocal:  make(map[string]string),
		routes:           make(map[string]*url.URL),
		localAddr:        listen,
	}

	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		port = "443"
	}

	targetCopy := url.URL{Scheme: target.Scheme, Host: target.Host}

	primaryHosts := []string{alias}
	if host == "localhost" || host == "" || host == "0.0.0.0" || host == "::" || isLoopback(host) {
		primaryHosts = append(primaryHosts, "localhost", "127.0.0.1", "::1")
	}
	if host != "" && host != "0.0.0.0" && host != "::" {
		primaryHosts = append(primaryHosts, host)
	}

	for _, h := range primaryHosts {
		if h == "" || h == "0.0.0.0" || h == "::" {
			continue
		}
		u := &url.URL{Scheme: "https", Host: net.JoinHostPort(h, port)}
		if key := originKey(u); key != "" {
			m.clientToUpstream[key] = targetCopy
		}
	}

	for _, h := range primaryHosts {
		if h != "" && h != "0.0.0.0" && h != "::" {
			m.routes[strings.ToLower(h)] = target
		}
	}

	primaryLocal := (&url.URL{Scheme: "https", Host: net.JoinHostPort(alias, port)}).String()
	if key := originKey(&targetCopy); key != "" {
		m.upstreamToLocal[key] = primaryLocal
	}

	for _, extra := range extras {
		extraCopy := url.URL{Scheme: extra.Upstream.Scheme, Host: extra.Upstream.Host}

		aliasURL := &url.URL{Scheme: "https", Host: net.JoinHostPort(extra.Alias, port)}
		if key := originKey(aliasURL); key != "" {
			m.clientToUpstream[key] = extraCopy
		}

		m.routes[strings.ToLower(extra.Alias)] = extra.Upstream

		localAlias := (&url.URL{Scheme: "https", Host: net.JoinHostPort(extra.Alias, port)}).String()
		if key := originKey(&extraCopy); key != "" {
			m.upstreamToLocal[key] = localAlias
		}
	}

	return m
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func originKey(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Opaque != "" || u.User != nil || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		if strings.HasSuffix(u.Host, ":") {
			return ""
		}
		port = "80"
		if scheme == "https" {
			port = "443"
		}
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return ""
	}
	return scheme + "\x00" + strings.ToLower(u.Hostname()) + "\x00" + strconv.FormatUint(p, 10)
}

// IsKnownFullOrigin returns true if the given URL's full origin (scheme,
// hostname, effective port) matches a known upstream or local alias.
func (m *OriginMapper) IsKnownFullOrigin(u *url.URL) bool {
	if m == nil {
		return false
	}
	key := originKey(u)
	if key == "" {
		return false
	}
	if _, ok := m.upstreamToLocal[key]; ok {
		return true
	}
	if _, ok := m.clientToUpstream[key]; ok {
		return true
	}
	return false
}

// IsKnownOrigin returns true if the given host belongs to a known upstream or
// local alias, meaning the proxy will serve (and scrub) its content.
func (m *OriginMapper) IsKnownOrigin(host string) bool {
	if m == nil {
		return false
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	if m.routes[strings.ToLower(h)] != nil {
		return true
	}
	for key := range m.upstreamToLocal {
		parts := strings.SplitN(key, "\x00", 3)
		if len(parts) >= 2 && parts[1] == strings.ToLower(h) {
			return true
		}
	}
	return false
}

// Resolve returns the upstream URL for the given request Host header, or nil if
// no route matches.
func (m *OriginMapper) Resolve(host string) *url.URL {
	if m == nil {
		return nil
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	return m.routes[strings.ToLower(h)]
}

// Rewrite maps a local proxy URL to the corresponding upstream URL. For
// multi-origin deployments, each alias hostname resolves to its own upstream.
func (m *OriginMapper) Rewrite(value string, originOnly bool) string {
	if m == nil {
		return value
	}
	u, err := url.Parse(value)
	if err != nil {
		return value
	}
	key := originKey(u)
	upstream, ok := m.clientToUpstream[key]
	if !ok {
		return value
	}
	if originOnly && (u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(value, "#")) {
		return value
	}
	u.Scheme, u.Host = upstream.Scheme, upstream.Host
	return u.String()
}

// RewriteUpstreamURL maps a full upstream URL to the corresponding local alias
// URL. If the URL's origin matches a known upstream, the scheme+host+port is
// replaced with the local alias while preserving the path, query and fragment.
// Unrecognised origins are returned unchanged.
func (m *OriginMapper) RewriteUpstreamURL(value string) string {
	if m == nil {
		return value
	}
	u, err := url.Parse(value)
	if err != nil {
		return value
	}
	key := originKey(u)
	if key == "" {
		return value
	}
	if local, ok := m.upstreamToLocal[key]; ok {
		lu, err := url.Parse(local)
		if err != nil {
			return value
		}
		u.Scheme = lu.Scheme
		u.Host = lu.Host
		return u.String()
	}
	return value
}

// RewriteResponseOrigin maps an upstream origin in a response header (such as
// Access-Control-Allow-Origin) back to the local origin the browser used.
// requestOrigin is the Origin header from the inbound request; when it matches
// a known local address for the same upstream, the ACAO echoes it back so
// localhost, 127.0.0.1 and alias-domain clients all get a matching origin.
func (m *OriginMapper) RewriteResponseOrigin(value, requestOrigin string) string {
	if m == nil {
		return value
	}
	if value == "*" || value == "null" {
		return value
	}
	u, err := url.Parse(value)
	if err != nil {
		return value
	}
	upKey := originKey(u)
	if _, ok := m.upstreamToLocal[upKey]; !ok {
		return value
	}
	if requestOrigin != "" {
		ru, err := url.Parse(requestOrigin)
		if err == nil {
			if upstream, ok := m.clientToUpstream[originKey(ru)]; ok {
				if originKey(&upstream) == upKey {
					return requestOrigin
				}
			}
		}
	}
	return m.upstreamToLocal[upKey]
}
