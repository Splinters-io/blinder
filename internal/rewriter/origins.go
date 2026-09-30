package rewriter

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/Splinters-io/blinder/internal/scrub"
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
	listenPort       string
	localScheme      string
	aliasDomain      string
	aliases          []string
	policyToLocal    map[string]string // Policy-only routes never authorize target/SRI requests.

	// OnDiscover is called when RewriteUpstreamURL encounters an HTTP/HTTPS
	// origin that is not yet registered. The callback should register the
	// origin and return the local alias URL (e.g. "https://host-xx.alias:port").
	// A nil callback or empty return leaves the URL unchanged.
	OnDiscover func(upstream *url.URL) string
}

// WithPolicyOrigins adds source-expression translations without giving those
// origins target routing, cookie restoration, cache, or SRI privileges.
func (m *OriginMapper) WithPolicyOrigins(origins map[string]string) *OriginMapper {
	view := *m
	view.policyToLocal = make(map[string]string, len(origins))
	for upstream, local := range origins {
		u, err := url.Parse(upstream)
		if err == nil && originKey(u) != "" {
			view.policyToLocal[originKey(u)] = local
		}
	}
	return &view
}

// WithLocalScheme selects the actual downstream scheme for an embedded HTTP
// listener. CLI listeners use HTTPS. Upstream origins and routing stay fixed.
func (m *OriginMapper) WithLocalScheme(scheme string) *OriginMapper {
	if m == nil || (scheme != "http" && scheme != "https") {
		return m
	}
	view := *m
	view.localScheme = scheme
	view.clientToUpstream = make(map[string]url.URL, len(m.clientToUpstream))
	for key, upstream := range m.clientToUpstream {
		parts := strings.Split(key, "\x00")
		parts[0] = scheme
		view.clientToUpstream[strings.Join(parts, "\x00")] = upstream
	}
	view.upstreamToLocal = make(map[string]string, len(m.upstreamToLocal))
	for key, local := range m.upstreamToLocal {
		u, err := url.Parse(local)
		if err == nil {
			u.Scheme = scheme
			local = u.String()
		}
		view.upstreamToLocal[key] = local
	}
	return &view
}

func (m *OriginMapper) rewritePolicySource(value string) string {
	if m == nil {
		return value
	}
	u, err := url.Parse(value)
	if err != nil || u.User != nil {
		return value
	}
	if local, ok := m.policyToLocal[originKey(u)]; ok {
		mapped, err := url.Parse(local)
		if err == nil {
			u.Scheme, u.Host = mapped.Scheme, mapped.Host
			return u.String()
		}
	}
	return value
}

// PolicySourceAliases returns the local inverse of an exact upstream URL
// source. A primary target may be entered through loopback or its named alias;
// each of those origins represents the same original policy permission.
// Separate target/provider origins are never included in that permission.
func (m *OriginMapper) PolicySourceAliases(value string) string {
	if m == nil {
		return value
	}
	u, err := url.Parse(value)
	if err != nil || u.User != nil || originKey(u) == "" {
		return value
	}
	want := originKey(u)
	var sources []string
	for key, upstream := range m.clientToUpstream {
		if originKey(&upstream) != want {
			continue
		}
		parts := strings.Split(key, "\x00")
		mapped := *u
		mapped.Scheme, mapped.Host = parts[0], net.JoinHostPort(parts[1], parts[2])
		sources = append(sources, mapped.String())
	}
	if len(sources) == 0 {
		return value
	}
	sort.Strings(sources)
	return strings.Join(sources, " ")
}

// NewOriginMapper builds an origin mapper for the primary target and any extra
// upstream origins. Each extra origin is served under its own alias hostname.
// Unrelated, opaque and malformed origins reach the target unchanged. Returns
// an error if two routes would claim the same hostname.
func NewOriginMapper(target *url.URL, listen, alias string, extras ...OriginRoute) (*OriginMapper, error) {
	m := &OriginMapper{
		clientToUpstream: make(map[string]url.URL),
		upstreamToLocal:  make(map[string]string),
		routes:           make(map[string]*url.URL),
		localAddr:        listen,
		localScheme:      "https",
		aliasDomain:      alias,
	}

	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		port = "443"
	}
	// Origin keys already compare numeric effective ports. Use the same form
	// for routing so an explicit leading zero cannot split the two models.
	if number, err := strconv.ParseUint(port, 10, 16); err == nil {
		port = strconv.FormatUint(number, 10)
	}
	m.listenPort = port

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

	if alias != "" {
		m.aliases = append(m.aliases, alias)
	}

	primaryLocal := (&url.URL{Scheme: "https", Host: net.JoinHostPort(alias, port)}).String()
	if key := originKey(&targetCopy); key != "" {
		m.upstreamToLocal[key] = primaryLocal
	}

	for _, extra := range extras {
		lowerAlias := strings.ToLower(extra.Alias)
		if prev, ok := m.routes[lowerAlias]; ok {
			return nil, fmt.Errorf("route collision: %s and %s both claim hostname %s", prev.Host, extra.Upstream.Host, extra.Alias)
		}

		extraCopy := url.URL{Scheme: extra.Upstream.Scheme, Host: extra.Upstream.Host}

		aliasURL := &url.URL{Scheme: "https", Host: net.JoinHostPort(extra.Alias, port)}
		if key := originKey(aliasURL); key != "" {
			m.clientToUpstream[key] = extraCopy
		}

		m.routes[lowerAlias] = extra.Upstream
		m.aliases = append(m.aliases, extra.Alias)

		localAlias := (&url.URL{Scheme: "https", Host: net.JoinHostPort(extra.Alias, port)}).String()
		if key := originKey(&extraCopy); key != "" {
			m.upstreamToLocal[key] = localAlias
		}
	}

	return m, nil
}

// Register adds an upstream origin to the mapper, returning a new mapper that
// includes the origin and the alias hostname assigned to it. The receiver is
// not modified. If the origin is already registered, the receiver is returned
// unchanged with the existing alias.
func (m *OriginMapper) Register(upstream *url.URL) (*OriginMapper, string) {
	upCopy := url.URL{Scheme: upstream.Scheme, Host: upstream.Host}
	key := originKey(&upCopy)
	if key == "" {
		return m, ""
	}
	if _, ok := m.upstreamToLocal[key]; ok {
		for _, a := range m.aliases {
			expected := scrub.AliasOrigin(upstream.Scheme, upstream.Hostname(), upstream.Port(), m.aliasDomain)
			if a == expected {
				return m, a
			}
		}
		return m, ""
	}

	alias := scrub.AliasOrigin(upstream.Scheme, upstream.Hostname(), upstream.Port(), m.aliasDomain)

	next := &OriginMapper{
		clientToUpstream: make(map[string]url.URL, len(m.clientToUpstream)+1),
		upstreamToLocal:  make(map[string]string, len(m.upstreamToLocal)+1),
		routes:           make(map[string]*url.URL, len(m.routes)+1),
		localAddr:        m.localAddr,
		listenPort:       m.listenPort,
		localScheme:      m.localScheme,
		aliasDomain:      m.aliasDomain,
		aliases:          make([]string, len(m.aliases), len(m.aliases)+1),
		OnDiscover:       m.OnDiscover,
	}
	for k, v := range m.clientToUpstream {
		next.clientToUpstream[k] = v
	}
	for k, v := range m.upstreamToLocal {
		next.upstreamToLocal[k] = v
	}
	for k, v := range m.routes {
		next.routes[k] = v
	}
	copy(next.aliases, m.aliases)
	if m.policyToLocal != nil {
		next.policyToLocal = make(map[string]string, len(m.policyToLocal))
		for k, v := range m.policyToLocal {
			next.policyToLocal[k] = v
		}
	}

	lowerAlias := strings.ToLower(alias)
	aliasURL := &url.URL{Scheme: next.localScheme, Host: net.JoinHostPort(alias, next.listenPort)}
	if aKey := originKey(aliasURL); aKey != "" {
		next.clientToUpstream[aKey] = upCopy
	}
	next.routes[lowerAlias] = &url.URL{Scheme: upCopy.Scheme, Host: upCopy.Host}
	next.aliases = append(next.aliases, alias)
	localAlias := (&url.URL{Scheme: next.localScheme, Host: net.JoinHostPort(alias, next.listenPort)}).String()
	next.upstreamToLocal[key] = localAlias

	return next, alias
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

// IsRoutedHostname returns true if the given hostname (without port) is
// registered as a routing target in this mapper.
func (m *OriginMapper) IsRoutedHostname(hostname string) bool {
	if m == nil {
		return false
	}
	return m.routes[strings.ToLower(hostname)] != nil
}

// Resolve returns the upstream URL for the given request Host header, or nil if
// no route matches. The port in the Host header must match the listen port; a
// bare hostname (no port) is accepted only when the listen port is 443.
func (m *OriginMapper) Resolve(host string) *url.URL {
	if m == nil {
		return nil
	}
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		h = host
		if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") && net.ParseIP(h[1:len(h)-1]) != nil {
			h = h[1 : len(h)-1]
		} else if strings.ContainsAny(h, ":[]") {
			return nil
		}
		defaultPort := "443"
		if m.localScheme == "http" {
			defaultPort = "80"
		}
		if m.listenPort != defaultPort && m.listenPort != "0" {
			return nil
		}
	} else {
		number, parseErr := strconv.ParseUint(p, 10, 16)
		if parseErr != nil || number == 0 {
			return nil
		}
		if m.listenPort != "0" && strconv.FormatUint(number, 10) != m.listenPort {
			return nil
		}
	}
	return m.routes[strings.ToLower(h)]
}

// ForRequestHost returns an immutable mapping view for a validated browser
// entry authority. Only that route's upstream-to-local mapping changes; extra
// origins retain their separate aliases. Unknown authorities cannot create a
// route, and the shared mapper is never modified.
func (m *OriginMapper) ForRequestHost(host string) *OriginMapper {
	upstream := m.Resolve(host)
	if upstream == nil {
		return nil
	}
	view := *m
	view.upstreamToLocal = make(map[string]string, len(m.upstreamToLocal))
	for key, value := range m.upstreamToLocal {
		view.upstreamToLocal[key] = value
	}
	view.upstreamToLocal[originKey(upstream)] = (&url.URL{Scheme: m.localScheme, Host: host}).String()
	return &view
}

// RestoreResourceURL reverses a complete local resource URL submitted as an
// application value. Only the registered TLS local origins are recognized;
// unknown schemes, authorities, ports, userinfo and opaque URLs are unchanged.
// Preserve the suffix verbatim so encoded segments and empty query/fragment
// markers are not normalized while restoring the origin.
func (m *OriginMapper) RestoreResourceURL(value string) string {
	if m == nil {
		return value
	}
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.Opaque != "" {
		return value
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "wss" {
		return value
	}
	upstream := m.Resolve(u.Host)
	if upstream == nil {
		return value
	}
	upstreamScheme := upstream.Scheme
	if scheme == "wss" {
		switch strings.ToLower(upstreamScheme) {
		case "http":
			upstreamScheme = "ws"
		case "https":
			upstreamScheme = "wss"
		default:
			return value
		}
	}
	start := strings.Index(value, "://")
	if start < 0 {
		return value
	}
	start += 3
	suffix := ""
	if end := strings.IndexAny(value[start:], "/?#"); end >= 0 {
		suffix = value[start+end:]
	}
	return upstreamScheme + "://" + upstream.Host + suffix
}

// RouteAliases returns the alias hostnames registered in this mapper, suitable
// for TLS SAN generation. The primary alias is first, followed by any extra
// origin aliases.
func (m *OriginMapper) RouteAliases() []string {
	if m == nil {
		return nil
	}
	out := make([]string, len(m.aliases))
	copy(out, m.aliases)
	return out
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

// RewriteKnownUpstreamURL is like RewriteUpstreamURL but never triggers origin
// discovery. Use it for policy sources (CSP) and other contexts where an
// unrecognised URL should pass through unchanged rather than register a new
// origin.
func (m *OriginMapper) RewriteKnownUpstreamURL(value string) string {
	return m.rewriteUpstream(value, false)
}

// RewriteUpstreamURL maps a full upstream URL to the corresponding local alias
// URL. If the URL's origin matches a known upstream, the scheme+host+port is
// replaced with the local alias while preserving the path, query and fragment.
// Unrecognised origins are returned unchanged.
func (m *OriginMapper) RewriteUpstreamURL(value string) string {
	return m.rewriteUpstream(value, true)
}

func (m *OriginMapper) rewriteUpstream(value string, discover bool) string {
	if m == nil {
		return value
	}
	protoRelative := strings.HasPrefix(value, "//") && (len(value) < 3 || value[2] != '/')
	lookup := value
	if protoRelative {
		lookup = "https:" + value
	}
	u, err := url.Parse(lookup)
	if err != nil {
		return value
	}
	key := originKey(u)
	if key == "" {
		return value
	}
	local, ok := m.upstreamToLocal[key]
	if !ok && discover && m.OnDiscover != nil {
		if _, isLocal := m.clientToUpstream[key]; !isLocal {
			scheme := strings.ToLower(u.Scheme)
			if scheme == "http" || scheme == "https" {
				local = m.OnDiscover(u)
				ok = local != ""
			}
		}
	}
	if !ok {
		return value
	}
	lu, err := url.Parse(local)
	if err != nil {
		return value
	}
	rewritten := *u
	rewritten.Scheme = lu.Scheme
	rewritten.Host = lu.Host
	result := rewritten.String()
	if protoRelative {
		result = strings.TrimPrefix(result, "https:")
	}
	return result
}

// RewriteWebSocketURL maps an explicitly registered ws/wss upstream origin to
// its TLS local alias. HTTP-equivalent schemes are used only for route lookup;
// this does not authorize WebSocket URLs for HTTP or SRI resource fetching.
func (m *OriginMapper) RewriteWebSocketURL(value string) string {
	if m == nil {
		return value
	}
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.Opaque != "" {
		return value
	}
	lookup := *u
	switch strings.ToLower(u.Scheme) {
	case "ws":
		lookup.Scheme = "http"
	case "wss":
		lookup.Scheme = "https"
	default:
		return value
	}
	key := originKey(&lookup)
	local, ok := m.upstreamToLocal[key]
	if key == "" || !ok {
		return value
	}
	alias, err := url.Parse(local)
	if err != nil {
		return value
	}
	// Keep the source suffix verbatim, including escaped path spelling, query
	// order, and empty query/fragment markers. Only scheme and authority change.
	authorityStart := strings.Index(value, "://") + 3
	if authorityStart < 3 {
		return value
	}
	suffix := ""
	if end := strings.IndexAny(value[authorityStart:], "/?#"); end >= 0 {
		suffix = value[authorityStart+end:]
	}
	return "wss://" + alias.Host + suffix
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
	// CORS compares a serialized origin, not an arbitrary URL's origin tuple.
	// Never repair a path, empty query/fragment, or noncanonical spelling into
	// a permission the original response did not grant.
	if !isSerializedOrigin(value, u) {
		return value
	}
	upKey := originKey(u)
	if _, ok := m.upstreamToLocal[upKey]; !ok {
		return value
	}
	if requestOrigin != "" {
		ru, err := url.Parse(requestOrigin)
		if err == nil && isSerializedOrigin(requestOrigin, ru) {
			if upstream, ok := m.clientToUpstream[originKey(ru)]; ok {
				if originKey(&upstream) == upKey {
					return requestOrigin
				}
			}
		}
	}
	return m.upstreamToLocal[upKey]
}

func isSerializedOrigin(value string, u *url.URL) bool {
	key := originKey(u)
	if key == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(value, "#") {
		return false
	}
	parts := strings.Split(key, "\x00")
	scheme, host, port := parts[0], parts[1], parts[2]
	for _, c := range host {
		if c > 127 {
			return false
		} // Browser origins use ASCII host serialization.
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	} else {
		host = net.JoinHostPort(host, port)
	}
	return value == scheme+"://"+host
}
