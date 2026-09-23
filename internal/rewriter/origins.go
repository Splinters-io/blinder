package rewriter

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// OriginMapper translates only explicitly recognized local origins. Unrelated,
// opaque and malformed origins must reach the target unchanged for valid scans.
// It is immutable after construction and shared by HTTP and WebSocket paths.
type OriginMapper struct {
	clients map[string]bool
	target  url.URL
}

func NewOriginMapper(target *url.URL, listen, alias string) *OriginMapper {
	m := &OriginMapper{clients: make(map[string]bool), target: url.URL{Scheme: target.Scheme, Host: target.Host}}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		port = "443"
	}
	hosts := []string{alias, host}
	if host == "localhost" || host == "" || host == "0.0.0.0" || host == "::" || isLoopback(host) {
		hosts = append(hosts, "localhost", "127.0.0.1", "::1")
	}
	for _, h := range hosts {
		if h == "" || h == "0.0.0.0" || h == "::" {
			continue
		}
		u := &url.URL{Scheme: "https", Host: net.JoinHostPort(h, port)}
		if key := originKey(u); key != "" {
			m.clients[key] = true
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

func (m *OriginMapper) Rewrite(value string, originOnly bool) string {
	if m == nil {
		return value
	}
	u, err := url.Parse(value)
	if err != nil || !m.clients[originKey(u)] {
		return value
	}
	if originOnly && (u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(value, "#")) {
		return value
	}
	u.Scheme, u.Host = m.target.Scheme, m.target.Host
	return u.String()
}
