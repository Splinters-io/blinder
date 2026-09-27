package proxy

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Splinters-io/blinder/internal/captcha"
	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/endpoint"
)

func validateOperatorEndpoint(cfg *config.Config) error {
	reserved := func(host string) bool {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		return host == endpoint.OperatorHost || host == endpoint.ChallengeSuffix || strings.HasSuffix(host, "."+endpoint.ChallengeSuffix)
	}
	if reserved(cfg.AliasDomain) || reserved(cfg.TargetURL.Hostname()) {
		return errors.New("the operator hostname cannot be used as a target or alias")
	}
	for _, origin := range cfg.ExtraOrigins {
		if reserved(origin.Hostname()) {
			return errors.New("the operator hostname cannot be used as an extra origin")
		}
	}
	host, _, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return err
	}
	if cfg.Captcha != nil && len(cfg.Captcha.Providers) > 0 {
		ip := net.ParseIP(host)
		if host != "" && host != "localhost" && (ip == nil || (!ip.IsLoopback() && !ip.IsUnspecified())) {
			return errors.New("CAPTCHA operator access requires a loopback or wildcard listen address")
		}
	}
	return nil
}

func operatorOrigin(listen string) string {
	_, port, _ := net.SplitHostPort(listen)
	if n, err := strconv.ParseUint(port, 10, 16); err == nil {
		port = strconv.FormatUint(n, 10)
	}
	if port == "443" {
		return "https://" + endpoint.OperatorHost
	}
	return "https://" + net.JoinHostPort(endpoint.OperatorHost, port)
}

// CaptchaOperatorURL names a separate browser origin, served by the same local
// listener. No target page, service worker or target cookie is served here.
func (s *Server) CaptchaOperatorURL() string {
	return operatorOrigin(s.cfg.ListenAddr) + "/__blinder/captcha/"
}

func (s *Server) routeRequest(w http.ResponseWriter, r *http.Request) {
	if s.providerRoutes != nil && s.providerRoutes.IsAliasHost(r.Host) {
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(peer)
		if err != nil || ip == nil || !ip.IsLoopback() {
			http.Error(w, "provider access is local only", http.StatusForbidden)
			return
		}
		s.providerHandler.ServeHTTP(w, r)
		return
	}
	u, err := url.Parse("https://" + r.Host)
	if err == nil && captcha.HandlesChallengeHost(u.Hostname()) {
		peer, _, peerErr := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(peer)
		if peerErr != nil || ip == nil || !ip.IsLoopback() {
			http.Error(w, "challenge access is local only", http.StatusForbidden)
			return
		}
		s.captchaOperator.ServeChallengeHTTP(w, r)
		return
	}
	operatorHost := err == nil && strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), endpoint.OperatorHost)
	if operatorHost {
		peer, _, peerErr := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(peer)
		if peerErr != nil || ip == nil || !ip.IsLoopback() {
			http.Error(w, "operator access is local only", http.StatusForbidden)
			return
		}
		if !operatorAuthorityMatches(u, s.cfg.ListenAddr) {
			http.Error(w, "unknown operator origin", http.StatusMisdirectedRequest)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/__blinder/captcha/") {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/__blinder/captcha/res" {
			http.NotFound(w, r)
			return
		}
		s.captchaOperator.ServeHTTP(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/__blinder/captcha/") {
		// Neither operator controls nor provider content may be served from a
		// target origin. Provider aliases have already been dispatched above.
		http.NotFound(w, r)
		return
	}
	// Browser host-only cookies already isolate the new operator origin. Also
	// discard legacy credentials and explicit reserved cookies from API clients
	// before HTTP, SRI prefetch, retry or WebSocket forwarding can see them.
	s.handleRequest(w, withoutOperatorCookies(r))
}

func withoutOperatorCookies(r *http.Request) *http.Request {
	var values []string
	changed := false
	for _, value := range r.Header.Values("Cookie") {
		var kept []string
		for _, part := range strings.Split(value, ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if name == captcha.OperatorCookieName || name == "__blinder_op" {
				changed = true
				continue
			}
			kept = append(kept, part)
		}
		if len(kept) > 0 {
			values = append(values, strings.TrimSpace(strings.Join(kept, ";")))
		}
	}
	if !changed {
		return r
	}
	copy := r.Clone(r.Context())
	copy.Header.Del("Cookie")
	for _, value := range values {
		copy.Header.Add("Cookie", value)
	}
	return copy
}

func operatorAuthorityMatches(u *url.URL, listen string) bool {
	if u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !strings.EqualFold(u.Hostname(), endpoint.OperatorHost) || strings.HasSuffix(u.Host, ":") {
		return false
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, err := strconv.ParseUint(port, 10, 16)
	_, configured, _ := net.SplitHostPort(listen)
	want, configuredErr := strconv.ParseUint(configured, 10, 16)
	return err == nil && configuredErr == nil && n != 0 && n == want
}
