package proxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Splinters-io/blinder/internal/captcha"
	"github.com/Splinters-io/blinder/internal/rewriter"
)

// Configure before serving. Provider origins deliberately never enter the
// target route table, cookie-restoration gate, response cache or SRI pipeline.
func (s *Server) configureProviderRoutes(scheme string) error {
	if s.cfg.Captcha == nil {
		return nil
	}
	if _, port, _ := net.SplitHostPort(s.cfg.ListenAddr); port == "0" {
		return nil
	}
	var routes *captcha.ProviderRoutes
	if s.cfg.UseTor() {
		var err error
		routes, err = captcha.NewProviderRoutes(s.captchaMatcher, scheme, s.cfg.ListenAddr)
		if err != nil {
			return err
		}
	}
	policyOrigins := make(map[string]string)
	for _, route := range routes.Routes() {
		if s.origins.Load().Resolve(route.Local.Host) != nil || strings.EqualFold(route.Local.Hostname(), s.cfg.AliasDomain) {
			return fmt.Errorf("CAPTCHA provider alias collides with a target route")
		}
		if s.origins.Load().IsKnownFullOrigin(route.Upstream) {
			return fmt.Errorf("CAPTCHA provider origin cannot also be a target origin")
		}
		policyOrigins[route.Upstream.String()] = route.Local.String()
	}
	s.providerRoutes = routes
	s.origins.Store(s.origins.Load().WithLocalScheme(scheme).WithPolicyOrigins(policyOrigins))
	mapTargetURL := func(value string, upstream bool) string {
		if upstream {
			value = s.captchaOperator.MapChallengeURL(value)
			return s.origins.Load().Rewrite(value, false)
		}
		return s.origins.Load().RewriteUpstreamURL(value)
	}
	mapTargetOrigin := func(value string, upstream bool) string {
		if upstream {
			value = s.captchaOperator.MapChallengeOrigin(value)
			return s.origins.Load().Rewrite(value, true)
		}
		return s.origins.Load().RewriteResponseOrigin(value, "")
	}
	mapPolicy := func(value string, base *url.URL) string {
		return rewriter.RewriteCSPURLs(value, func(directive, source string) string {
			u, err := url.Parse(source)
			if err != nil || u.User != nil || u.Opaque != "" || u.Scheme == "" || u.Host == "" {
				return source
			}
			for _, route := range routes.Routes() {
				if sameOrigin(u, route.Upstream) {
					u.Scheme, u.Host = route.Local.Scheme, route.Local.Host
					return u.String()
				}
			}
			if directive == "report-uri" {
				return mapTargetURL(source, false)
			}
			return s.origins.Load().PolicySourceAliases(source)
		})
	}
	mapDocumentURL := func(raw string, base *url.URL) (string, bool) {
		u, err := url.Parse(raw)
		if err != nil || u.User != nil || u.Opaque != "" {
			return raw, false
		}
		if base != nil {
			u = base.ResolveReference(u)
		}
		for _, route := range routes.Routes() {
			if sameOrigin(u, route.Upstream) {
				// A base URL need not itself match the resource path regex.
				// Translate its origin; dispatch still checks every request URL.
				u.Scheme, u.Host = route.Local.Scheme, route.Local.Host
				return u.String(), true
			}
		}
		// Provider documents can navigate or submit back to the registered
		// primary/extra target origins. Keep those static URLs on the proxy,
		// using the same target mapping as response Location/Refresh headers.
		if mapped := mapTargetURL(u.String(), false); mapped != u.String() {
			return mapped, true
		}
		return raw, false
	}
	s.captchaOperator.SetChallengeHeaderRewriter(func(headers http.Header, base *url.URL) error {
		if err := rewriteChallengeHeaders(headers, base, func(raw string, base *url.URL) (string, bool) {
			u, err := url.Parse(raw)
			if err != nil || u.User != nil || u.Opaque != "" || base == nil {
				return raw, false
			}
			u = base.ResolveReference(u)
			if u.Scheme != "http" && u.Scheme != "https" {
				return raw, false
			}
			if mapped, ok := routes.RewriteURL(u.String(), nil); ok {
				return mapped, true
			}
			if s.origins.Load().IsKnownFullOrigin(u) {
				return s.origins.Load().RewriteUpstreamURL(u.String()), true
			}
			if s.captchaMatcher.IsProviderResource(u) && (!s.cfg.UseTor() || !s.captchaMatcher.ShouldRouteResource(u)) {
				return u.String(), true
			}
			return raw, false
		}); err != nil {
			return err
		}
		for name, values := range headers {
			if strings.EqualFold(name, "Content-Security-Policy") || strings.EqualFold(name, "Content-Security-Policy-Report-Only") {
				for i, value := range values {
					values[i] = mapPolicy(value, base)
				}
			}
		}
		return nil
	})
	s.captchaOperator.SetProviderRoutes(routes, func(body []byte, base *url.URL, headers http.Header) []byte {
		return rewriter.RewriteOpaqueHTML(body, base, headers.Values("Content-Security-Policy"), mapDocumentURL, func(policy string) string { return mapPolicy(policy, base) })
	})
	if !s.cfg.UseTor() {
		return nil
	}
	s.providerHandler = captcha.NewProviderHandler(captcha.ProviderRelayConfig{
		Routes: routes, Transport: s.transport, Timeout: time.Duration(s.cfg.UpstreamTimeout) * time.Second,
		OperatorToken: s.captchaOperatorToken, MapTargetOrigin: mapTargetOrigin, MapTargetURL: mapTargetURL,
		RestoreMethod: s.gate.RestoreBody,
		RewriteCSP:    mapPolicy,
		RewriteBody: func(body []byte, base *url.URL, headers http.Header) ([]byte, error) {
			if !strings.HasPrefix(strings.ToLower(headers.Get("Content-Type")), "text/html") {
				return body, nil
			}
			encoding := strings.TrimSpace(strings.ToLower(headers.Get("Content-Encoding")))
			decoded := body
			if encoding == "gzip" {
				reader, err := gzip.NewReader(bytes.NewReader(body))
				if err != nil {
					return nil, err
				}
				defer reader.Close()
				decoded, err = io.ReadAll(io.LimitReader(reader, 10*1024*1024+1))
				if err != nil || len(decoded) > 10*1024*1024 {
					return nil, fmt.Errorf("invalid provider HTML encoding")
				}
			} else if encoding != "" && encoding != "identity" {
				return nil, fmt.Errorf("unsupported provider HTML encoding")
			}
			// Relative provider URLs already resolve against the isolated alias.
			// Keep them byte-for-byte unless an upstream base changes the origin.
			mapURL := func(raw string, effectiveBase *url.URL) (string, bool) {
				u, err := url.Parse(raw)
				if err == nil && u.Scheme == "" && u.Host == "" && effectiveBase != nil && effectiveBase.Scheme == base.Scheme && effectiveBase.Host == base.Host {
					return raw, true
				}
				return mapDocumentURL(raw, effectiveBase)
			}
			result := rewriter.RewriteOpaqueHTML(decoded, base, headers.Values("Content-Security-Policy"), mapURL, func(policy string) string { return mapPolicy(policy, base) })
			result = captcha.InjectProviderRoutingRuntime(result, base, routes, headers)
			if bytes.Equal(decoded, result) {
				return body, nil
			}
			headers.Del("Content-Encoding")
			headers.Set("X-Blinder-View", "transformed")
			headers.Set("X-Blinder-Original-Body-Bytes", strconv.Itoa(len(decoded)))
			headers.Set("X-Blinder-Rewritten-Body-Bytes", strconv.Itoa(len(result)))
			return result, nil
		},
	})
	return nil
}
