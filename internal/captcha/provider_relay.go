package captcha

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Splinters-io/blinder/internal/urlutil"
)

// ProviderRelayConfig serves provider aliases independently of the operator and
// target. Cookie state belongs to the browser's provider origin, so ordinary
// widgets and simultaneous challenges share the same session as on the site.
// The caller validates loopback access and dispatches only provider authorities.
type ProviderRelayConfig struct {
	Routes          *ProviderRoutes
	Transport       http.RoundTripper
	Timeout         time.Duration
	OperatorToken   string
	MapTargetOrigin func(value string, toUpstream bool) string
	MapTargetURL    func(value string, toUpstream bool) string
	// RestoreMethod reverses an issued alias in a protocol method without
	// exempting that value from the target document's identity masking.
	RestoreMethod func(string) string
	// RewriteBody receives response bytes and mutable cloned headers. A caller
	// decoding content encodings must keep those headers consistent with output.
	// Nil preserves bytes exactly; no runtime or replacement CSP is injected.
	RewriteBody func(body []byte, upstream *url.URL, headers http.Header) ([]byte, error)
	RewriteCSP  func(policy string, upstream *url.URL) string
}

type ProviderHandler struct{ cfg ProviderRelayConfig }

func NewProviderHandler(cfg ProviderRelayConfig) *ProviderHandler {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &ProviderHandler{cfg: cfg}
}

func (h *ProviderHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !validHTTPMethod(r.Method) {
		http.Error(w, "invalid method", http.StatusBadRequest)
		return
	}
	if h.cfg.Routes == nil {
		http.Error(w, "unknown provider origin", http.StatusMisdirectedRequest)
		return
	}
	upstream, ok := h.cfg.Routes.Resolve(r)
	if !ok {
		http.Error(w, "resource outside provider scope", http.StatusForbidden)
		return
	}
	if h.cfg.Transport == nil {
		http.Error(w, "no provider transport configured", http.StatusServiceUnavailable)
		return
	}
	bodyReader := r.Body
	if bodyReader == nil {
		bodyReader = http.NoBody
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, bodyReader, 2*1024*1024))
	if err != nil {
		status := http.StatusBadRequest
		if _, oversized := err.(*http.MaxBytesError); oversized {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, "invalid provider request body", status)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.Timeout)
	defer cancel()
	request := r.Clone(ctx)
	if h.cfg.RestoreMethod != nil {
		request.Method = h.cfg.RestoreMethod(r.Method)
		if !validHTTPMethod(request.Method) {
			http.Error(w, "invalid restored method", http.StatusBadRequest)
			return
		}
	}
	request.URL = cloneProviderURL(upstream)
	request.Host = upstream.Host
	request.RequestURI = ""
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	request.TransferEncoding = nil
	request.Trailer = nil
	request.Close = false
	stripProviderHopHeaders(request.Header)
	request.Header.Del("Content-Length")
	filterProviderRequestCredentials(request.Header, h.cfg.OperatorToken)
	if h.cfg.RewriteBody != nil {
		// HTML rewriting supports identity and gzip. Do not offer browser
		// encodings such as br/zstd that this response path cannot decode.
		request.Header.Set("Accept-Encoding", "gzip, identity")
	}
	var browserPreflightMethod, upstreamPreflightMethod string
	if methods := request.Header.Values("Access-Control-Request-Method"); len(methods) > 0 {
		if len(methods) != 1 || !validHTTPMethod(methods[0]) {
			http.Error(w, "invalid preflight method", http.StatusBadRequest)
			return
		}
		browserPreflightMethod, upstreamPreflightMethod = methods[0], methods[0]
		if h.cfg.RestoreMethod != nil {
			upstreamPreflightMethod = h.cfg.RestoreMethod(browserPreflightMethod)
			if !validHTTPMethod(upstreamPreflightMethod) {
				http.Error(w, "invalid restored preflight method", http.StatusBadRequest)
				return
			}
		}
		request.Header.Set("Access-Control-Request-Method", upstreamPreflightMethod)
	}
	mapProviderHeader(request.Header, "Origin", func(value string) string { return h.mapOrigin(value, true) })
	mapProviderHeader(request.Header, "Referer", func(value string) string { return h.mapURL(value, true) })

	// OPTIONS and CORS preflights are ordinary upstream requests here. The
	// provider's status, allow headers and denials are not manufactured locally.
	response, err := h.cfg.Transport.RoundTrip(request)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		http.Error(w, "provider fetch failed", http.StatusBadGateway)
		return
	}
	if response == nil {
		http.Error(w, "provider fetch failed", http.StatusBadGateway)
		return
	}
	if response.Body == nil {
		response.Body = http.NoBody
	}
	defer response.Body.Close()
	headers := make(http.Header)
	for name, values := range response.Header {
		key := http.CanonicalHeaderKey(name)
		headers[key] = append(headers[key], values...)
	}
	stripProviderHopHeaders(headers)
	if browserPreflightMethod != upstreamPreflightMethod {
		mapProviderHeader(headers, "Access-Control-Allow-Methods", func(value string) string {
			return translateProviderAllowMethods(value, browserPreflightMethod, upstreamPreflightMethod)
		})
	}
	mapProviderHeader(headers, "Access-Control-Allow-Origin", func(value string) string {
		mapped := h.mapOrigin(value, false)
		originalOrigins, sentOrigins := r.Header.Values("Origin"), request.Header.Values("Origin")
		if len(originalOrigins) == 1 && len(sentOrigins) == 1 && originalOrigins[0] != sentOrigins[0] {
			// The target may be entered through loopback or its configured
			// alias. Echo only the exact local origin represented by the
			// provider's actual ACAO, never create a new permission. Swap a
			// literal local-origin grant away too: it did not authorize the
			// original upstream requesting origin.
			if value == sentOrigins[0] {
				return originalOrigins[0]
			}
			if value == originalOrigins[0] {
				return sentOrigins[0]
			}
		}
		return mapped
	})
	mapProviderHeader(headers, "Content-Location", func(value string) string {
		if mapped, ok := h.mapResponseURL(value, upstream); ok {
			return mapped
		}
		return value
	})
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		for i, location := range headers.Values("Location") {
			mapped, allowed := h.mapResponseURL(location, upstream)
			if !allowed {
				http.Error(w, "provider redirect outside configured scope", http.StatusBadGateway)
				return
			}
			headers["Location"][i] = mapped
		}
	}
	for i, refresh := range headers.Values("Refresh") {
		rejected := false
		mapped, accepted := urlutil.RewriteRefresh(refresh, func(value string) (string, bool) {
			result, allowed := h.mapResponseURL(value, upstream)
			rejected = !allowed
			return result, allowed
		})
		if rejected {
			http.Error(w, "provider refresh outside configured scope", http.StatusBadGateway)
			return
		}
		if accepted {
			headers["Refresh"][i] = mapped
		}
	}
	mapProviderCookies(headers, upstream.Hostname())
	var responseBody []byte
	withBody := request.Method != http.MethodHead && providerResponseHasBody(response.StatusCode)
	if withBody {
		const maxResponse = 10 * 1024 * 1024
		responseBody, err = io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
		if err != nil || len(responseBody) > maxResponse {
			http.Error(w, "provider response read failed", http.StatusBadGateway)
			return
		}
		if h.cfg.RewriteBody != nil {
			original := append([]byte(nil), responseBody...)
			responseBody, err = h.cfg.RewriteBody(responseBody, upstream, headers)
			if err != nil {
				http.Error(w, "provider response rewrite failed", http.StatusBadGateway)
				return
			}
			if !bytes.Equal(original, responseBody) {
				for _, name := range []string{"ETag", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest"} {
					headers.Del(name)
				}
			}
		}
		headers.Set("Content-Length", strconv.Itoa(len(responseBody)))
	} else if response.StatusCode == http.StatusNoContent || response.StatusCode < 200 {
		// A 304 or HEAD may report the selected representation's length, but
		// informational and 204 responses cannot carry Content-Length.
		headers.Del("Content-Length")
	}
	// Body URL/base processing needs the original enforcing policies. Map
	// their origins only after the callback has finished using those values.
	for _, name := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		if h.cfg.RewriteCSP != nil {
			mapProviderHeader(headers, name, func(value string) string { return h.cfg.RewriteCSP(value, upstream) })
		}
	}
	for name, values := range headers {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.WriteHeader(response.StatusCode)
	if withBody {
		_, _ = w.Write(responseBody)
	}
}

func cloneProviderURL(u *url.URL) *url.URL { result := *u; return &result }

// CORS method matching is case-sensitive. Exchange the request's original and
// local spelling rather than adding a grant: an upstream literal equal to the
// local alias must not newly authorize the restored method. Keep wildcard and
// list formatting unchanged.
func translateProviderAllowMethods(value, browser, upstream string) string {
	parts := strings.Split(value, ",")
	for i, part := range parts {
		method := strings.Trim(part, " \t")
		if method == "*" {
			continue
		}
		replacement := method
		if method == upstream {
			replacement = browser
		} else if method == browser {
			replacement = upstream
		}
		if replacement != method {
			start := len(part) - len(strings.TrimLeft(part, " \t"))
			parts[i] = part[:start] + replacement + part[start+len(method):]
		}
	}
	return strings.Join(parts, ",")
}

func providerResponseHasBody(status int) bool { return status >= 200 && status != 204 && status != 304 }

func mapProviderHeader(headers http.Header, name string, transform func(string) string) {
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		for i, value := range values {
			headers[key][i] = transform(value)
		}
	}
}

func stripProviderHopHeaders(headers http.Header) {
	for _, connection := range headers.Values("Connection") {
		for _, token := range strings.Split(connection, ",") {
			headers.Del(strings.TrimSpace(token))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		headers.Del(name)
	}
}

func filterProviderRequestCredentials(headers http.Header, operatorToken string) {
	var cookies []string
	for _, value := range headers.Values("Cookie") {
		var kept []string
		for _, item := range strings.Split(value, ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(item), "=")
			if name != OperatorCookieName && name != "__blinder_op" {
				kept = append(kept, strings.TrimSpace(item))
			}
		}
		if len(kept) > 0 {
			cookies = append(cookies, strings.Join(kept, "; "))
		}
	}
	headers.Del("Cookie")
	for _, value := range cookies {
		headers.Add("Cookie", value)
	}
	if operatorToken == "" {
		return
	}
	var auth []string
	for _, value := range headers.Values("Authorization") {
		fields := strings.Fields(value)
		if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") && fields[1] == operatorToken {
			continue
		}
		auth = append(auth, value)
	}
	headers.Del("Authorization")
	for _, value := range auth {
		headers.Add("Authorization", value)
	}
}

func mapProviderCookies(headers http.Header, upstreamHost string) {
	values := headers.Values("Set-Cookie")
	headers.Del("Set-Cookie")
	for _, value := range values {
		cookie, err := http.ParseSetCookie(value)
		if err != nil {
			continue
		}
		if cookie.Name == OperatorCookieName || cookie.Name == "__blinder_op" {
			continue
		}
		// Wider parent-domain sharing requires an explicit site topology model.
		// Do not give a provider cookie access to unrelated local aliases.
		if cookie.Domain != "" && !strings.EqualFold(strings.TrimPrefix(cookie.Domain, "."), upstreamHost) {
			continue
		}
		// Removing Domain must not repair an originally invalid __Host cookie.
		if strings.HasPrefix(cookie.Name, "__Host-") && (cookie.Domain != "" || !cookie.Secure || cookie.Path != "/") {
			continue
		}
		// Preserve all other attributes, including extensions the current Go
		// parser does not understand. Only the Domain attribute changes.
		parts := strings.Split(value, ";")
		kept := parts[:1]
		for _, part := range parts[1:] {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if !strings.EqualFold(name, "domain") {
				kept = append(kept, part)
			}
		}
		headers.Add("Set-Cookie", strings.Join(kept, ";"))
	}
}

func (h *ProviderHandler) mapOrigin(value string, toUpstream bool) string {
	if mapped := h.cfg.Routes.MapOrigin(value, toUpstream); mapped != value {
		return mapped
	}
	if h.cfg.MapTargetOrigin != nil {
		return h.cfg.MapTargetOrigin(value, toUpstream)
	}
	return value
}

func (h *ProviderHandler) mapURL(value string, toUpstream bool) string {
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.Opaque != "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return value
	}
	origin := u.Scheme + "://" + u.Host
	if mapped := h.cfg.Routes.MapOrigin(origin, toUpstream); mapped != origin {
		return mapped + strings.TrimPrefix(value, origin)
	}
	if h.cfg.MapTargetURL != nil {
		return h.cfg.MapTargetURL(value, toUpstream)
	}
	return value
}

func (h *ProviderHandler) mapResponseURL(value string, upstream *url.URL) (string, bool) {
	if mapped, ok := h.cfg.Routes.RewriteURL(value, upstream); ok {
		return mapped, true
	}
	resolved, err := upstream.Parse(value)
	if err != nil || resolved.User != nil {
		return value, false
	}
	if h.cfg.MapTargetURL != nil {
		if mapped := h.cfg.MapTargetURL(resolved.String(), false); mapped != resolved.String() {
			return mapped, true
		}
	}
	return value, false
}
