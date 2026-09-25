package captcha

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// A pending challenge ID is a random capability, revealed only on the authorised
// operator surface. It grants provider-resource access, never control API access.
// Cookies live in a separate jar per challenge, not in the operator browser jar.
func (h *OperatorHandler) resourceSession(id string) (*cookiejar.Jar, bool) {
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()
	for key := range h.resourceSessions {
		if _, ok := h.queue.Get(key); !ok {
			delete(h.resourceSessions, key)
		}
	}
	if _, ok := h.queue.Get(id); !ok {
		return nil, false
	}
	jar := h.resourceSessions[id]
	if jar == nil {
		jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		h.resourceSessions[id] = jar
	}
	return jar, true
}

func relayURL(raw, session string) string {
	result := resourcePath + "?u=" + url.QueryEscape(raw)
	if session != "" {
		result += "&sid=" + url.QueryEscape(session)
	}
	return result
}

func (h *OperatorHandler) serveResource(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" && r.Method != "POST" && r.Method != "OPTIONS" {
		http.Error(w, "method not allowed", 405)
		return
	}
	rawURL := r.URL.Query().Get("u")
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		http.Error(w, "invalid resource URL", 400)
		return
	}
	if h.matcher == nil || !h.matcher.ShouldRouteResource(parsed) {
		http.Error(w, "not a routable provider resource", 403)
		return
	}
	session := r.URL.Query().Get("sid")
	var jar *cookiejar.Jar
	if session != "" {
		var ok bool
		jar, ok = h.resourceSession(session)
		if !ok {
			http.Error(w, "challenge session expired", 403)
			return
		}
	} else if r.Method == "POST" || r.Method == "OPTIONS" {
		http.Error(w, "challenge session required", 403)
		return
	}
	// Sandbox frames have opaque origins. The session capability gates access;
	// browser cookies/Authorization are never copied into the provider request.
	if session != "" {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Vary", "Origin")
		}
		w.Header().Set("Cache-Control", "no-store")
	}
	if r.Method == "OPTIONS" {
		method := r.Header.Get("Access-Control-Request-Method")
		if method != "GET" && method != "HEAD" && method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		for _, name := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "", "content-type", "accept", "accept-language":
			default:
				http.Error(w, "header not allowed", 403)
				return
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Accept-Language")
		w.WriteHeader(204)
		return
	}
	if h.transport == nil {
		http.Error(w, "no transport configured", 503)
		return
	}
	bodyIn, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2*1024*1024))
	if err != nil {
		var status = 400
		if _, ok := err.(*http.MaxBytesError); ok {
			status = 413
		}
		http.Error(w, "invalid provider request body", status)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.resourceTimeout)
	defer cancel()
	fetchReq, err := http.NewRequestWithContext(ctx, r.Method, rawURL, bytes.NewReader(bodyIn))
	if err != nil {
		http.Error(w, "bad resource request", 400)
		return
	}
	for _, name := range []string{"Content-Type", "Accept", "Accept-Language"} {
		if v := r.Header.Get(name); v != "" {
			fetchReq.Header.Set(name, v)
		}
	}
	if jar != nil {
		for _, c := range jar.Cookies(parsed) {
			fetchReq.AddCookie(c)
		}
	}
	resp, err := h.transport.RoundTrip(fetchReq)
	if err != nil {
		http.Error(w, "resource fetch failed", 502)
		return
	}
	defer resp.Body.Close()
	if jar != nil {
		jar.SetCookies(parsed, resp.Cookies())
	}
	const maxResource = 10 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResource+1))
	if err != nil || len(body) > maxResource {
		http.Error(w, "resource read failed", 502)
		return
	}
	if location := resp.Header.Get("Location"); location != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		destination, err := parsed.Parse(location)
		if err != nil || destination.User != nil || !h.matcher.ShouldRouteResource(destination) {
			http.Error(w, "provider redirect outside configured scope", 502)
			return
		}
		w.Header().Set("Location", relayURL(destination.String(), session))
	}
	rewrittenHTML := h.routeResources && strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/html")
	if rewrittenHTML {
		body = h.matcher.RewriteProviderHTML(body, parsed, session)
		if session != "" {
			body = h.injectRuntime(body, parsed, r, session)
		}
		w.Header().Set("Content-Security-Policy", strings.TrimPrefix(h.matcher.OperatorCSP(), "frame-ancestors 'none'; "))
	}
	for _, name := range []string{"Content-Type", "Cache-Control", "ETag", "Last-Modified"} {
		if (session != "" && name == "Cache-Control") || (rewrittenHTML && (name == "ETag" || name == "Last-Modified")) {
			continue
		}
		if v := resp.Header.Get(name); v != "" {
			w.Header().Set(name, v)
		}
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(resp.StatusCode)
	if r.Method != "HEAD" {
		w.Write(body)
	}
}
