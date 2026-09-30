package captcha

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"mime"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Splinters-io/blinder/internal/endpoint"
)

const (
	OperatorHost          = endpoint.OperatorHost
	OperatorCookieName    = "__Host-blinder-operator"
	operatorCookieName    = OperatorCookieName
	ChallengeHostSuffix   = ".blinder-challenge.localhost"
	challengeViewPath     = "/__blinder/captcha/view"
	challengeViewLifetime = 2 * time.Minute
	maxChallengeViews     = maxPendingChallenges * 4
)

type challengeView struct {
	id      string
	expires time.Time
}

type OperatorHandler struct {
	queue            *ChallengeQueue
	matcher          *Matcher
	bearerHash       [32]byte
	transport        http.RoundTripper
	routeResources   bool
	resourceTimeout  time.Duration
	sessionMu        sync.Mutex
	resourceSessions map[string]*cookiejar.Jar
	operatorOrigin   string
	providerRoutes   *ProviderRoutes
	providerHTML     func([]byte, *url.URL, http.Header) []byte
	challengeHeaders func(http.Header, *url.URL) error
	viewMu           sync.Mutex
	views            map[[32]byte]challengeView
	authLimiter      *authRateLimiter
}

// SetChallengeHeaderRewriter configures URL translation for original response
// policies. It receives a private header copy and must not grant new permissions.
func (h *OperatorHandler) SetChallengeHeaderRewriter(rewrite func(http.Header, *url.URL) error) {
	h.challengeHeaders = rewrite
}

// SetProviderRoutes configures the operator's resource references before use.
// Control authentication remains exclusively on the operator origin.
func (h *OperatorHandler) SetProviderRoutes(routes *ProviderRoutes, rewriteHTML func([]byte, *url.URL, http.Header) []byte) {
	h.providerRoutes, h.providerHTML = routes, rewriteHTML
}

func (h *OperatorHandler) operatorCSP() string {
	var origins []string
	for _, route := range h.providerRoutes.Routes() {
		origins = append(origins, route.Local.String())
	}
	return h.matcher.OperatorCSP(origins...)
}

func generateOperatorToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func NewOperatorHandler(queue *ChallengeQueue, matcher *Matcher, transport http.RoundTripper, routeResources ...bool) (*OperatorHandler, string) {
	token := generateOperatorToken()
	return &OperatorHandler{
		queue:            queue,
		matcher:          matcher,
		bearerHash:       hashToken(token),
		transport:        transport,
		routeResources:   len(routeResources) > 0 && routeResources[0],
		resourceTimeout:  30 * time.Second,
		resourceSessions: make(map[string]*cookiejar.Jar),
		views:            make(map[[32]byte]challengeView),
		authLimiter:      newAuthRateLimiter(10, time.Minute),
	}, token
}

// SetResourceTimeout is called at construction, before serving requests.
func (h *OperatorHandler) SetResourceTimeout(timeout time.Duration) {
	if timeout > 0 {
		h.resourceTimeout = timeout
	}
}

// SetOperatorOrigin fixes the browser origin used to authorize native form
// submissions. Configure it before serving; never infer it from request headers.
func (h *OperatorHandler) SetOperatorOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() != OperatorHost || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(origin, "#") || strings.HasSuffix(u.Host, ":") {
		return fmt.Errorf("invalid CAPTCHA operator origin")
	}
	port := u.Port()
	defaultPort := "443"
	if u.Scheme == "http" {
		defaultPort = "80"
	}
	if port == "" {
		port = defaultPort
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return fmt.Errorf("invalid CAPTCHA operator origin port")
	}
	h.operatorOrigin = u.Scheme + "://" + OperatorHost
	if strconv.FormatUint(number, 10) != defaultPort {
		h.operatorOrigin += ":" + strconv.FormatUint(number, 10)
	}
	return nil
}

func hashToken(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

func (h *OperatorHandler) authorize(r *http.Request) bool {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		hash := hashToken(token)
		if subtle.ConstantTimeCompare(hash[:], h.bearerHash[:]) == 1 {
			return true
		}
	}
	if cookie, err := r.Cookie(operatorCookieName); err == nil {
		hash := hashToken(cookie.Value)
		if subtle.ConstantTimeCompare(hash[:], h.bearerHash[:]) == 1 {
			dest := r.Header.Get("Sec-Fetch-Dest")
			if dest == "" || dest == "document" {
				if r.Method != http.MethodGet && r.Method != http.MethodHead {
					return h.operatorOrigin != "" && r.Header.Get("Origin") == h.operatorOrigin
				}
				return true
			}
		}
	}
	return false
}

func (h *OperatorHandler) setAuthCookie(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	http.SetCookie(w, &http.Cookie{
		Name:     operatorCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *OperatorHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !h.authLimiter.allowed() {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many failed requests", http.StatusTooManyRequests)
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token parameter", http.StatusBadRequest)
		return
	}
	hash := hashToken(token)
	if subtle.ConstantTimeCompare(hash[:], h.bearerHash[:]) != 1 {
		h.authLimiter.recordFailure()
		http.Error(w, "invalid token", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     operatorCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/__blinder/captcha/", http.StatusSeeOther)
}

func (h *OperatorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/__blinder/captcha")

	if path == "/res" {
		h.serveResource(w, r)
		return
	}

	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cache-Control", "no-store")
	// Native same-origin form POSTs need their concrete Origin for the CSRF
	// check. no-referrer turns that Origin into null in the browser.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'none'; object-src 'none'; worker-src 'none'; form-action 'self'")
	if h.routeResources {
		w.Header().Set("Content-Security-Policy", h.operatorCSP()+"; worker-src 'none'")
	}
	if path == "/login" {
		// The bootstrap token is in this URL; never make it a Referer, including
		// on the redirect to the trusted queue page.
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleLogin(w, r)
		return
	}

	if !h.authLimiter.allowed() {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many failed requests", http.StatusTooManyRequests)
		return
	}
	if !h.authorize(r) {
		h.authLimiter.recordFailure()
		http.Error(w, "operator authorization required", http.StatusForbidden)
		return
	}

	h.setAuthCookie(w, r)

	switch {
	case path == "" || path == "/":
		h.listChallenges(w, r)
	case strings.HasPrefix(path, "/challenge/"):
		id := strings.TrimPrefix(path, "/challenge/")
		if id == "" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPost {
			h.completeChallenge(w, r, id)
		} else if r.Method == http.MethodGet {
			h.showChallenge(w, r, id)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case strings.HasPrefix(path, "/solve/"):
		id := strings.TrimPrefix(path, "/solve/")
		h.serveSolvePage(w, r, id)
	case strings.HasPrefix(path, "/page/"):
		id := strings.TrimPrefix(path, "/page/")
		h.serveChallengePage(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (h *OperatorHandler) listChallenges(w http.ResponseWriter, _ *http.Request) {
	pending := h.queue.Pending()

	type entry struct {
		ID       string `json:"id"`
		Provider string `json:"provider"`
		PageURL  string `json:"page_url"`
		Age      string `json:"age"`
	}

	entries := make([]entry, len(pending))
	for i, ch := range pending {
		entries[i] = entry{
			ID:       ch.ID,
			Provider: ch.ProviderName,
			PageURL:  ch.PageURL,
			Age:      time.Since(ch.CreatedAt).Round(time.Second).String(),
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html><head><title>Blinder CAPTCHA Queue</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 600px; margin: 2rem auto; padding: 0 1rem; }
h1 { font-size: 1.25rem; }
.empty { color: #666; }
.challenge { border: 1px solid #ddd; padding: 1rem; margin: 0.5rem 0; border-radius: 4px; }
.challenge a { color: #0066cc; }
.meta { font-size: 0.85rem; color: #666; }
</style>
</head><body>
<h1>CAPTCHA Challenges (%d pending)</h1>`, len(entries))

	if len(entries) == 0 {
		fmt.Fprint(w, `<p class="empty">No pending challenges.</p>`)
	}
	for _, e := range entries {
		fmt.Fprintf(w, `<div class="challenge">
<a href="/__blinder/captcha/challenge/%s">%s challenge</a>
<div class="meta">%s -- %s ago</div>
</div>`, html.EscapeString(e.ID), html.EscapeString(e.Provider),
			html.EscapeString(e.PageURL), html.EscapeString(e.Age))
	}

	fmt.Fprint(w, `</body></html>`)
}

func (h *OperatorHandler) showChallenge(w http.ResponseWriter, r *http.Request, id string) {
	h.showChallengeWrapper(w, r, id, false)
}

// Only this trusted wrapper runs at the operator origin. Each original challenge
// lives at its own origin, including when opened in a separate solve window.
func (h *OperatorHandler) showChallengeWrapper(w http.ResponseWriter, r *http.Request, id string, automatic bool) {
	ch, ok := h.queue.Get(id)
	if !ok {
		http.Error(w, "challenge not found or expired", http.StatusNotFound)
		return
	}

	viewURL, ok := h.mintChallengeView(id)
	if !ok {
		http.Error(w, "no active challenge view", http.StatusForbidden)
		return
	}
	opaqueFields := h.challengeFields(ch.ProviderName)
	viewOrigin := viewURL.Scheme + "://" + viewURL.Host
	// This changes only the trusted wrapper's framing policy, never a target
	// policy. The challenge origin is not a permitted operator script source.
	policy := w.Header().Get("Content-Security-Policy")
	var directives []string
	for _, directive := range strings.Split(policy, ";") {
		fields := strings.Fields(directive)
		if len(fields) > 0 && fields[0] != "frame-src" {
			directives = append(directives, strings.TrimSpace(directive))
		}
	}
	directives = append(directives, "frame-src "+viewOrigin)
	w.Header().Set("Content-Security-Policy", strings.Join(directives, "; "))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html><head><title>Solve: %s</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 700px; margin: 2rem auto; padding: 0 1rem; }
h1 { font-size: 1.25rem; }
iframe { width: 100%%; height: 500px; border: 1px solid #ddd; border-radius: 4px; }
.actions { margin-top: 1rem; }
.actions button { padding: 0.5rem 1.5rem; font-size: 1rem; cursor: pointer; }
.meta { font-size: 0.85rem; color: #666; margin-bottom: 1rem; }
.fields { margin: 0.5rem 0; }
.fields label { display: block; margin: 0.25rem 0; font-size: 0.9rem; }
.fields input { width: 100%%; padding: 0.25rem; font-family: monospace; }
</style>
</head><body>
<h1>%s Challenge</h1>
<div class="meta">
<div>Page: %s</div>
<div>ID: %s</div>
</div>
<p>Complete the CAPTCHA below, or <a href="/__blinder/captcha/solve/%s" target="_blank" rel="noopener">open a separate solve window</a> (auto-submits on completion).</p>
<iframe src="%s" sandbox="allow-scripts allow-forms allow-same-origin" referrerpolicy="no-referrer"></iframe>
<form method="POST" action="/__blinder/captcha/challenge/%s" class="fields">`,
		html.EscapeString(ch.ProviderName),
		html.EscapeString(ch.ProviderName),
		html.EscapeString(ch.PageURL),
		html.EscapeString(ch.ID),
		html.EscapeString(ch.ID),
		html.EscapeString(viewURL.String()),
		html.EscapeString(ch.ID))

	for _, field := range opaqueFields {
		fmt.Fprintf(w, `<label>%s: <input name="%s" type="text"></label>`,
			html.EscapeString(field), html.EscapeString(field))
	}
	fmt.Fprint(w, `<div class="actions"><button type="submit">Submit Solution</button></div>
</form>`)
	fmt.Fprint(w, operatorCompletionScript(ch.ID, opaqueFields, automatic, viewOrigin))
	fmt.Fprint(w, `</body></html>`)
}

// HandlesChallengeHost reserves the entire namespace, including malformed
// labels, so an invalid view hostname cannot fall through to the target proxy.
func HandlesChallengeHost(hostname string) bool {
	hostname = strings.TrimSuffix(strings.ToLower(hostname), ".")
	return hostname == strings.TrimPrefix(ChallengeHostSuffix, ".") || strings.HasSuffix(hostname, ChallengeHostSuffix)
}

func challengeIDFromHost(hostname string) string {
	if !strings.HasSuffix(hostname, ChallengeHostSuffix) {
		return ""
	}
	id := strings.TrimSuffix(hostname, ChallengeHostSuffix)
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 16 || id != strings.ToLower(id) {
		return ""
	}
	return id
}

func (h *OperatorHandler) challengeOrigin(id string) *url.URL {
	operator, err := url.Parse(h.operatorOrigin)
	if err != nil || operator.Host == "" || challengeIDFromHost(id+ChallengeHostSuffix) == "" {
		return nil
	}
	host := id + ChallengeHostSuffix
	if operator.Port() != "" {
		host += ":" + operator.Port()
	}
	return &url.URL{Scheme: operator.Scheme, Host: host}
}

func (h *OperatorHandler) challengeFields(provider string) []string {
	for _, p := range h.matcher.providers {
		if p.Name == provider {
			return append([]string(nil), p.OpaqueFields...)
		}
	}
	return nil
}

func (h *OperatorHandler) mintChallengeView(id string) (*url.URL, bool) {
	u := h.challengeOrigin(id)
	if u == nil {
		return nil, false
	}
	if _, ok := h.queue.activeChallenge(id); !ok {
		return nil, false
	}
	token := generateOperatorToken()
	now := time.Now()
	h.viewMu.Lock()
	for key, view := range h.views {
		if !now.Before(view.expires) {
			delete(h.views, key)
		}
	}
	if len(h.views) >= maxChallengeViews {
		var oldest [32]byte
		var expiry time.Time
		for key, view := range h.views {
			if expiry.IsZero() || view.expires.Before(expiry) {
				oldest, expiry = key, view.expires
			}
		}
		delete(h.views, oldest)
	}
	h.views[hashToken(token)] = challengeView{id: id, expires: now.Add(challengeViewLifetime)}
	h.viewMu.Unlock()
	u.Path = challengeViewPath
	u.RawQuery = url.Values{"view": {token}}.Encode()
	return u, true
}

// ChallengePageURL maps only a pending, actively waited challenge hostname.
func (h *OperatorHandler) ChallengePageURL(hostname string) (*url.URL, bool) {
	id := challengeIDFromHost(hostname)
	ch, ok := h.queue.activeChallenge(id)
	if !ok {
		return nil, false
	}
	u, err := url.Parse(ch.PageURL)
	return u, err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") && u.User == nil
}

func (h *OperatorHandler) mapChallengeValue(value string, originOnly bool) string {
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.Fragment != "" || (originOnly && (u.Path != "" || u.RawQuery != "" || u.ForceQuery)) {
		return value
	}
	expected := h.challengeOrigin(challengeIDFromHost(u.Hostname()))
	if expected == nil || u.Scheme != expected.Scheme || u.Host != expected.Host {
		return value
	}
	page, ok := h.ChallengePageURL(u.Hostname())
	if !ok {
		return value
	}
	if originOnly {
		return page.Scheme + "://" + page.Host
	}
	// The view URL and its capability must never be forwarded upstream.
	return page.String()
}

func (h *OperatorHandler) MapChallengeOrigin(value string) string {
	return h.mapChallengeValue(value, true)
}

func (h *OperatorHandler) MapChallengeURL(value string) string {
	return h.mapChallengeValue(value, false)
}

// ServeChallengeHTTP serves untrusted content only at a dedicated challenge
// origin. It never accepts the operator bearer/cookie as view authorization.
// The caller must additionally enforce the listener's loopback-client rule.
func (h *OperatorHandler) ServeChallengeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestOrigin := &url.URL{Scheme: "http", Host: r.Host}
	if r.TLS != nil {
		requestOrigin.Scheme = "https"
	}
	id := challengeIDFromHost(requestOrigin.Hostname())
	expected := h.challengeOrigin(id)
	if expected == nil || r.Host != expected.Host || requestOrigin.Scheme != expected.Scheme ||
		(r.URL.IsAbs() && (r.URL.Scheme != expected.Scheme || r.URL.Host != expected.Host)) ||
		r.URL.EscapedPath() != challengeViewPath {
		http.NotFound(w, r)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["view"]) != 1 || len(query.Get("view")) != 64 {
		http.Error(w, "challenge view authorization required", http.StatusForbidden)
		return
	}
	key := hashToken(query.Get("view"))
	h.viewMu.Lock()
	view, ok := h.views[key]
	if ok && !time.Now().Before(view.expires) {
		delete(h.views, key)
		ok = false
	}
	h.viewMu.Unlock()
	if !ok || view.id != id {
		http.Error(w, "challenge view authorization required", http.StatusForbidden)
		return
	}
	ch, ok := h.queue.activeChallenge(id)
	if !ok {
		http.Error(w, "challenge not active", http.StatusGone)
		return
	}
	headers := ch.ResponseHeaders.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	base, _ := url.Parse(ch.PageURL)
	if h.challengeHeaders != nil {
		if err := h.challengeHeaders(headers, base); err != nil {
			http.Error(w, "unsupported challenge response headers", http.StatusBadGateway)
			return
		}
	}
	// Original enforcement headers, including every CSP policy and XFO, remain.
	// Hop-by-hop metadata, target cookies and validators for original bytes do
	// not describe this private, instrumented document representation.
	for _, connection := range headers.Values("Connection") {
		for _, name := range strings.Split(connection, ",") {
			headers.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Set-Cookie", "Set-Cookie2", "Content-Length", "Content-Encoding", "ETag", "Last-Modified", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest"} {
		headers.Del(name)
	}
	for name, values := range headers {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	contentType := ch.ContentType
	if contentType == "" {
		contentType = "text/html; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	body := ch.PageBody
	mediaType, mediaParams, mediaErr := mime.ParseMediaType(contentType)
	charset := strings.ToLower(mediaParams["charset"])
	canRewrite := mediaErr == nil && mediaType == "text/html" &&
		(charset == "" || charset == "utf-8" || charset == "us-ascii") &&
		utf8.Valid(body) && !strings.HasPrefix(string(body), "\xef\xbb\xbf")
	if canRewrite {
		if base != nil {
			body = rewriteCaptchaScriptHost(body, "host="+url.QueryEscape(base.Host))
		}
		if h.routeResources {
			if h.providerHTML != nil {
				body = h.providerHTML(body, base, ch.ResponseHeaders.Clone())
			} else {
				body = h.matcher.RewriteProviderHTML(body, base, id)
			}
		}
		// A bridge inserted ahead of meta CSP would evade that policy. Keep all
		// documents with original policies uninstrumented until their exact
		// execution permission can be replicated; never borrow a nonce/grant.
		if !providerDocumentHasPolicy(ch.PageBody, ch.ResponseHeaders) {
			body = h.injectRuntime(body, base, r, id, h.challengeFields(ch.ProviderName))
		}
	}
	w.Header().Set("X-Blinder-View", "transformed")
	w.Header().Set("X-Blinder-Original-Body-Bytes", strconv.Itoa(len(ch.PageBody)))
	w.Header().Set("X-Blinder-Rewritten-Body-Bytes", strconv.Itoa(len(body)))
	sizeMatch := "different"
	if len(body) == len(ch.PageBody) {
		sizeMatch = "exact"
	}
	w.Header().Set("X-Blinder-Body-Size-Match", sizeMatch)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (h *OperatorHandler) completeChallenge(w http.ResponseWriter, r *http.Request, id string) {
	if !h.queue.HasWaiter(id) {
		writeCompletionError(w, r, id, "no pending request for this challenge", http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		writeCompletionError(w, r, id, "bad form data", http.StatusBadRequest)
		return
	}

	solution := make(map[string]string)
	for key, vals := range r.PostForm {
		if len(vals) > 0 && vals[0] != "" {
			solution[key] = vals[0]
		}
	}

	if len(solution) == 0 {
		writeCompletionError(w, r, id, "no solution fields provided", http.StatusBadRequest)
		return
	}

	if !h.queue.Complete(id, solution) {
		writeCompletionError(w, r, id, "challenge not found or already completed", http.StatusNotFound)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Vary", "Accept")
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		writeCompletionPage(w, http.StatusOK, id, "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "completed",
		"id":     id,
		"fields": len(solution),
	})
}

func writeCompletionError(w http.ResponseWriter, r *http.Request, id, message string, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Vary", "Accept")
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		writeCompletionPage(w, status, id, message)
		return
	}
	http.Error(w, message, status)
}

// A browser's authenticated native POST receives a receipt. API clients retain
// the existing JSON success response and plain-text errors. This does not grant
// cookie-only fetch/XHR access to the operator endpoints.
func writeCompletionPage(w http.ResponseWriter, status int, id, message string) {
	title := "Solution submitted"
	if status != http.StatusOK {
		title = "Submission failed"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html><head><title>%s</title>
<style>body{font-family:system-ui,sans-serif;max-width:600px;margin:3rem auto;padding:0 1rem}button,a{margin-right:1rem}</style>
</head><body><h1>%s</h1>`, title, title)
	if status == http.StatusOK {
		fmt.Fprint(w, `<p role="status">The solution was sent to the waiting request. Return to the original page to check its result.</p><p>You can close this window.</p>`)
	} else {
		fmt.Fprintf(w, `<p role="alert">%s</p><p><button type="button" onclick="history.back()">Try again</button><a href="/__blinder/captcha/challenge/%s">Reopen challenge</a></p>`, html.EscapeString(message), html.EscapeString(url.PathEscape(id)))
	}
	fmt.Fprint(w, `<p><a href="/__blinder/captcha/">Challenge queue</a></p></body></html>`)
}

func (h *OperatorHandler) serveSolvePage(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.showChallengeWrapper(w, r, id, true)
}

func (h *OperatorHandler) serveChallengePage(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.showChallengeWrapper(w, r, id, false)
}

var captchaScriptRe = regexp.MustCompile(`(<script\s[^>]*src=["']https://js\.hcaptcha\.com/1/api\.js)(\?[^"']*)?["']`)

func rewriteCaptchaScriptHost(body []byte, hostParam string) []byte {
	return captchaScriptRe.ReplaceAllFunc(body, func(match []byte) []byte {
		loc := captchaScriptRe.FindSubmatchIndex(match)
		if loc == nil {
			return match
		}
		base := match[loc[2]:loc[3]]
		var result []byte
		if loc[4] >= 0 {
			existing := string(match[loc[4]:loc[5]])
			result = append(result, base...)
			result = append(result, []byte(existing+"&"+hostParam)...)
		} else {
			result = append(result, base...)
			result = append(result, []byte("?"+hostParam)...)
		}
		result = append(result, '"')
		return result
	})
}
