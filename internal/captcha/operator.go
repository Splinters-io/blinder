package captcha

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Splinters-io/blinder/internal/endpoint"
)

const (
	OperatorHost       = endpoint.OperatorHost
	OperatorCookieName = "__Host-blinder-operator"
	operatorCookieName = OperatorCookieName
)

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
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token parameter", http.StatusBadRequest)
		return
	}
	hash := hashToken(token)
	if subtle.ConstantTimeCompare(hash[:], h.bearerHash[:]) != 1 {
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
		w.Header().Set("Content-Security-Policy", h.matcher.OperatorCSP()+"; worker-src 'none'")
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

	if !h.authorize(r) {
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

// Only this trusted wrapper runs at the operator origin. The original challenge
// stays in an opaque sandbox, including when opened in its own solve window.
func (h *OperatorHandler) showChallengeWrapper(w http.ResponseWriter, r *http.Request, id string, automatic bool) {
	ch, ok := h.queue.Get(id)
	if !ok {
		http.Error(w, "challenge not found or expired", http.StatusNotFound)
		return
	}

	opaqueFields := []string{}
	for _, p := range h.matcher.providers {
		if p.Name == ch.ProviderName {
			opaqueFields = p.OpaqueFields
			break
		}
	}
	pageBody := ch.PageBody
	base, _ := url.Parse(ch.PageURL)
	if base != nil {
		pageBody = rewriteCaptchaScriptHost(pageBody, "host="+url.QueryEscape(base.Host))
	}
	if h.routeResources {
		pageBody = h.matcher.RewriteProviderHTML(pageBody, base, id)
	}
	// The completion bridge is needed in both direct and Tor modes. Its network
	// interception is disabled outside Tor mode; credentials never enter srcdoc.
	pageBody = h.injectRuntime(pageBody, base, r, id)

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
<iframe srcdoc="%s" sandbox="allow-scripts allow-forms"></iframe>
<form method="POST" action="/__blinder/captcha/challenge/%s" class="fields">`,
		html.EscapeString(ch.ProviderName),
		html.EscapeString(ch.ProviderName),
		html.EscapeString(ch.PageURL),
		html.EscapeString(ch.ID),
		html.EscapeString(ch.ID),
		html.EscapeString(string(pageBody)),
		html.EscapeString(ch.ID))

	for _, field := range opaqueFields {
		fmt.Fprintf(w, `<label>%s: <input name="%s" type="text"></label>`,
			html.EscapeString(field), html.EscapeString(field))
	}
	fmt.Fprint(w, `<div class="actions"><button type="submit">Submit Solution</button></div>
</form>`)
	fmt.Fprint(w, operatorCompletionScript(ch.ID, opaqueFields, automatic))
	fmt.Fprint(w, `</body></html>`)
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
