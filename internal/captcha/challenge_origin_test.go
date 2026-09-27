package captcha

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"
)

func challengeViewURL(t *testing.T, h *OperatorHandler, id, token string) *url.URL {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, operatorRequest(http.MethodGet, "/__blinder/captcha/challenge/"+id, token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("wrapper: %d %s", w.Code, w.Body.String())
	}
	z := html.NewTokenizer(strings.NewReader(w.Body.String()))
	for {
		switch z.Next() {
		case html.ErrorToken:
			t.Fatal("missing isolated iframe")
		case html.StartTagToken:
			tok := z.Token()
			if tok.Data != "iframe" {
				continue
			}
			for _, attr := range tok.Attr {
				if attr.Key != "src" {
					continue
				}
				u, err := url.Parse(attr.Val)
				if err != nil {
					t.Fatal(err)
				}
				return u
			}
		}
	}
}

func TestChallengeViewRequiresAuthenticatedWrapperAndActiveWaiter(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)
	id := q.Submit("hcaptcha", "https://target.test/login", []byte("private challenge"), "text/html")
	for _, bearer := range []string{"", token} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, operatorRequest(http.MethodGet, "/__blinder/captcha/challenge/"+id, bearer, nil))
		if w.Code != http.StatusForbidden || len(h.views) != 0 || strings.Contains(w.Body.String(), "private challenge") {
			t.Fatalf("inactive wrapper exposed view: %d, %d capabilities", w.Code, len(h.views))
		}
	}
	completionWaiter(t, q, id)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, operatorRequest(http.MethodGet, "/__blinder/captcha/challenge/"+id, "", nil))
	if w.Code != http.StatusForbidden || len(h.views) != 0 {
		t.Fatal("active waiter replaced operator authentication")
	}
	u := challengeViewURL(t, h, id, token)
	if u.Hostname() != id+ChallengeHostSuffix || u.Port() != "8099" || u.Scheme != "https" {
		t.Fatalf("wrong isolated origin: %s", u)
	}
	view := httptest.NewRecorder()
	h.ServeChallengeHTTP(view, httptest.NewRequest(http.MethodGet, u.String(), nil))
	if view.Code != http.StatusOK || !strings.Contains(view.Body.String(), "private challenge") || strings.Contains(view.Body.String(), token) {
		t.Fatalf("isolated view failed or contains operator credential: %d", view.Code)
	}
	for name, want := range map[string]string{"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"} {
		if view.Header().Get(name) != want {
			t.Errorf("%s=%q", name, view.Header().Get(name))
		}
	}
	if view.Header().Get("Set-Cookie") != "" {
		t.Fatal("view set an operator cookie")
	}
	if view.Header().Get("X-Blinder-View") != "transformed" || view.Header().Get("X-Blinder-Original-Body-Bytes") != strconv.Itoa(len("private challenge")) || view.Header().Get("X-Blinder-Rewritten-Body-Bytes") != strconv.Itoa(view.Body.Len()) || view.Header().Get("X-Blinder-Body-Size-Match") != "different" {
		t.Fatal("instrumented view lacks accurate provenance/measurements")
	}
	if !strings.Contains(view.Body.String(), `"parentOrigin":"https://`+OperatorHost+`:8099"`) {
		t.Fatal("bridge has no exact parent origin")
	}
}

func TestChallengeViewCapabilityCannotMoveBetweenOriginsOrEndpoints(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)
	id := q.Submit("hcaptcha", "https://target.test/login", []byte("private challenge"), "text/html")
	completionWaiter(t, q, id)
	u := challengeViewURL(t, h, id, token)
	otherID := q.Submit("hcaptcha", "https://target.test/other", nil, "text/html")
	completionWaiter(t, q, otherID)
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"wrong_port", func(r *http.Request) { r.Host = id + ChallengeHostSuffix + ":8100" }},
		{"wrong_scheme", func(r *http.Request) { r.TLS = nil }},
		{"operator_host", func(r *http.Request) { r.Host = OperatorHost + ":8099" }},
		{"other_challenge", func(r *http.Request) { r.Host = otherID + ChallengeHostSuffix + ":8099"; r.URL.Host = r.Host }},
		{"trailing_dot", func(r *http.Request) { r.Host = id + ChallengeHostSuffix + ".:8099" }},
		{"extra_label", func(r *http.Request) { r.Host = "extra." + id + ChallengeHostSuffix + ":8099" }},
		{"wrong_path", func(r *http.Request) { r.URL.Path = "/__blinder/captcha/" }},
		{"absolute_authority", func(r *http.Request) { r.URL.Host = "foreign.test:8099" }},
		{"no_capability", func(r *http.Request) { r.URL.RawQuery = "" }},
		{"operator_bearer", func(r *http.Request) { r.URL.RawQuery = ""; r.Header.Set("Authorization", "Bearer "+token) }},
		{"operator_cookie", func(r *http.Request) {
			r.URL.RawQuery = ""
			r.AddCookie(&http.Cookie{Name: OperatorCookieName, Value: token})
		}},
		{"incorrect_capability", func(r *http.Request) { r.URL.RawQuery = "view=" + strings.Repeat("0", 64) }},
		{"duplicate_capability", func(r *http.Request) { r.URL.RawQuery += "&" + r.URL.RawQuery }},
		{"extra_query", func(r *http.Request) { r.URL.RawQuery += "&other=1" }},
		{"post", func(r *http.Request) { r.Method = http.MethodPost }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, u.String(), nil)
			tc.mutate(r)
			w := httptest.NewRecorder()
			h.ServeChallengeHTTP(w, r)
			if w.Code < 400 || strings.Contains(w.Body.String(), "private challenge") {
				t.Fatalf("invalid view allowed: %d", w.Code)
			}
		})
	}
	head := httptest.NewRecorder()
	h.ServeChallengeHTTP(head, httptest.NewRequest(http.MethodHead, u.String(), nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") == "" {
		t.Fatalf("HEAD view: %d %s", head.Code, head.Body.String())
	}
}

func TestChallengeViewExpiresAndStopsWithPendingRequest(t *testing.T) {
	for _, reason := range []string{"capability_expired", "completed", "cancelled", "challenge_expired"} {
		t.Run(reason, func(t *testing.T) {
			h, q, _, token := testOperatorSetup(t)
			id := q.Submit("hcaptcha", "https://target.test/login", []byte("private challenge"), "text/html")
			completionWaiter(t, q, id)
			u := challengeViewURL(t, h, id, token)
			switch reason {
			case "capability_expired":
				h.viewMu.Lock()
				key := hashToken(u.Query().Get("view"))
				v := h.views[key]
				v.expires = time.Now().Add(-time.Second)
				h.views[key] = v
				h.viewMu.Unlock()
			case "completed":
				q.Complete(id, map[string]string{"h-captcha-response": "done"})
			case "cancelled":
				q.Cancel(id)
			case "challenge_expired":
				q.mu.Lock()
				q.pending[id].CreatedAt = time.Now().Add(-10 * time.Minute)
				q.mu.Unlock()
			}
			w := httptest.NewRecorder()
			h.ServeChallengeHTTP(w, httptest.NewRequest(http.MethodGet, u.String(), nil))
			if w.Code < 400 || strings.Contains(w.Body.String(), "private challenge") {
				t.Fatalf("inactive view accessible: %d", w.Code)
			}
		})
	}
}

func TestChallengeViewRetainsOriginalEnforcementWithoutGrants(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)
	body := `<!doctype html><meta http-equiv="Content-Security-Policy" content="script-src 'none'"><script nonce="source-nonce">window.original=1</script>`
	id := q.Submit("hcaptcha", "https://target.test/login", []byte(body), "text/html")
	original := http.Header{
		"Content-Security-Policy":             {"default-src 'none'; frame-ancestors 'none'; script-src 'nonce-source-nonce'", "connect-src https://provider.test"},
		"Content-Security-Policy-Report-Only": {"script-src 'none'"},
		"X-Frame-Options":                     {"DENY"}, "Cross-Origin-Embedder-Policy": {"require-corp"},
		"Set-Cookie": {"target-secret=value"}, "Content-Length": {"1"}, "Content-Encoding": {"gzip"}, "Etag": {"stale"},
	}
	q.SetResponseHeaders(id, original)
	h.SetChallengeHeaderRewriter(func(headers http.Header, base *url.URL) error {
		if base.String() != "https://target.test/login" {
			t.Errorf("wrong policy base: %s", base)
		}
		values := headers.Values("Content-Security-Policy")
		values[1] = strings.ReplaceAll(values[1], "https://provider.test", "https://provider-alias.localhost:8099")
		return nil
	})
	completionWaiter(t, q, id)
	u := challengeViewURL(t, h, id, token)
	w := httptest.NewRecorder()
	h.ServeChallengeHTTP(w, httptest.NewRequest(http.MethodGet, u.String(), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("view: %d", w.Code)
	}
	policies := w.Header().Values("Content-Security-Policy")
	if len(policies) != 2 || policies[0] != original.Values("Content-Security-Policy")[0] || policies[1] != "connect-src https://provider-alias.localhost:8099" {
		t.Fatalf("policies changed: %v", policies)
	}
	for _, name := range []string{"Content-Security-Policy-Report-Only", "X-Frame-Options", "Cross-Origin-Embedder-Policy"} {
		if w.Header().Get(name) != original.Get(name) {
			t.Errorf("lost %s", name)
		}
	}
	if !strings.Contains(w.Body.String(), body[len("<!doctype html>"):]) || strings.Contains(w.Body.String(), `<script nonce="source-nonce">;(function(cfg)`) {
		t.Fatal("original policy/body changed or bridge inherited an upstream nonce")
	}
	if strings.Contains(w.Body.String(), "function publishFields") {
		t.Fatal("CSP-protected page received injected bridge")
	}
	for _, name := range []string{"Set-Cookie", "Content-Encoding", "ETag"} {
		if w.Header().Get(name) != "" {
			t.Errorf("view replayed %s", name)
		}
	}
	ch, _ := q.Get(id)
	if ch.ResponseHeaders.Values("Content-Security-Policy")[1] != "connect-src https://provider.test" {
		t.Fatal("policy mapping changed retained upstream evidence")
	}
}

func TestChallengeViewDeclinesBridgeAcrossPoliciesAndUnsupportedCharsets(t *testing.T) {
	for _, tc := range []struct {
		name, body, contentType string
		headers                 http.Header
	}{
		{"meta_policy", `<html><head><meta http-equiv="Content-Security-Policy" content="script-src 'none'"></head><body>challenge</body></html>`, "text/html", nil},
		{"header_policy", `<body>challenge</body>`, "text/html", http.Header{"Content-Security-Policy": {"script-src 'unsafe-inline'"}}},
		{"report_only", `<body>challenge</body>`, "text/html", http.Header{"Content-Security-Policy-Report-Only": {"script-src 'none'"}}},
		{"charset", `<body>challenge</body>`, "text/html; charset=iso-8859-1", nil},
		{"invalid_utf8", "<body>\xff</body>", "text/html", nil},
		{"bom", "\xef\xbb\xbf<body>challenge</body>", "text/html", nil},
		{"plain_text", `<script>literal example</script>`, "text/plain", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, q, _, token := testOperatorSetup(t)
			id := q.Submit("hcaptcha", "https://target.test/", []byte(tc.body), tc.contentType)
			q.SetResponseHeaders(id, tc.headers)
			completionWaiter(t, q, id)
			u := challengeViewURL(t, h, id, token)
			w := httptest.NewRecorder()
			h.ServeChallengeHTTP(w, httptest.NewRequest(http.MethodGet, u.String(), nil))
			if w.Code != http.StatusOK || w.Body.String() != tc.body || w.Header().Get("Content-Type") != tc.contentType {
				t.Fatalf("protected/unsupported original changed: %d %q", w.Code, w.Body.String())
			}
		})
	}
}

func TestChallengeViewRejectsUnsupportedResponseHeadersBeforeReplay(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)
	id := q.Submit("hcaptcha", "https://target.test/", []byte("private challenge"), "text/html")
	q.SetResponseHeaders(id, http.Header{"Refresh": {"0; url=https://unregistered.test/"}})
	h.SetChallengeHeaderRewriter(func(headers http.Header, base *url.URL) error {
		headers.Set("Location", "https://unregistered.test/private")
		return errors.New("unsupported private destination")
	})
	completionWaiter(t, q, id)
	u := challengeViewURL(t, h, id, token)
	w := httptest.NewRecorder()
	h.ServeChallengeHTTP(w, httptest.NewRequest(http.MethodGet, u.String(), nil))
	if w.Code != http.StatusBadGateway || w.Header().Get("Refresh") != "" || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "private") || !strings.Contains(w.Body.String(), "unsupported challenge response headers") {
		t.Fatalf("unsupported headers replayed or failure lost: %d %v %s", w.Code, w.Header(), w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("failure lost private-view response policy")
	}
}

func TestChallengeHeaderAndFormSnapshotsAreImmutable(t *testing.T) {
	q := NewChallengeQueue(time.Minute)
	id := q.Submit("hcaptcha", "https://target.test/", nil, "text/html")
	headers := http.Header{"Content-Security-Policy": {"script-src 'none'"}}
	fields := map[string]string{"csrf": "original"}
	q.SetResponseHeaders(id, headers)
	q.SetFormFields(id, fields)
	headers["Content-Security-Policy"][0] = "script-src *"
	fields["csrf"] = "caller"
	for _, read := range []func() *Challenge{func() *Challenge { ch, _ := q.Get(id); return ch }, func() *Challenge { return q.Pending()[0] }} {
		ch := read()
		if ch.ResponseHeaders.Get("Content-Security-Policy") != "script-src 'none'" || ch.FormFields["csrf"] != "original" {
			t.Fatal("caller mutated queued snapshot")
		}
		ch.ResponseHeaders["Content-Security-Policy"][0] = "script-src *"
		ch.FormFields["csrf"] = "snapshot"
	}
	q.Complete(id, map[string]string{"h-captcha-response": "done"})
	completed, _ := q.GetCompleted(id)
	if completed.ResponseHeaders.Get("Content-Security-Policy") != "script-src 'none'" || completed.FormFields["csrf"] != "original" {
		t.Fatal("completion lost immutable evidence")
	}
	completed.ResponseHeaders["Content-Security-Policy"][0] = "script-src *"
	again, _ := q.GetCompleted(id)
	if again.ResponseHeaders.Get("Content-Security-Policy") != "script-src 'none'" {
		t.Fatal("completed snapshot is mutable")
	}
}

func TestChallengeOriginMappingNeverForwardsViewCapability(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)
	id := q.Submit("hcaptcha", "https://target.test:8443/login?session=original", nil, "text/html")
	completionWaiter(t, q, id)
	u := challengeViewURL(t, h, id, token)
	origin := u.Scheme + "://" + u.Host
	if h.MapChallengeOrigin(origin) != "https://target.test:8443" || h.MapChallengeURL(u.String()) != "https://target.test:8443/login?session=original" {
		t.Fatal("isolated origin mapping failed")
	}
	for _, value := range []string{"null", strings.Replace(origin, "https:", "http:", 1), strings.Replace(origin, ":8099", ":8100", 1), "https://foreign.test", origin + "/"} {
		if h.MapChallengeOrigin(value) != value {
			t.Errorf("mapped unowned origin %q", value)
		}
	}
	q.Cancel(id)
	if h.MapChallengeOrigin(origin) != origin || h.MapChallengeURL(u.String()) != u.String() {
		t.Fatal("inactive challenge origin still mapped")
	}
	for _, hostname := range []string{"blinder-challenge.localhost", "invalid" + ChallengeHostSuffix, "extra.label" + ChallengeHostSuffix, id + ChallengeHostSuffix + "."} {
		if !HandlesChallengeHost(hostname) {
			t.Errorf("reserved name can fall through: %s", hostname)
		}
	}
	if HandlesChallengeHost("attacker-blinder-challenge.localhost") || HandlesChallengeHost(id+ChallengeHostSuffix+".attacker.test") {
		t.Fatal("reserved namespace matched external hostname")
	}
}
