package captcha

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestOperatorCookieCompletionRequiresExactOrigin(t *testing.T) {
	for _, origin := range []string{"", "null", "https://alias.local:8099", "https://" + OperatorHost + ":8100", "http://" + OperatorHost + ":8099", "https://" + OperatorHost + ":8099/", "https://" + OperatorHost + ":8099"} {
		t.Run(origin, func(t *testing.T) {
			h, q, _, token := testOperatorSetup(t)
			id := q.Submit("hcaptcha", "https://target.test/", []byte("challenge"), "text/html")
			completionWaiter(t, q, id)
			r := completionBrowserRequest(id, token, "h-captcha-response=fixture-solution")
			r.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := http.StatusForbidden
			if origin == "https://"+OperatorHost+":8099" {
				want = http.StatusOK
			}
			if w.Code != want {
				t.Fatalf("Origin=%q status=%d want=%d", origin, w.Code, want)
			}
			if want == http.StatusForbidden {
				if _, pending := q.Get(id); !pending {
					t.Fatal("cross-origin submission consumed challenge")
				}
			}
		})
	}
}

func TestOperatorBearerCompletionDoesNotDependOnBrowserOrigin(t *testing.T) {
	h, q, _, token := testOperatorSetup(t)
	id := q.Submit("hcaptcha", "https://target.test/", nil, "text/html")
	completionWaiter(t, q, id)
	r := operatorRequest(http.MethodPost, "/__blinder/captcha/challenge/"+id, token, strings.NewReader("h-captcha-response=api-solution"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"completed"`) {
		t.Fatalf("explicit bearer API rejected: %d %s", w.Code, w.Body.String())
	}
}

func TestOperatorLegacyCookieNeverAuthenticates(t *testing.T) {
	h, _, _, token := testOperatorSetup(t)
	r := httptest.NewRequest(http.MethodGet, "/__blinder/captcha/", nil)
	r.AddCookie(&http.Cookie{Name: "__blinder_op", Value: token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("legacy same-origin cookie authenticated: %d", w.Code)
	}
}

func TestOperatorOriginConfiguration(t *testing.T) {
	h, _, _, _ := testOperatorSetup(t)
	for input, want := range map[string]string{
		"https://" + OperatorHost + ":00443": "https://" + OperatorHost,
		"https://" + OperatorHost + ":08099": "https://" + OperatorHost + ":8099",
		"http://" + OperatorHost + ":80":     "http://" + OperatorHost,
	} {
		if err := h.SetOperatorOrigin(input); err != nil || h.operatorOrigin != want {
			t.Fatalf("SetOperatorOrigin(%q)=%q,%v want=%q", input, h.operatorOrigin, err, want)
		}
	}
	for _, input := range []string{"https://alias.local:8099", "https://" + OperatorHost + ":", "https://" + OperatorHost + ":0", "https://" + OperatorHost + ":65536", "https://" + OperatorHost + "/", "https://" + OperatorHost + "?", "https://" + OperatorHost + "#", "https://user@" + OperatorHost} {
		if err := h.SetOperatorOrigin(input); err == nil {
			t.Errorf("accepted invalid operator origin %q", input)
		}
	}
}

func TestOperatorControlResponsesSeparateOpenerAndPreventCaching(t *testing.T) {
	h, _, _, token := testOperatorSetup(t)
	for _, tc := range []struct{ path, bearer string }{
		{"/__blinder/captcha/", token},
		{"/__blinder/captcha/", ""},
		{"/__blinder/captcha/login?token=" + token, ""},
		{"/__blinder/captcha/login?token=invalid", ""},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, operatorRequest(http.MethodGet, tc.path, tc.bearer, nil))
		referrerPolicy := "same-origin"
		if strings.HasPrefix(tc.path, "/__blinder/captcha/login") {
			referrerPolicy = "no-referrer"
		}
		for name, want := range map[string]string{"Cross-Origin-Opener-Policy": "same-origin", "Cache-Control": "no-store", "Referrer-Policy": referrerPolicy, "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY"} {
			if got := w.Header().Get(name); got != want {
				t.Errorf("%s lacks %s=%q: %q", tc.path, name, want, got)
			}
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "worker-src 'none'") {
			t.Fatal("operator response permits worker creation")
		}
	}
}

func TestOperatorChallengeDocumentsStayInsideSeparateOrigin(t *testing.T) {
	const untrusted = `<body><script>window.untrustedChallenge=1</script></iframe><iframe sandbox="allow-scripts allow-same-origin" srcdoc="bad"></iframe><input name="h-captcha-response" value="fixture"></body>`
	for _, route := range []string{"challenge", "solve", "page"} {
		t.Run(route, func(t *testing.T) {
			h, q, _, token := testOperatorSetup(t)
			id := q.Submit("hcaptcha", "https://target.test/account", []byte(untrusted), "text/html")
			completionWaiter(t, q, id)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, operatorRequest(http.MethodGet, "/__blinder/captcha/"+route+"/"+id, token, nil))
			doc, err := html.Parse(strings.NewReader(w.Body.String()))
			if err != nil || w.Code != http.StatusOK {
				t.Fatalf("operator wrapper failed: %d %v", w.Code, err)
			}
			frames := 0
			var visit func(*html.Node)
			visit = func(n *html.Node) {
				if n.Type == html.ElementNode && n.Data == "iframe" {
					frames++
					attrs := map[string]string{}
					for _, a := range n.Attr {
						attrs[a.Key] = a.Val
					}
					if attrs["sandbox"] != "allow-scripts allow-forms allow-same-origin" || attrs["srcdoc"] != "" || !strings.HasPrefix(attrs["src"], "https://"+id+ChallengeHostSuffix+":8099"+challengeViewPath+"?") {
						t.Errorf("challenge not isolated at its own origin: %v", attrs)
					} else {
						view := httptest.NewRecorder()
						h.ServeChallengeHTTP(view, httptest.NewRequest(http.MethodGet, attrs["src"], nil))
						if view.Code != http.StatusOK || !strings.Contains(view.Body.String(), untrusted) {
							t.Errorf("challenge lost in isolated view: %d", view.Code)
						}
					}
				}
				if n.Type == html.ElementNode && n.Data == "script" && n.FirstChild != nil && strings.Contains(n.FirstChild.Data, "untrustedChallenge") {
					t.Error("untrusted script became privileged operator script")
				}
				for child := n.FirstChild; child != nil; child = child.NextSibling {
					visit(child)
				}
			}
			visit(doc)
			if frames != 1 || strings.Contains(w.Body.String(), token) {
				t.Fatalf("wrapper iframe count=%d or credential exposed", frames)
			}
		})
	}
}

func TestProviderRelayDocumentAlwaysHasOpaqueSandbox(t *testing.T) {
	for _, contentType := range []string{"text/html", "application/xhtml+xml", "image/svg+xml", "text/plain", "application/javascript"} {
		t.Run(contentType, func(t *testing.T) {
			h, _, id := relayTestHandler(t, func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {contentType}}, Body: io.NopCloser(strings.NewReader(`<script>window.untrustedProvider=1</script>`))}, nil
			})
			response := relayTestRequest(h, id, http.MethodGet, "https://provider.test/widget/document", "")
			found := false
			for _, policy := range response.Header().Values("Content-Security-Policy") {
				if policy == "sandbox allow-scripts allow-forms" {
					found = true
				}
			}
			if response.Code != http.StatusOK || !found || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("direct resource document gains local origin: %d %v", response.Code, response.Header())
			}
		})
	}
}
