package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestSignedReviewPublicConfigurationCannotMintOwnership(t *testing.T) {
	var forwarded string
	s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
		forwarded = r.URL.RequestURI()
		return audit267SRIResponse("text/plain", "ok"), nil
	})
	// Forge a 128-bit MAC from public config. The registry uses a random secret,
	// so any deterministic derivation must fail.
	secret := sha256.Sum256([]byte("blinder-version-registry\x00alias.local\x00main.example"))
	const data = "0123456789abcdef"
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte(data))
	forged := data + hex.EncodeToString(mac.Sum(nil)[:16])
	uri := "/api?__blv=" + forged + "&keep=value"
	got := audit267CacheRequest(s, "GET", uri, nil)
	if got.Code != 200 || forwarded != uri {
		t.Fatalf("application __blv intercepted as proxy metadata: input=%q forwarded=%q status=%d body=%q", uri, forwarded, got.Code, got.Body.String())
	}
}

func TestSignedReviewEscapeGrammarClosesOverItsOwnOutput(t *testing.T) {
	g := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	marker := scrub.ValueAliasPrefix + "probe]"
	for depth := 0; depth < 8; depth++ {
		original := "before " + marker + " after AcmeCorp"
		transformed := g.Scrub(original, "document")
		if restored := g.RestoreBody(transformed); restored != original {
			t.Fatalf("round trip fails for emitted escape syntax at depth %d: original=%q transformed=%q restored=%q", depth, original, transformed, restored)
		}
		marker = g.Scrub(marker, "discover-next-marker")
	}
}

func TestSignedPropertyEscapeDepthRoundTrip(t *testing.T) {
	for _, tokens := range [][]string{
		nil,
		{"X"},
		{"AcmeCorp", "SecretProject"},
	} {
		g := scrub.NewGate(nil, tokens, "alias.local")
		marker := scrub.ValueAliasPrefix + "depth-test]"
		for depth := 0; depth < 16; depth++ {
			identity := ""
			if len(tokens) > 0 {
				identity = " " + tokens[0]
			}
			original := marker + identity
			transformed := g.Scrub(original, "doc")
			restored := g.RestoreBody(transformed)
			if restored != original {
				t.Fatalf("tokens=%v depth=%d: original=%q restored=%q", tokens, depth, original, restored)
			}
			marker = g.Scrub(marker, "next")
		}
	}
}

func TestSignedPropertyVersionBindingPreservesMatchingRequest(t *testing.T) {
	resources := []string{
		"/asset",
		"/asset?choice=one",
		"/asset?a=1&b=2",
		"/asset?__blv=appdata",
	}
	for _, res := range resources {
		t.Run(res, func(t *testing.T) {
			body := "var x=1;"
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/page" {
					return audit267SRIResponse("text/html", audit267SRIPage(res, body)), nil
				}
				return audit267SRIResponse("application/javascript", body), nil
			})
			page := audit267CacheRequest(s, "GET", "/page", nil)
			src := audit267SRIAttribute(page.Body.String(), "src")
			if src == "" {
				t.Fatal("no src emitted")
			}
			got := audit267CacheRequest(s, "GET", audit750BrowserPath(t, src), nil)
			if got.Code != 200 {
				t.Fatalf("matching request rejected: src=%q status=%d body=%q", src, got.Code, got.Body.String())
			}
		})
	}
}

func TestSignedPropertyWriteMethodRejectedWithToken(t *testing.T) {
	methods := []string{"POST", "PUT", "DELETE", "PATCH"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			body := "var x=1;"
			var forwarded bool
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/page" {
					return audit267SRIResponse("text/html", audit267SRIPage("/asset", body)), nil
				}
				forwarded = true
				return audit267SRIResponse("application/javascript", body), nil
			})
			page := audit267CacheRequest(s, "GET", "/page", nil)
			src := audit267SRIAttribute(page.Body.String(), "src")
			u, _ := url.Parse(src)
			token := u.Query().Get("__blv")
			if token == "" {
				t.Fatal("no token")
			}
			forwarded = false
			r := httptest.NewRequest(method, "https://alias.local:18099/asset?__blv="+url.QueryEscape(token), strings.NewReader("body"))
			r.Header.Set("Content-Type", "application/octet-stream")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if forwarded {
				t.Fatalf("%s with version token was forwarded upstream", method)
			}
			if w.Code < 400 {
				t.Fatalf("%s accepted: status=%d", method, w.Code)
			}
		})
	}
}

func TestSignedReviewReferenceDoesNotRetargetRequest(t *testing.T) {
	for _, tc := range []struct{ name, method, path, query string }{
		{"different_path", "GET", "/different", "choice=one"},
		{"edited_application_query", "GET", "/asset", "choice=two"},
		{"write_method", "POST", "/submit", "choice=one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const asset = "var value=1;"
			var calls []string
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/page" {
					return audit267SRIResponse("text/html", audit267SRIPage("/asset?choice=one", asset)), nil
				}
				var body []byte
				if r.Body != nil {
					body, _ = io.ReadAll(r.Body)
				}
				calls = append(calls, fmt.Sprintf("%s %s body=%q", r.Method, r.URL.RequestURI(), body))
				resp := audit267SRIResponse("application/javascript", asset)
				resp.Header.Set("Cache-Control", "no-store")
				return resp, nil
			})
			page := audit267CacheRequest(s, "GET", "/page", nil)
			src := audit267SRIAttribute(page.Body.String(), "src")
			u, err := url.Parse(src)
			if err != nil || src == "" {
				t.Fatalf("fixture reference missing: %q %v", src, err)
			}
			token := u.Query().Get("__blv")
			if token == "" {
				t.Fatal("fixture token missing")
			}
			calls = nil
			uri := tc.path + "?" + tc.query + "&__blv=" + url.QueryEscape(token)
			var payload io.Reader
			if tc.method == "POST" {
				payload = strings.NewReader("note=operator-edit")
			}
			r := httptest.NewRequest(tc.method, "https://alias.local:18099"+uri, payload)
			if tc.method == "POST" {
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if len(calls) > 0 {
				t.Fatalf("resource-bound token silently changed request destination instead of rejecting mismatch: requested=%s %s forwarded=%q status=%d", tc.method, uri, calls, w.Code)
			}
			if w.Code < 400 {
				t.Fatalf("mismatched reference served successfully: status=%d body=%q", w.Code, w.Body.String())
			}
		})
	}
}
