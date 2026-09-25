package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
	"github.com/Splinters-io/blinder/internal/sri"
)

func TestOwnershipReviewVersionBindingIncludesScheme(t *testing.T) {
	const asset = "var value=1;"
	var observed []string
	s := mappingReviewServer(t, "https://main.example", []string{"AcmeCorp"}, func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme == "http" {
			observed = append(observed, r.Header.Get("Cookie"))
			resp := audit267SRIResponse("application/javascript", asset)
			resp.Header.Set("Cache-Control", "no-store")
			return resp, nil
		}
		if r.URL.Path == "/login" {
			resp := audit267SRIResponse("text/plain", "ok")
			resp.Header.Set("Set-Cookie", "sid=secure-primary; Path=/; Secure; HttpOnly")
			return resp, nil
		}
		return audit267SRIResponse("text/html", audit267SRIPage("http://main.example/asset", asset)), nil
	}, "http://main.example")
	jar, _ := cookiejar.New(nil)
	base, _ := url.Parse("https://alias.local:18099/page")
	mappingReviewBrowser(t, s, jar, "https://alias.local:18099/login")
	page := mappingReviewBrowser(t, s, jar, base.String())
	src := audit267SRIAttribute(page.Body.String(), "src")
	resource, err := base.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if src == "" || resource.Host == base.Host || len(observed) != 1 || observed[0] != "" {
		t.Fatalf("fixture expected isolated anonymous prefetch: src=%q cookies=%q", src, observed)
	}
	resource.Host = base.Host
	got := mappingReviewBrowser(t, s, jar, resource.String())
	for _, cookie := range observed {
		if cookie != "" {
			t.Fatalf("HTTPS-origin reference guard accepted HTTP upstream and forwarded its secure cookie: upstream cookies=%q status=%d", observed, got.Code)
		}
	}
}

func TestOwnershipReviewPrefixDoesNotProveQueryOwnership(t *testing.T) {
	for _, value := range []string{"bv:application-value", "bv:0123456789abcdef"} {
		t.Run(value, func(t *testing.T) {
			var forwarded string
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				forwarded = r.URL.RequestURI()
				return audit267SRIResponse("text/plain", "ok"), nil
			})
			uri := "/api?__blv=" + value + "&keep=value"
			got := audit267CacheRequest(s, "GET", uri, nil)
			if got.Code != 200 || forwarded != uri {
				t.Fatalf("unissued app-owned query consumed by prefix: input=%q forwarded=%q status=%d body=%q", uri, forwarded, got.Code, got.Body.String())
			}
		})
	}
}

func TestOwnershipReviewLiteralEscapeMarkerRoundTrips(t *testing.T) {
	g := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	// Use the actual public output marker; do not assume its spelling or nonce.
	emitted := g.Scrub("[REDACTED:fixture]", "probe")
	if emitted == "[REDACTED:fixture]" {
		t.Fatal("fixture did not escape")
	}
	original := "literal " + emitted + " and identity AcmeCorp"
	transformed := g.Scrub(original, "document")
	if got := g.RestoreBody(transformed); got != original {
		t.Fatalf("literal generated-marker text not escaped: original=%q transformed=%q restored=%q", original, transformed, got)
	}
}

func TestOwnershipReviewCSSPlaceholderCannotMatchConfiguredToken(t *testing.T) {
	const original = `a { background: url("/asset"); }`
	s := mappingReviewServer(t, "https://main.example", []string{"CSSURL"}, func(r *http.Request) (*http.Response, error) { return audit267SRIResponse("text/css", original), nil })
	got := audit267CacheRequest(s, "GET", "/style", nil)
	if got.Code != 200 || got.Body.String() != original {
		t.Fatalf("internal CSS placeholder was scrubbed and could not be restored: got=%q want=%q", got.Body.String(), original)
	}
}

func TestOwnershipReviewJSONRestorationCannotDiscardInput(t *testing.T) {
	for _, suffix := range []string{` {"second":2}`, ` trailing-content`} {
		t.Run(suffix, func(t *testing.T) {
			var forwarded string
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				b, _ := io.ReadAll(r.Body)
				forwarded = string(b)
				resp := audit267SRIResponse("text/plain", "ok")
				if !json.Valid(b) {
					resp.StatusCode = 400
				}
				return resp, nil
			})
			payload := `{"first":1}` + suffix
			r := httptest.NewRequest("POST", "https://alias.local:18099/api", strings.NewReader(payload))
			r.Header.Set("Content-Type", "application/json")
			got := httptest.NewRecorder()
			s.ServeHTTP(got, r)
			if forwarded != "" && forwarded != payload {
				t.Fatalf("request truncated into a valid JSON document: input=%q forwarded=%q status=%d", payload, forwarded, got.Code)
			}
		})
	}
	t.Run("inverse_key_collision", func(t *testing.T) {
		var forwarded []byte
		s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
			forwarded, _ = io.ReadAll(r.Body)
			return audit267SRIResponse("text/plain", "ok"), nil
		})
		alias := s.gate.Scrub("AcmeCorp", "document-key")
		body, _ := json.Marshal(map[string]int{alias: 1, "AcmeCorp": 2})
		r := httptest.NewRequest("POST", "https://alias.local:18099/api", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		got := httptest.NewRecorder()
		s.ServeHTTP(got, r)
		if len(forwarded) == 0 && got.Code >= 400 {
			return
		}
		var decoded map[string]int
		if err := json.Unmarshal(forwarded, &decoded); err != nil {
			t.Fatal(err)
		}
		if len(decoded) != 2 {
			t.Fatalf("restored keys collide and one field is silently lost: submitted=%s forwarded=%s status=%d", body, forwarded, got.Code)
		}
		t.Log(fmt.Sprint(decoded))
	})
}

func TestOwnershipPropertyLiteralMarkerRoundTrip(t *testing.T) {
	for _, tokens := range [][]string{
		{"AcmeCorp"},
		{"AcmeCorp", "SecretProject"},
		{"x"},
	} {
		g := scrub.NewGate(nil, tokens, "alias.local")
		marker := g.Scrub("[REDACTED:probe]", "discover")
		cases := []string{
			"before " + marker + " after",
			marker + marker,
			"nested [REDACTED:" + marker + "]",
			marker,
		}
		for _, original := range cases {
			full := original + " identity " + tokens[0]
			transformed := g.Scrub(full, "body")
			restored := g.RestoreBody(transformed)
			if restored != full {
				t.Errorf("literal marker round-trip failed: tokens=%v original=%q transformed=%q restored=%q", tokens, full, transformed, restored)
			}
		}
	}
}

func TestOwnershipPropertyPrefixShapedAppValues(t *testing.T) {
	prefixes := []string{
		"bv:app-data",
		"bv:0123456789abcdef",
		"bv:",
		"bv:bv:nested",
		"abc123",
		"",
		"a]b[c",
	}
	for _, value := range prefixes {
		t.Run(value, func(t *testing.T) {
			var forwarded string
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				forwarded = r.URL.RequestURI()
				return audit267SRIResponse("text/plain", "ok"), nil
			})
			uri := "/path?__blv=" + url.QueryEscape(value) + "&other=kept"
			got := audit267CacheRequest(s, "GET", uri, nil)
			if got.Code != 200 {
				t.Fatalf("app value rejected: value=%q status=%d body=%q", value, got.Code, got.Body.String())
			}
			if forwarded != uri {
				t.Fatalf("app query mutated: input=%q forwarded=%q", uri, forwarded)
			}
		})
	}
}

func TestOwnershipPropertyOriginComparisonBlocks(t *testing.T) {
	cases := []struct {
		name    string
		primary string
		extra   string
	}{
		{"scheme_mismatch", "https://target.example", "http://target.example"},
		{"port_mismatch", "https://target.example", "https://target.example:8443"},
		{"host_mismatch", "https://a.example", "https://b.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const asset = "var x=1;"
			var upstreamCookies []string
			s := mappingReviewServer(t, tc.primary, []string{"AcmeCorp"}, func(r *http.Request) (*http.Response, error) {
				origin := r.URL.Scheme + "://" + r.URL.Host
				if origin == tc.extra {
					upstreamCookies = append(upstreamCookies, r.Header.Get("Cookie"))
					resp := audit267SRIResponse("application/javascript", asset)
					resp.Header.Set("Cache-Control", "no-store")
					return resp, nil
				}
				if r.URL.Path == "/login" {
					resp := audit267SRIResponse("text/plain", "ok")
					resp.Header.Set("Set-Cookie", "sid=s; Path=/; Secure; HttpOnly")
					return resp, nil
				}
				return audit267SRIResponse("text/html", audit267SRIPage(tc.extra+"/asset", asset)), nil
			}, tc.extra)
			jar, _ := cookiejar.New(nil)
			base, _ := url.Parse("https://alias.local:18099/page")
			mappingReviewBrowser(t, s, jar, "https://alias.local:18099/login")
			page := mappingReviewBrowser(t, s, jar, base.String())
			src := audit267SRIAttribute(page.Body.String(), "src")
			if src == "" {
				t.Fatal("no src in fixture page")
			}
			resource, err := base.Parse(src)
			if err != nil {
				t.Fatal(err)
			}
			resource.Host = base.Host
			mappingReviewBrowser(t, s, jar, resource.String())
			for _, c := range upstreamCookies {
				if c != "" {
					t.Fatalf("origin guard did not block: primary=%s extra=%s cookie=%q", tc.primary, tc.extra, c)
				}
			}
		})
	}
}

func TestOwnershipPropertyIssuedTokenSurvivesAppBlv(t *testing.T) {
	const asset = "var x=1;"
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset?__blv=appdata", asset)), nil
		}
		return audit267SRIResponse("application/javascript", asset), nil
	})
	page := audit267CacheRequest(s, "GET", "/page", nil)
	src := audit267SRIAttribute(page.Body.String(), "src")
	integrity := audit267SRIAttribute(page.Body.String(), "integrity")
	if src == "" || integrity == "" {
		t.Fatal("fixture did not produce verified reference")
	}
	got := audit267CacheRequest(s, "GET", audit750BrowserPath(t, src), nil)
	valid, _ := sri.Verify(got.Body.Bytes(), sri.ParseIntegrity(integrity))
	if got.Code != 200 || !valid {
		t.Fatalf("issued token alongside app __blv failed: src=%q status=%d", src, got.Code)
	}
}
