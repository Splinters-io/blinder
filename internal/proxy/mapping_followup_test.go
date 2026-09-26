package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
	"github.com/Splinters-io/blinder/internal/sri"
)

func TestMappingFollowupJSONNumberPrecision(t *testing.T) {
	for _, number := range []string{"9007199254740993", "18446744073709551615", "0.123456789012345678901"} {
		t.Run(number, func(t *testing.T) {
			var forwarded []byte
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				forwarded, _ = io.ReadAll(r.Body)
				return audit267SRIResponse("text/plain", "ok"), nil
			})
			payload := `{"id":` + number + `,"note":"operator edit"}`
			r := httptest.NewRequest("POST", "https://alias.local:18099/api", strings.NewReader(payload))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			decoder := json.NewDecoder(strings.NewReader(string(forwarded)))
			decoder.UseNumber()
			var values map[string]any
			if err := decoder.Decode(&values); err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprint(values["id"]); got != number {
				t.Fatalf("untouched JSON number rounded: input=%s forwarded=%s", payload, forwarded)
			}
		})
	}
}

func TestMappingFollowupVersionQueryOwnership(t *testing.T) {
	t.Run("application_request", func(t *testing.T) {
		const uri = "/api?__blv=app&keep=value"
		var forwarded string
		s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
			forwarded = r.URL.RequestURI()
			return audit267SRIResponse("text/plain", "ok"), nil
		})
		got := audit267CacheRequest(s, "GET", uri, nil)
		if got.Code != 200 || forwarded != uri {
			t.Fatalf("application-owned parameter consumed by proxy: status=%d forwarded=%q body=%q", got.Code, forwarded, got.Body.String())
		}
	})
	t.Run("versioned_resource", func(t *testing.T) {
		const asset = "var value=1;"
		s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/page" {
				return audit267SRIResponse("text/html", audit267SRIPage("/asset?__blv=app", asset)), nil
			}
			if r.URL.RawQuery != "__blv=app" {
				return nil, fmt.Errorf("application query changed: %s", r.URL)
			}
			return audit267SRIResponse("application/javascript", asset), nil
		})
		page := audit267CacheRequest(s, "GET", "/page", nil)
		src := audit267SRIAttribute(page.Body.String(), "src")
		if src == "" {
			t.Fatal("fixture did not produce a verified reference")
		}
		got := audit267CacheRequest(s, "GET", audit750BrowserPath(t, src), nil)
		valid, _ := sri.Verify(got.Body.Bytes(), sri.ParseIntegrity(audit267SRIAttribute(page.Body.String(), "integrity")))
		if got.Code != 200 || !valid {
			t.Fatalf("valid SRI resource broken by existing __blv: src=%q status=%d body=%q", src, got.Code, got.Body.String())
		}
	})
}

func mappingFollowupExtraOrigin(t *testing.T, policy string) (*Server, http.CookieJar, *url.URL, string, *[]string) {
	t.Helper()
	const asset = "var value=1;"
	observed := []string{}
	s := mappingReviewServer(t, "https://main.example", []string{"AcmeCorp"}, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "assets.example" {
			observed = append(observed, r.Header.Get("Cookie"))
			resp := audit267SRIResponse("application/javascript", asset)
			resp.Header.Set("Cache-Control", policy)
			resp.Header.Set("Access-Control-Allow-Origin", "https://main.example")
			return resp, nil
		}
		if r.URL.Path == "/login" {
			resp := audit267SRIResponse("text/plain", "ok")
			resp.Header.Set("Set-Cookie", "sid=primary-session; Path=/; Secure; HttpOnly")
			return resp, nil
		}
		return audit267SRIResponse("text/html", audit267SRIPage("https://assets.example/asset", asset)), nil
	}, "https://assets.example")
	jar, _ := cookiejar.New(nil)
	base, _ := url.Parse("https://alias.local:18099/page")
	mappingReviewBrowser(t, s, jar, "https://alias.local:18099/login")
	page := mappingReviewBrowser(t, s, jar, base.String())
	src := audit267SRIAttribute(page.Body.String(), "src")
	if src == "" || len(observed) != 1 || observed[0] != "" {
		t.Fatalf("fixture prefetch: src=%q cookies=%q", src, observed)
	}
	resource, err := base.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if resource.Host == base.Host {
		t.Fatal("resource did not retain separate origin")
	}
	return s, jar, resource, audit267SRIAttribute(page.Body.String(), "integrity"), &observed
}

func TestMappingFollowupExtraOriginResourceActuallyLoads(t *testing.T) {
	for _, policy := range []string{"no-store", "max-age=3600"} {
		t.Run(policy, func(t *testing.T) {
			s, jar, resource, integrity, observed := mappingFollowupExtraOrigin(t, policy)
			got := mappingReviewBrowser(t, s, jar, resource.String())
			for _, cookie := range *observed {
				if cookie != "" {
					t.Fatalf("extra origin received primary cookie: %q", *observed)
				}
			}
			valid, _ := sri.Verify(got.Body.Bytes(), sri.ParseIntegrity(integrity))
			if got.Code != 200 || !valid {
				t.Fatalf("valid anonymous extra-origin resource fails after credentialed page prefetch: url=%s status=%d body=%q", resource, got.Code, got.Body.String())
			}
		})
	}
}

func TestMappingFollowupVersionCannotRetargetPrimaryCredentials(t *testing.T) {
	s, jar, resource, _, observed := mappingFollowupExtraOrigin(t, "no-store")
	// Moving a reference to a different local origin must not let it route that
	// origin's credentials to the reference's unrelated upstream.
	resource.Host = "alias.local:18099"
	got := mappingReviewBrowser(t, s, jar, resource.String())
	for _, cookie := range *observed {
		if cookie != "" {
			t.Fatalf("version reference accepted under wrong origin and forwarded its cookies: url=%s upstream cookies=%q status=%d", resource, *observed, got.Code)
		}
	}
}

func TestMappingFollowupLiteralEscapeRoundTrip(t *testing.T) {
	t.Run("literal_escape_prefix", func(t *testing.T) {
		g := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
		original := "literal [LITERAL:fixture] and identity AcmeCorp"
		transformed := g.Scrub(original, "document")
		if got := g.RestoreBody(transformed); got != original {
			t.Fatalf("escape prefix not self-escaped: original=%q transformed=%q restored=%q", original, transformed, got)
		}
	})
	for _, original := range []string{scrub.ValueAliasPrefix + "fixture]", "[REDACTED:fixture]"} {
		t.Run("form_literal_"+original, func(t *testing.T) {
			var received string
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				if r.Method == "POST" {
					r.ParseForm()
					received = r.PostForm.Get("name")
					return audit267SRIResponse("text/plain", "ok"), nil
				}
				return audit267SRIResponse("text/html", `<form><input name="name" value="`+original+`"></form>`), nil
			})
			page := audit267CacheRequest(s, "GET", "/model", nil)
			value := audit267SRIAttribute(page.Body.String(), "value")
			r := httptest.NewRequest("POST", "https://alias.local:18099/submit", strings.NewReader(url.Values{"name": {value}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			s.ServeHTTP(httptest.NewRecorder(), r)
			if received != original {
				t.Fatalf("ContainsAlias skips escaped literal: emitted=%q forwarded=%q want=%q", value, received, original)
			}
		})
	}
	t.Run("CSS_rewrite_passes", func(t *testing.T) {
		var received string
		s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/style" {
				return audit267SRIResponse("text/css", `a { background: url("/asset?name=AcmeCorp"); }`), nil
			}
			received = r.URL.Query().Get("name")
			return audit267SRIResponse("text/plain", "ok"), nil
		})
		css := audit267CacheRequest(s, "GET", "/style", nil)
		match := regexp.MustCompile(`url\("([^"]+)"\)`).FindStringSubmatch(css.Body.String())
		if len(match) != 2 {
			t.Fatalf("no URL in CSS: %s", css.Body.String())
		}
		audit267CacheRequest(s, "GET", match[1], nil)
		if received != "AcmeCorp" {
			t.Fatalf("later scrub pass escapes its own generated alias: css=%q upstream value=%q", css.Body.String(), received)
		}
	})
}
