package proxy

import (
	"encoding/json"
	"fmt"
	stdhtml "html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/sri"
	xhtml "golang.org/x/net/html"
)

// Read a transformed document, edit one ordinary field, then submit its values.
// The upstream must receive the originals for transformed fields and the edit.
func TestReversibleReviewDocumentValuesRoundTrip(t *testing.T) {
	for _, mode := range []string{"json", "html_form"} {
		t.Run(mode, func(t *testing.T) {
			original := map[string]string{
				"name": "AcmeCorp", "case": "ACMECORP", "literal": "[REDACTED]",
				"mail1": "alice@fixture.synthetic", "mail2": "bob@fixture.synthetic",
				"host": "main.example", "ip1": "198.51.100.10", "ip2": "192.0.2.20",
			}
			var received map[string]string
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				if r.Method == "POST" {
					received = make(map[string]string)
					if mode == "json" {
						if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
							t.Fatalf("upstream JSON invalid: %v", err)
						}
					} else {
						if err := r.ParseForm(); err != nil {
							t.Fatalf("upstream form invalid: %v", err)
						}
						for k := range r.PostForm {
							received[k] = r.PostForm.Get(k)
						}
					}
					return audit267SRIResponse("application/json", `{"ok":true}`), nil
				}
				if mode == "json" {
					body, err := json.Marshal(original)
					if err != nil {
						t.Fatal(err)
					}
					return audit267SRIResponse("application/json", string(body)), nil
				}
				var body strings.Builder
				body.WriteString(`<form method="post" action="/submit">`)
				for name, value := range original {
					fmt.Fprintf(&body, `<input name="%s" value="%s">`, name, stdhtml.EscapeString(value))
				}
				body.WriteString(`</form>`)
				return audit267SRIResponse("text/html", body.String()), nil
			})
			doc := audit267CacheRequest(s, "GET", "/model", nil)
			if doc.Code != 200 {
				t.Fatalf("document failed: %d", doc.Code)
			}
			values := make(map[string]string)
			if mode == "json" {
				if err := json.Unmarshal(doc.Body.Bytes(), &values); err != nil {
					t.Fatalf("downstream JSON invalid: %v", err)
				}
			} else {
				z := xhtml.NewTokenizer(strings.NewReader(doc.Body.String()))
				for z.Next() != xhtml.ErrorToken {
					tok := z.Token()
					if tok.Data != "input" {
						continue
					}
					var name, value string
					for _, a := range tok.Attr {
						if a.Key == "name" {
							name = a.Val
						}
						if a.Key == "value" {
							value = a.Val
						}
					}
					if name != "" {
						values[name] = value
					}
				}
			}
			if values["name"] == original["name"] {
				t.Fatal("fixture did not transform identifying values")
			}
			values["note"] = "operator edit"
			var payload, contentType string
			if mode == "json" {
				body, err := json.Marshal(values)
				if err != nil {
					t.Fatal(err)
				}
				payload, contentType = string(body), "application/json"
			} else {
				form := make(url.Values)
				for k, v := range values {
					form.Set(k, v)
				}
				payload, contentType = form.Encode(), "application/x-www-form-urlencoded"
			}
			r := httptest.NewRequest("POST", "https://127.0.0.1:18099/submit", strings.NewReader(payload))
			r.Header.Set("Content-Type", contentType)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 200 || received == nil {
				t.Fatalf("submission failed: status=%d", w.Code)
			}
			for field, want := range original {
				if got := received[field]; got != want {
					t.Errorf("round trip lost original field %s: downstream=%q upstream=%q want=%q", field, values[field], got, want)
				}
			}
			if received["note"] != "operator edit" {
				t.Errorf("operator's new value lost: %q", received["note"])
			}
		})
	}
}

func TestReversibleReviewExistingQueryKeepsVersionBinding(t *testing.T) {
	for _, resource := range []string{"/asset?_bv=app", "/asset?q=_bv=app", "/asset#_bv=section"} {
		t.Run(resource, func(t *testing.T) {
			version := 1
			body := func() string { return fmt.Sprintf("var version=%d;", version) }
			expectedURI := audit750BrowserPath(t, resource)
			s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/page" {
					return audit267SRIResponse("text/html", audit267SRIPage(resource, body())), nil
				}
				if r.URL.RequestURI() != expectedURI {
					resp := audit267SRIResponse("text/plain", "query changed")
					resp.StatusCode = 404
					return resp, nil
				}
				resp := audit267SRIResponse("application/javascript", body())
				resp.Header.Set("Cache-Control", "no-store")
				return resp, nil
			})
			first := audit267CacheRequest(s, "GET", "/page", nil)
			firstPath := audit750BrowserPath(t, audit267SRIAttribute(first.Body.String(), "src"))
			firstHash := audit267SRIAttribute(first.Body.String(), "integrity")
			control := audit267CacheRequest(s, "GET", firstPath, nil)
			valid, _ := sri.Verify(control.Body.Bytes(), sri.ParseIntegrity(firstHash))
			if control.Code != 200 || !valid {
				t.Fatal("initial valid resource did not load")
			}
			version = 2
			second := audit267CacheRequest(s, "GET", "/page", nil)
			secondHash := audit267SRIAttribute(second.Body.String(), "integrity")
			current := audit267CacheRequest(s, "GET", audit750BrowserPath(t, audit267SRIAttribute(second.Body.String(), "src")), nil)
			valid, _ = sri.Verify(current.Body.Bytes(), sri.ParseIntegrity(secondHash))
			if firstHash == secondHash || current.Code != 200 || !valid {
				t.Fatal("newly verified resource did not load")
			}
			old := audit267CacheRequest(s, "GET", firstPath, nil)
			valid, _ = sri.Verify(old.Body.Bytes(), sri.ParseIntegrity(firstHash))
			if old.Code == 200 && !valid {
				t.Fatalf("version binding disabled for existing URL text: issued URL=%q status=%d incompatible body=%q", firstPath, old.Code, old.Body.String())
			}
		})
	}
}

func TestReversibleReviewPrefixDoesNotProveQueryOwnership(t *testing.T) {
	const requestURI = "/api?_bv=bl0123456789abcdef&keep=value"
	var forwarded string
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		forwarded = r.URL.RequestURI()
		return audit267SRIResponse("text/plain", "ok"), nil
	})
	got := audit267CacheRequest(s, "GET", requestURI, nil)
	if got.Code != 200 || forwarded != requestURI {
		t.Fatalf("ordinary application query misclassified: requested=%q forwarded=%q status=%d body=%q", requestURI, forwarded, got.Code, got.Body.String())
	}
}
