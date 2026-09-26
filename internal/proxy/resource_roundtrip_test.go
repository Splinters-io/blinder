package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/captcha"
)

func TestResourceURLSubmittedValueRoundTrip(t *testing.T) {
	const original = "http://main.example:8080/return"
	var submitted string
	s := mappingReviewServer(t, "http://main.example:8080", nil, func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			submitted = string(b)
			return audit267SRIResponse("text/plain", "ok"), nil
		}
		return audit267SRIResponse("application/javascript", `window.returnURL="`+original+`";`), nil
	})
	view := httptest.NewRecorder()
	s.ServeHTTP(view, httptest.NewRequest("GET", "https://127.0.0.1:18099/script", nil))
	parts := strings.Split(view.Body.String(), `"`)
	if len(parts) < 3 {
		t.Fatalf("unexpected JS %s", view.Body.String())
	}
	post := httptest.NewRequest("POST", "https://127.0.0.1:18099/save", strings.NewReader(`{"returnURL":"`+parts[1]+`"}`))
	post.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(httptest.NewRecorder(), post)
	if want := `{"returnURL":"` + original + `"}`; submitted != want {
		t.Fatalf("upstream %s want %s", submitted, want)
	}
}

func TestResponseDomainOnlyURLRemainsReversibleInJSONAndText(t *testing.T) {
	const originalURL = "http://main.example:8080/return"
	for _, contentType := range []string{"application/json", "text/plain"} {
		t.Run(contentType, func(t *testing.T) {
			original := originalURL
			if contentType == "application/json" {
				original = `{"url":"` + originalURL + `","n":9007199254740993}`
			}
			var submitted string
			s := mappingReviewServer(t, "http://main.example:8080", nil, func(r *http.Request) (*http.Response, error) {
				if r.Method == "POST" {
					b, _ := io.ReadAll(r.Body)
					submitted = string(b)
					return audit267SRIResponse("text/plain", "ok"), nil
				}
				return audit267SRIResponse(contentType, original), nil
			})
			view := httptest.NewRecorder()
			s.ServeHTTP(view, httptest.NewRequest("GET", "https://127.0.0.1:18099/value", nil))
			if strings.Contains(view.Body.String(), "main.example") {
				t.Fatalf("response leaked target: %s", view.Body.String())
			}
			post := httptest.NewRequest("POST", "https://127.0.0.1:18099/save", strings.NewReader(view.Body.String()))
			post.Header.Set("Content-Type", contentType)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, post)
			if w.Code != 200 || submitted != original {
				t.Fatalf("status=%d emitted=%s submitted=%s want=%s", w.Code, view.Body.String(), submitted, original)
			}
		})
	}
}

func TestSubmittedResourceURLFormatsKeepUnchangedBytesAndOpaqueFields(t *testing.T) {
	const local = "https://127.0.0.1:18099/a%2fb?keep=%2f#"
	const original = "http://main.example:8080/a%2fb?keep=%2f#"
	for _, format := range []string{"json", "form", "query"} {
		t.Run(format, func(t *testing.T) {
			var body, query string
			s := mappingReviewServer(t, "http://main.example:8080", nil, func(r *http.Request) (*http.Response, error) {
				b, _ := io.ReadAll(r.Body)
				body = string(b)
				query = r.URL.RawQuery
				if r.ContentLength != int64(len(b)) {
					t.Fatalf("wrong restored ContentLength %d actual %d", r.ContentLength, len(b))
				}
				return audit267SRIResponse("text/plain", "ok"), nil
			})
			s.captchaMatcher = captcha.NewMatcher(&captcha.Config{Providers: []captcha.Provider{{Name: "synthetic", OpaqueFields: []string{"opaque"}, Submissions: []captcha.SubmissionRule{{Target: "main.example", Method: "POST"}}}}})
			input := `{"n":9007199254740993,"dec":1.2300e+04, "escaped":"\u0041", "` + local + `":"` + local + `", "nested":{"opaque":"` + local + `"}}`
			want := `{"n":9007199254740993,"dec":1.2300e+04, "escaped":"\u0041", "` + original + `":"` + original + `", "nested":{"opaque":"` + local + `"}}`
			ct := "application/json"
			requestURL := "https://127.0.0.1:18099/save"
			if format != "json" {
				input = "untouched=one%20two&&" + url.QueryEscape(local) + "=" + url.QueryEscape(local) + "&opaque=" + url.QueryEscape(local) + "&bare"
				want = "untouched=one%20two&&" + url.QueryEscape(original) + "=" + url.QueryEscape(original) + "&opaque=" + url.QueryEscape(local) + "&bare"
				ct = "application/x-www-form-urlencoded"
			}
			if format == "query" {
				requestURL += "?" + input
				input = ""
			}
			r := httptest.NewRequest("POST", requestURL, strings.NewReader(input))
			r.Header.Set("Content-Type", ct)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			got := body
			if format == "query" {
				got = query
			}
			if w.Code != 200 || got != want {
				t.Fatalf("status=%d got=%s want=%s", w.Code, got, want)
			}
		})
	}
}

func TestSubmittedResourceURLCollisionRejectsBeforeUpstream(t *testing.T) {
	s := mappingReviewServer(t, "http://main.example:8080", nil, func(*http.Request) (*http.Response, error) { t.Fatal("ambiguous JSON reached target"); return nil, nil })
	r := httptest.NewRequest("POST", "https://127.0.0.1:18099/save", strings.NewReader(`{"https://127.0.0.1:18099/key":1,"http://main.example:8080/key":2}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("status=%d", w.Code)
	}
}
