package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCaptchaSessionJSONTrailingDataIsNotDiscarded(t *testing.T) {
	for _, suffix := range []string{` {"second":2}`, ` unexpected`} {
		t.Run(suffix, func(t *testing.T) {
			var forwarded string
			s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
				b, _ := io.ReadAll(r.Body)
				forwarded = string(b)
				return audit267SRIResponse("text/plain", "accepted"), nil
			})
			payload := `{"first":1,"h-captcha-response":"opaque"}` + suffix
			r := httptest.NewRequest("POST", "https://alias.local:18099/login", strings.NewReader(payload))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if forwarded != "" && forwarded != payload {
				t.Fatalf("CAPTCHA opacity silently truncated JSON input: input=%q forwarded=%q", payload, forwarded)
			}
		})
	}
}

func TestCaptchaSessionRetryHandlesJSONNull(t *testing.T) {
	s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), nil)
	defer func() {
		if value := recover(); value != nil {
			t.Errorf("JSON null makes challenge retry panic: %v", value)
		}
	}()
	s.buildCaptchaRetryBody([]byte("null"), "application/json", map[string]string{"h-captcha-response": "solution"})
}

func TestCaptchaSessionRotatedCookieReplacesOldValue(t *testing.T) {
	var calls atomic.Int32
	var observed string
	s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			resp := audit267SRIResponse("text/html", `<p>Verify you are human</p><script src="https://js.hcaptcha.com/1/api.js"></script>`)
			resp.StatusCode = 403
			resp.Header.Set("Set-Cookie", "sid=rotated; Path=/; Secure")
			return resp, nil
		}
		observed = r.Header.Get("Cookie")
		resp := audit267SRIResponse("text/plain", "accepted")
		cookie, err := r.Cookie("sid")
		if err != nil || cookie.Value != "rotated" {
			resp.StatusCode = 401
		}
		return resp, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("POST", "https://alias.local:18099/login", strings.NewReader("csrf=nonce")).WithContext(ctx)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Cookie", "sid=old")
		w := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(w, r)
		done <- w
	}()
	id := captchaDeliveryWaitID(t, s)
	captchaFollowupWaiter(t, s, id)
	w := captchaDeliveryOperatorPost(s, id, "valid-solution", s.CaptchaOperatorToken())
	if w.Code != 200 {
		t.Fatalf("authenticated fixture completion failed: %d", w.Code)
	}
	select {
	case got := <-done:
		if got.Code != 200 {
			t.Fatalf("retry appends rotated cookie behind old session: cookie=%q target status=%d", observed, got.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("fixture completion did not finish")
	}
}

func TestCaptchaSessionGETChallengeUsesSubmissionEndpoint(t *testing.T) {
	var calls atomic.Int32
	var retry string
	s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			resp := audit267SRIResponse("text/html", `<p>Verify you are human</p><script src="https://js.hcaptcha.com/1/api.js"></script><form method="POST" action="/verify"><input name="csrf" value="nonce"></form>`)
			resp.StatusCode = 403
			return resp, nil
		}
		b, _ := io.ReadAll(r.Body)
		retry = fmt.Sprintf("%s %s body=%q", r.Method, r.URL.Path, b)
		resp := audit267SRIResponse("text/plain", "wrong submission workflow")
		resp.StatusCode = 405
		if r.Method == "POST" && r.URL.Path == "/verify" {
			resp.StatusCode = 200
		}
		return resp, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(w, httptest.NewRequest("GET", "https://alias.local:18099/protected", nil).WithContext(ctx))
		done <- w
	}()
	id := captchaDeliveryWaitID(t, s)
	captchaFollowupWaiter(t, s, id)
	w := captchaDeliveryOperatorPost(s, id, "valid-solution", s.CaptchaOperatorToken())
	if w.Code != 200 {
		t.Fatalf("fixture operator rejected: %d", w.Code)
	}
	select {
	case got := <-done:
		if got.Code != 200 {
			t.Fatalf("GET challenge never uses its verification endpoint: retry=%s status=%d", retry, got.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("fixture completion did not finish")
	}
}

func TestCaptchaSessionSecFetchDestIsolation(t *testing.T) {
	const secret = "AcmeCorp private target page, original identity"
	s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) {
		return audit267SRIResponse("text/html", "<p>proxied</p>"), nil
	})
	s.captchaQueue.Submit("hcaptcha", "https://private-target.synthetic/account", []byte(secret), "text/plain")
	id := s.captchaQueue.Pending()[0].ID
	token := s.CaptchaOperatorToken()

	for _, tc := range []struct {
		name   string
		dest   string
		bearer bool
		expect int
	}{
		{"bearer_no_dest", "", true, 200},
		{"bearer_empty_dest", "empty", true, 200},
		{"cookie_document", "document", false, 200},
		{"cookie_iframe", "iframe", false, 403},
		{"cookie_no_dest", "", false, 200},
		{"cookie_empty_dest_list", "empty", false, 403},
		{"cookie_empty_dest_page", "empty", false, 403},
		{"cookie_script_dest", "script", false, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := "/__blinder/captcha/"
			if strings.Contains(tc.name, "page") {
				path = "/__blinder/captcha/page/" + id
			}
			r := httptest.NewRequest("GET", "https://alias.local:18099"+path, nil)
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer "+token)
			} else {
				r.AddCookie(&http.Cookie{Name: "__blinder_op", Value: token})
			}
			if tc.dest != "" {
				r.Header.Set("Sec-Fetch-Dest", tc.dest)
			}
			w := httptest.NewRecorder()
			s.server.Handler.ServeHTTP(w, r)
			if w.Code != tc.expect {
				t.Fatalf("Sec-Fetch-Dest=%q bearer=%v: got status %d, want %d (body=%q)",
					tc.dest, tc.bearer, w.Code, tc.expect, w.Body.String())
			}
			if tc.expect == 403 {
				return
			}
			if strings.Contains(tc.name, "page") && w.Body.String() == secret {
				if !tc.bearer {
					t.Fatalf("cookie auth with Sec-Fetch-Dest=%q leaked private challenge body", tc.dest)
				}
			}
		})
	}
}

// This test serves only synthetic content and waits for a real local browser.
func TestCaptchaSessionBrowserOperatorIsolation(t *testing.T) {
	if os.Getenv("BLINDER_REVIEW_BROWSER") != "1" {
		t.Skip("opt-in local browser check")
	}
	const secret = "AcmeCorp private target page, original identity"
	const untrusted = `<!doctype html><title>Blinder synthetic isolation check</title><pre id="result">Checking...</pre><script>
(async()=>{
 const result={};
 try {
  const list=await fetch('/__blinder/captcha/');result.listStatus=list.status;
  const markup=await list.text();
  const doc=new DOMParser().parseFromString(markup,'text/html');
  const link=doc.querySelector('a');
  if(link){const id=link.getAttribute('href').split('/').pop();const page=await fetch('/__blinder/captcha/page/'+id);result.pageStatus=page.status;result.pageBody=await page.text();}
 }catch(e){result.error=String(e)}
 document.getElementById('result').textContent=JSON.stringify(result);
 await fetch('/review-report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(result)});
})();</script>`
	s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), func(r *http.Request) (*http.Response, error) { return audit267SRIResponse("text/html", untrusted), nil })
	s.captchaQueue.Submit("hcaptcha", "https://private-target.synthetic/account", []byte(secret), "text/plain")
	report := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/review-bootstrap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		token, _ := json.Marshal("Bearer " + s.CaptchaOperatorToken())
		fmt.Fprintf(w, `<!doctype html><script>(async()=>{const r=await fetch('/__blinder/captcha/',{headers:{Authorization:%s}});if(r.status===200)location.href='/fixture-page';else document.body.textContent='bootstrap failed';})()</script>`, token)
	})
	mux.HandleFunc("/review-report", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		http.SetCookie(w, &http.Cookie{Name: "__blinder_op", Value: "", Path: "/__blinder/captcha/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		w.WriteHeader(204)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		report <- string(b)
	})
	mux.Handle("/", s.server.Handler)
	server := httptest.NewServer(mux)
	defer server.Close()
	u, _ := url.Parse(server.URL)
	u.Host = "localhost:" + u.Port()
	u.Path = "/review-bootstrap"
	if err := os.WriteFile("/private/tmp/blinder-captcha-browser-url.txt", []byte(u.String()), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-report:
		os.WriteFile("/private/tmp/blinder-captcha-browser-result.json", []byte(body), 0600)
		var got struct {
			ListStatus int    `json:"listStatus"`
			PageStatus int    `json:"pageStatus"`
			PageBody   string `json:"pageBody"`
			Error      string `json:"error"`
		}
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatal(err)
		}
		if got.Error != "" {
			t.Fatal(got.Error)
		}
		if got.ListStatus == 200 && got.PageStatus == 200 && got.PageBody == secret {
			t.Fatalf("ordinary proxied script used operator cookie to read original private challenge: %s", body)
		}
		t.Log(body)
	case <-time.After(55 * time.Second):
		t.Fatal("browser did not report")
	}
}
