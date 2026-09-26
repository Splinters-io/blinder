package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/captcha"
	"github.com/Splinters-io/blinder/internal/config"
)

type captchaFlowRequest struct {
	Method, URI, Host, Origin, Referer string
	CookieNames                        []string
	ProviderSession                    string
	TargetCredential                   bool
	OperatorCredential                 bool
	Authorization                      bool
}

func observeCaptchaFlowRequest(r *http.Request) captchaFlowRequest {
	row := captchaFlowRequest{Method: r.Method, URI: r.URL.RequestURI(), Host: r.Host, Origin: r.Header.Get("Origin"), Referer: r.Header.Get("Referer"), Authorization: r.Header.Get("Authorization") != ""}
	for _, cookie := range r.Cookies() {
		row.CookieNames = append(row.CookieNames, cookie.Name)
		switch cookie.Name {
		case "provider_session":
			row.ProviderSession = cookie.Value
		case "target_session", "challenge_stage":
			row.TargetCredential = true
		case captcha.OperatorCookieName, "__blinder_op":
			row.OperatorCredential = true
		}
	}
	return row
}

type captchaFlowRelayRequest struct {
	Request captchaFlowRequest
	Status  int
	Error   string
}

type captchaFlowRoundTripFunc func(*http.Request) (*http.Response, error)

func (f captchaFlowRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// No real CAPTCHA is solved: a deterministic local provider returns a fixture
// token after exercising ordinary browser APIs. A human/operator still submits
// the visible completion form, exactly as in the application workflow.
func TestCaptchaFlowBrowser(t *testing.T) {
	if os.Getenv("BLINDER_REVIEW_BROWSER") != "1" {
		t.Skip("requires local browser")
	}
	var mu sync.Mutex
	var requests []string
	var providerRequests []captchaFlowRequest
	var relayRequests []captchaFlowRelayRequest
	var retry map[string]string
	var challengeID, operatorURL string
	var resultStatus int
	var resultBody, resultError string
	var completed bool
	termination := "setup did not complete"
	socksDestinations := func() []string { return nil }
	// Retain failed and timed-out runs too. Snapshots share the handlers' lock,
	// so a late upstream result cannot race with timeout evidence collection.
	defer func() {
		mu.Lock()
		observed := append([]string(nil), requests...)
		providerObserved := append([]captchaFlowRequest(nil), providerRequests...)
		relayObserved := append([]captchaFlowRelayRequest(nil), relayRequests...)
		retryObserved := make(map[string]string, len(retry))
		for k, v := range retry {
			retryObserved[k] = v
		}
		mu.Unlock()
		evidence := map[string]any{
			"completed": completed, "passed": !t.Failed() && completed, "termination": termination,
			"status": resultStatus, "body": resultBody, "error": resultError,
			"operatorURL": operatorURL, "challengeID": challengeID, "retry": retryObserved,
			"providerRequests": observed, "providerObservations": providerObserved,
			"relayRequests": relayObserved, "socksDestinations": socksDestinations(),
			"transport": "synthetic local SOCKS; HTTP localhost browser endpoints; no live Tor or TLS trust acceptance",
		}
		encoded, err := json.MarshalIndent(evidence, "", "  ")
		if err != nil {
			t.Errorf("encode browser evidence: %v", err)
			return
		}
		if err := os.WriteFile("/private/tmp/blinder-flow-browser-result.json", encoded, 0600); err != nil {
			t.Errorf("write browser evidence: %v", err)
		}
		t.Log(string(encoded))
	}()
	var providerOrigin string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observation := observeCaptchaFlowRequest(r)
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		providerRequests = append(providerRequests, observation)
		mu.Unlock()
		if observation.Authorization || observation.TargetCredential || observation.OperatorCredential {
			t.Error("target/operator credentials reached provider")
		}
		switch r.URL.Path {
		case "/widget/start":
			http.SetCookie(w, &http.Cookie{Name: "provider_session", Value: "fixture-session", Path: "/widget/", HttpOnly: true})
			http.Redirect(w, r, "frame?stage=one", 302)
		case "/widget/frame":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<!doctype html><p>Provider fixture: testing APIs</p><script src="%s/widget/api.js?render=explicit&amp;onload=ready"></script>`, providerOrigin)
		case "/widget/api.js":
			if r.URL.Query().Get("onload") != "ready" {
				t.Error("encoded query lost")
			}
			w.Header().Set("Content-Type", "application/javascript")
			origin, _ := json.Marshal(providerOrigin)
			fmt.Fprintf(w, `(async()=>{try{
const origin=%s;
const frame=document.createElement('iframe');
const inner=new Promise(resolve=>window.addEventListener('message',e=>{if(e.source===frame.contentWindow&&e.data==='inner-ready')resolve();}));
frame.src=origin+'/widget/inner';document.body.appendChild(frame);
await new Promise((resolve,reject)=>{const s=document.createElement('script');s.src=origin+'/widget/dynamic.js';s.onload=resolve;s.onerror=reject;document.body.appendChild(s)});
if(!window.fixtureDynamic)throw Error('dynamic script missing');
const response=await fetch('verify?mode=one&mode=two',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({answer:'synthetic'})});
if(!response.ok)throw Error('POST '+response.status);const data=await response.json();
for(const method of ['PUT','PATCH','DELETE','OPTIONS','PROPFIND','vendor.sync']){
const result=await fetch('method/'+encodeURIComponent(method),{method,headers:{'Content-Type':'application/json'},body:JSON.stringify({method})});
if(!result.ok)throw Error(method+' '+result.status);
}
await new Promise((resolve,reject)=>{const x=new XMLHttpRequest();x.open('GET','status');x.withCredentials=true;x.onload=()=>x.status===200?resolve():reject(Error('XHR '+x.status));x.onerror=reject;x.send()});
await inner;document.body.insertAdjacentHTML('beforeend','<p>Provider APIs and nested frame passed</p>');
parent.postMessage({type:'fixture-token',token:data.token},'*');
}catch(e){document.body.insertAdjacentHTML('beforeend','<pre>FIXTURE ERROR: '+String(e)+'</pre>')}})();`, origin)
		case "/widget/dynamic.js":
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, "window.fixtureDynamic=true;")
		case "/widget/inner":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<!doctype html><p>Nested provider frame loaded</p><script>parent.postMessage('inner-ready','*')</script>`)
		case "/widget/verify":
			b, _ := io.ReadAll(r.Body)
			cookie, err := r.Cookie("provider_session")
			if r.Method != "POST" || string(b) != `{"answer":"synthetic"}` || err != nil || cookie.Value != "fixture-session" || len(r.URL.Query()["mode"]) != 2 {
				http.Error(w, "provider POST/session failed", 400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"token":"synthetic-valid-solution"}`)
		case "/widget/status":
			cookie, err := r.Cookie("provider_session")
			if err != nil || cookie.Value != "fixture-session" {
				http.Error(w, "provider XHR session lost", 400)
				return
			}
			io.WriteString(w, "ok")
		default:
			if strings.HasPrefix(r.URL.Path, "/widget/method/") {
				method := strings.TrimPrefix(r.URL.Path, "/widget/method/")
				var body struct{ Method string }
				cookie, err := r.Cookie("provider_session")
				if json.NewDecoder(r.Body).Decode(&body) != nil || body.Method != method || r.Method != method || err != nil || cookie.Value != "fixture-session" {
					http.Error(w, "custom method/body/session changed", 400)
					return
				}
				w.WriteHeader(204)
				return
			}
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	pu, _ := url.Parse(provider.URL)
	pu.Host = "localhost:" + pu.Port()
	providerOrigin = pu.String()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/protected" {
			http.NotFound(w, r)
			return
		}
		r.ParseForm()
		if r.Form.Get("fixture-response") == "" {
			w.Header().Set("Content-Type", "text/html")
			http.SetCookie(w, &http.Cookie{Name: "challenge_stage", Value: "two", Path: "/"})
			w.WriteHeader(403)
			fmt.Fprintf(w, `<!doctype html><p>Verify you are human — synthetic fixture only</p><form action="/protected" method="POST"><input type="hidden" name="csrf" value="fresh"></form><iframe id="provider" src="%s/widget/start"></iframe><script>addEventListener('message',e=>{if(e.source!==document.getElementById('provider').contentWindow||!e.data||e.data.type!=='fixture-token')return;const field=document.createElement('input');field.type='hidden';field.name='fixture-response';field.value=e.data.token;document.body.appendChild(field);const p=document.createElement('p');p.textContent='Synthetic provider completed';document.body.appendChild(p)});</script>`, providerOrigin)
			return
		}
		a, _ := r.Cookie("target_session")
		b, _ := r.Cookie("challenge_stage")
		mu.Lock()
		retry = map[string]string{"method": r.Method, "username": r.Form.Get("username"), "csrf": r.Form.Get("csrf"), "token": r.Form.Get("fixture-response"), "cookies": r.Header.Get("Cookie")}
		mu.Unlock()
		if r.Method != "POST" || r.Form.Get("username") != "fixture-user" || r.Form.Get("csrf") != "fresh" || a == nil || a.Value != "one" || b == nil || b.Value != "two" {
			http.Error(w, "original session/form lost", 400)
			return
		}
		io.WriteString(w, "Original request resumed")
	}))
	defer upstream.Close()
	tu, _ := url.Parse(upstream.URL)
	socks, seen := captchaRoutingSOCKS(t, map[string]bool{tu.Host: true, pu.Host: true})
	socksDestinations = seen
	capcfg := captchaDeliveryConfig(t, fmt.Sprintf("version: 1\ncaptcha:\n  custom:\n    - name: synthetic\n      resource_origins: [%s]\n      opaque_fields: [fixture-response]\n", providerOrigin))
	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	defer server.Close()
	cfg, err := config.New(upstream.URL, server.Listener.Addr().String(), "alias.local", []string{"AcmeCorp"}, true, false, false, socks, "", 0, "", "", 10, 180)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Captcha = capcfg
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	transport := s.transport.(*http.Transport)
	defer transport.CloseIdleConnections()
	// Count every provider request issued through the configured transport.
	// Seeing one SOCKS connection is insufficient: a later dynamic URL could
	// still be fetched directly by the browser from the original provider.
	s.transport = captchaFlowRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != pu.Host {
			return transport.RoundTrip(r)
		}
		mu.Lock()
		index := len(relayRequests)
		relayRequests = append(relayRequests, captchaFlowRelayRequest{Request: observeCaptchaFlowRequest(r)})
		mu.Unlock()
		response, err := transport.RoundTrip(r)
		mu.Lock()
		if response != nil {
			relayRequests[index].Status = response.StatusCode
		}
		if err != nil {
			relayRequests[index].Error = err.Error()
		}
		mu.Unlock()
		return response, err
	})
	// This fixture intentionally exercises HTTP .localhost endpoints. Configure
	// aliases to match that listener; production HTTPS alias trust is separate.
	if err := s.configureProviderRoutes("http"); err != nil {
		t.Fatal(err)
	}
	cleanup := make(chan struct{}, 1)
	mux.HandleFunc("/review-bootstrap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		token, _ := json.Marshal("Bearer " + s.CaptchaOperatorToken())
		fmt.Fprintf(w, `<!doctype html><script>(async()=>{const r=await fetch('/__blinder/captcha/',{headers:{Authorization:%s}});if(r.ok)location.href='/__blinder/captcha/challenge/%s'})()</script>`, token, challengeID)
	})
	mux.HandleFunc("/review-cleanup", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: captcha.OperatorCookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		io.WriteString(w, "Synthetic flow complete")
		select {
		case cleanup <- struct{}{}:
		default:
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/__blinder/captcha/challenge/") {
			_, cookieErr := r.Cookie(captcha.OperatorCookieName)
			t.Logf("operator completion request: origin=%q dest=%q cookie=%t", r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Dest"), cookieErr == nil)
		}
		s.server.Handler.ServeHTTP(w, r)
	})
	if err := s.captchaOperator.SetOperatorOrigin("http://" + captcha.OperatorHost + ":" + strconv.Itoa(server.Listener.Addr().(*net.TCPAddr).Port)); err != nil {
		t.Fatal(err)
	}
	server.Start()
	defer s.captchaQueue.Shutdown()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	type result struct {
		status int
		body   string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		r, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/protected", strings.NewReader("username=fixture-user&csrf=old"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Cookie", "target_session=one")
		resp, err := server.Client().Do(r)
		if err != nil {
			done <- result{err: err}
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		done <- result{status: resp.StatusCode, body: string(body)}
	}()
	challengeID = captchaDeliveryWaitID(t, s)
	captchaFollowupWaiter(t, s, challengeID)
	u, _ := url.Parse(server.URL)
	u.Host = captcha.OperatorHost + ":" + u.Port()
	u.Path = "/review-bootstrap"
	operatorURL = u.String()
	if err := os.WriteFile("/private/tmp/blinder-flow-browser-url.txt", []byte(u.String()), 0600); err != nil {
		t.Fatal(err)
	}
	termination = "waiting for browser completion"
	select {
	case got := <-done:
		completed = true
		termination = "original request returned"
		resultStatus, resultBody = got.status, got.body
		if got.err != nil {
			resultError = got.err.Error()
		}
		mu.Lock()
		observed := append([]string(nil), requests...)
		providerObserved := append([]captchaFlowRequest(nil), providerRequests...)
		relayObserved := append([]captchaFlowRelayRequest(nil), relayRequests...)
		mu.Unlock()
		if got.err != nil || got.status != 200 || got.body != "Original request resumed" {
			t.Errorf("end-to-end flow failed: %v status=%d body=%q", got.err, got.status, got.body)
		}
		for _, want := range []string{"GET /widget/start", "GET /widget/frame?stage=one", "GET /widget/api.js?render=explicit&onload=ready", "GET /widget/dynamic.js", "GET /widget/inner", "POST /widget/verify?mode=one&mode=two", "GET /widget/status", "PUT /widget/method/PUT", "PATCH /widget/method/PATCH", "DELETE /widget/method/DELETE", "OPTIONS /widget/method/OPTIONS", "PROPFIND /widget/method/PROPFIND", "vendor.sync /widget/method/vendor.sync"} {
			found := false
			for _, got := range observed {
				found = found || got == want
			}
			if !found {
				t.Errorf("missing provider request %s", want)
			}
		}
		counts := func(rows []captchaFlowRequest) map[string]int {
			result := make(map[string]int)
			for _, row := range rows {
				// Header observations also distinguish provider fetches using an
				// opaque/direct browser origin from the request the relay sent.
				key, _ := json.Marshal(row)
				result[string(key)]++
			}
			return result
		}
		var relayed []captchaFlowRequest
		for _, row := range relayObserved {
			if row.Error != "" {
				t.Errorf("provider relay error for %s %s: %s", row.Request.Method, row.Request.URI, row.Error)
			}
			relayed = append(relayed, row.Request)
		}
		if !reflect.DeepEqual(counts(providerObserved), counts(relayed)) {
			t.Errorf("provider requests differ from relay requests: received=%v relayed=%v", counts(providerObserved), counts(relayed))
		}
		for _, dst := range []string{tu.Host, pu.Host} {
			found := false
			for _, got := range seen() {
				found = found || got == dst
			}
			if !found {
				t.Errorf("missing SOCKS route %s", dst)
			}
		}
		select {
		case <-cleanup:
		case <-time.After(25 * time.Second):
			t.Log("cleanup navigation not received")
		}
	case <-ctx.Done():
		termination = "browser completion deadline exceeded"
		resultError = ctx.Err().Error()
		t.Fatal("browser flow did not finish")
	}
}
