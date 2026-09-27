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

const captchaFlowSolution = "synthetic-valid-solution"

type captchaFlowRequest struct {
	Method, URI, Host, Origin, Referer string
	PreflightMethod, PreflightHeaders  string
	CookieNames                        []string
	ProviderSession                    string
	TargetCredential                   bool
	OperatorCredential                 bool
	Authorization                      bool
}

func observeCaptchaFlowRequest(r *http.Request) captchaFlowRequest {
	row := captchaFlowRequest{
		Method: r.Method, URI: r.URL.RequestURI(), Host: r.Host,
		Origin: r.Header.Get("Origin"), Referer: r.Header.Get("Referer"),
		PreflightMethod: r.Header.Get("Access-Control-Request-Method"), PreflightHeaders: r.Header.Get("Access-Control-Request-Headers"),
		Authorization: r.Header.Get("Authorization") != "",
	}
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
	direct := os.Getenv("BLINDER_REVIEW_CAPTCHA_DIRECT") == "1"
	// Third-party Lax cookies are a denial control, not a valid completion
	// precondition. The positive provider uses an opaque response token and no
	// cookie; target retry cookies remain required in both modes.
	laxCookie := os.Getenv("BLINDER_REVIEW_CAPTCHA_PROFILE") == "lax"
	type directResult struct {
		Type  string `json:"type"`
		Token string `json:"token"`
		Error string `json:"error"`
	}
	type isolationResult struct {
		ParentDenied        bool   `json:"parentDenied"`
		ParentError         string `json:"parentError"`
		OperatorFetchDenied bool   `json:"operatorFetchDenied"`
		FetchError          string `json:"fetchError"`
	}
	directDone := make(chan directResult, 1)
	var mu sync.Mutex
	var requests []string
	var providerRequests []captchaFlowRequest
	var relayRequests []captchaFlowRelayRequest
	var retry map[string]string
	var challengeID, operatorURL string
	var challengeOperatorOrigin string
	var isolationProbeStatus int
	var isolationProbeCount int
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
		challengeObserved := challengeID
		probeStatus, probeCount := isolationProbeStatus, isolationProbeCount
		retryObserved := make(map[string]string, len(retry))
		for k, v := range retry {
			retryObserved[k] = v
		}
		mu.Unlock()
		evidence := map[string]any{
			"profile":   map[bool]string{true: "cross-site Lax cookie denial", false: "stateless opaque-token completion"}[laxCookie],
			"completed": completed, "passed": !t.Failed() && completed, "termination": termination,
			"status": resultStatus, "body": resultBody, "error": resultError,
			"operatorURL": operatorURL, "challengeID": challengeObserved, "retry": retryObserved,
			"isolationProbeStatus": probeStatus, "isolationProbeCount": probeCount,
			"providerRequests": observed, "providerObservations": providerObserved,
			"relayRequests": relayObserved, "socksDestinations": socksDestinations(),
			"transport": "synthetic local SOCKS; HTTP localhost browser endpoints; no live Tor or TLS trust acceptance",
		}
		encoded, err := json.MarshalIndent(evidence, "", "  ")
		if err != nil {
			t.Errorf("encode browser evidence: %v", err)
			return
		}
		resultPath := "/private/tmp/blinder-flow-browser-result.json"
		if direct {
			evidence["transport"] = "direct browser reference; same original target/provider origins and cookie policy; no proxy or SOCKS"
			encoded, _ = json.MarshalIndent(evidence, "", "  ")
			resultPath = "/private/tmp/blinder-flow-direct-browser-result.json"
		}
		if err := os.WriteFile(resultPath, encoded, 0600); err != nil {
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
			if laxCookie {
				http.SetCookie(w, &http.Cookie{Name: "provider_session", Value: "fixture-session", Path: "/widget/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
			}
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
}catch(e){document.body.insertAdjacentHTML('beforeend','<pre>FIXTURE ERROR: '+String(e)+'</pre>');parent.postMessage({type:'fixture-error',error:String(e)},'*')}})();`, origin)
		case "/widget/dynamic.js":
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, "window.fixtureDynamic=true;")
		case "/widget/inner":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<!doctype html><p>Nested provider frame loaded</p><script>parent.postMessage('inner-ready','*')</script>`)
		case "/widget/verify":
			b, _ := io.ReadAll(r.Body)
			cookie, err := r.Cookie("provider_session")
			if r.Method != "POST" || string(b) != `{"answer":"synthetic"}` || (laxCookie && (err != nil || cookie.Value != "fixture-session")) || len(r.URL.Query()["mode"]) != 2 {
				http.Error(w, "provider POST/session failed", 400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"token": captchaFlowSolution})
		case "/widget/status":
			cookie, err := r.Cookie("provider_session")
			if laxCookie && (err != nil || cookie.Value != "fixture-session") {
				http.Error(w, "provider XHR session lost", 400)
				return
			}
			io.WriteString(w, "ok")
		default:
			if strings.HasPrefix(r.URL.Path, "/widget/method/") {
				method := strings.TrimPrefix(r.URL.Path, "/widget/method/")
				var body struct{ Method string }
				cookie, err := r.Cookie("provider_session")
				if json.NewDecoder(r.Body).Decode(&body) != nil || body.Method != method || r.Method != method || (laxCookie && (err != nil || cookie.Value != "fixture-session")) {
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
		if direct && r.URL.Path == "/review-direct" {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Cache-Control", "no-store")
			origin, _ := json.Marshal(providerOrigin)
			fmt.Fprintf(w, `<!doctype html><title>Direct CAPTCHA reference</title><h1>Direct provider reference</h1><p>Original target/provider origins and cookie policy; no Blinder rewriting.</p><iframe id="provider" src="%s/widget/start" style="width:90%%;height:500px"></iframe><pre id="result">Waiting for provider</pre><script>addEventListener('message',async e=>{if(e.origin!==%s||e.source!==document.getElementById('provider').contentWindow||!e.data||!['fixture-token','fixture-error'].includes(e.data.type))return;document.getElementById('result').textContent=JSON.stringify(e.data);await fetch('/review-direct-result',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(e.data)})});</script>`, providerOrigin, origin)
			return
		}
		if direct && r.URL.Path == "/review-direct-result" && r.Method == http.MethodPost {
			var result directResult
			if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&result); err != nil {
				http.Error(w, "invalid fixture result", http.StatusBadRequest)
				return
			}
			select {
			case directDone <- result:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/protected" {
			http.NotFound(w, r)
			return
		}
		r.ParseForm()
		if r.Form.Get("fixture-response") == "" {
			w.Header().Set("Content-Type", "text/html")
			http.SetCookie(w, &http.Cookie{Name: "challenge_stage", Value: "two", Path: "/"})
			w.WriteHeader(403)
			mu.Lock()
			operatorOriginJSON, _ := json.Marshal(challengeOperatorOrigin)
			mu.Unlock()
			fmt.Fprintf(w, `<!doctype html><p>Verify you are human — synthetic fixture only</p><form action="/protected" method="POST"><input type="hidden" name="csrf" value="fresh"></form><iframe id="provider" src="%s/widget/start"></iframe><script>addEventListener('message',async e=>{
if(e.source!==document.getElementById('provider').contentWindow||!e.data)return;
if(e.data.type==='fixture-error'){parent.postMessage(e.data,'*');return;}
if(e.data.type!=='fixture-token')return;
const isolation={parentDenied:false,parentError:'',operatorFetchDenied:false,fetchError:''};
try{void parent.document.body}catch(error){isolation.parentDenied=error.name==='SecurityError';isolation.parentError=error.name;}
try{const response=await fetch(%s+'/__blinder/captcha/',{credentials:'include'});await response.text();}
catch(error){isolation.operatorFetchDenied=error.name==='TypeError';isolation.fetchError=error.name;}
const telemetry=document.createElement('input');telemetry.type='hidden';telemetry.name='fixture-isolation';telemetry.value=JSON.stringify(isolation);document.body.appendChild(telemetry);
if(!isolation.parentDenied||!isolation.operatorFetchDenied){const failure=document.createElement('pre');failure.textContent='ISOLATION FAILURE: '+JSON.stringify(isolation);document.body.appendChild(failure);return;}
const field=document.createElement('input');field.type='hidden';field.name='fixture-response';field.value=e.data.token;document.body.appendChild(field);const p=document.createElement('p');p.textContent='Synthetic provider and operator isolation completed';document.body.appendChild(p)});</script>`, providerOrigin, operatorOriginJSON)
			return
		}
		a, _ := r.Cookie("target_session")
		b, _ := r.Cookie("challenge_stage")
		mu.Lock()
		retry = map[string]string{"method": r.Method, "username": r.Form.Get("username"), "csrf": r.Form.Get("csrf"), "token": r.Form.Get("fixture-response"), "isolation": r.Form.Get("fixture-isolation"), "cookies": r.Header.Get("Cookie")}
		mu.Unlock()
		if r.Form.Get("fixture-response") != captchaFlowSolution {
			http.Error(w, "invalid synthetic solution", http.StatusForbidden)
			return
		}
		var isolation isolationResult
		if json.Unmarshal([]byte(r.Form.Get("fixture-isolation")), &isolation) != nil || !isolation.ParentDenied || isolation.ParentError != "SecurityError" || !isolation.OperatorFetchDenied || isolation.FetchError != "TypeError" {
			http.Error(w, "operator isolation was not demonstrated", http.StatusForbidden)
			return
		}
		if r.Method != "POST" || r.Form.Get("username") != "fixture-user" || r.Form.Get("csrf") != "fresh" || a == nil || a.Value != "one" || b == nil || b.Value != "two" {
			http.Error(w, "original session/form lost", 400)
			return
		}
		io.WriteString(w, "Original request resumed")
	}))
	defer upstream.Close()
	if direct {
		operatorURL = upstream.URL + "/review-direct"
		if err := os.WriteFile("/private/tmp/blinder-flow-direct-browser-url.txt", []byte(operatorURL), 0600); err != nil {
			t.Fatal(err)
		}
		t.Logf("direct reference URL: %s", operatorURL)
		select {
		case result := <-directDone:
			completed = true
			termination = "direct provider returned browser result"
			resultBody, resultError = result.Token, result.Error
			if laxCookie && (result.Type != "fixture-error" || result.Error != "Error: POST 400") {
				t.Errorf("direct Lax denial changed: %+v", result)
			} else if !laxCookie && (result.Type != "fixture-token" || result.Token != captchaFlowSolution) {
				t.Errorf("direct reference did not complete provider APIs: %+v", result)
			}
		case <-time.After(150 * time.Second):
			termination = "direct browser deadline exceeded"
			t.Fatal("direct browser reference did not finish")
		}
		return
	}
	tu, _ := url.Parse(upstream.URL)
	socks, seen := captchaRoutingSOCKS(t, map[string]bool{tu.Host: true, pu.Host: true})
	socksDestinations = seen
	capcfg := captchaDeliveryConfig(t, fmt.Sprintf("version: 1\ncaptcha:\n  custom:\n    - name: synthetic\n      resource_origins: [%s]\n      opaque_fields: [fixture-response, fixture-isolation]\n", providerOrigin))
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
	if laxCookie {
		mux.HandleFunc("/review-provider-result", func(w http.ResponseWriter, r *http.Request) {
			var result directResult
			if r.Method != http.MethodPost || json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&result) != nil {
				http.Error(w, "invalid fixture result", http.StatusBadRequest)
				return
			}
			select {
			case directDone <- result:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}
	mux.HandleFunc("/review-bootstrap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		token, _ := json.Marshal("Bearer " + s.CaptchaOperatorToken())
		mu.Lock()
		id := challengeID
		mu.Unlock()
		fmt.Fprintf(w, `<!doctype html><script>(async()=>{const r=await fetch('/__blinder/captcha/',{headers:{Authorization:%s}});if(r.ok)location.href='/__blinder/captcha/challenge/%s'})()</script>`, token, id)
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
		mu.Lock()
		activeID := challengeID
		operatorOrigin := challengeOperatorOrigin
		mu.Unlock()
		viewOrigin := "http://" + activeID + captcha.ChallengeHostSuffix + ":" + strconv.Itoa(server.Listener.Addr().(*net.TCPAddr).Port)
		if r.Host == strings.TrimPrefix(operatorOrigin, "http://") && r.URL.Path == "/__blinder/captcha/" && r.Header.Get("Origin") == viewOrigin {
			recorded := httptest.NewRecorder()
			s.server.Handler.ServeHTTP(recorded, r)
			mu.Lock()
			isolationProbeCount++
			isolationProbeStatus = recorded.Code
			mu.Unlock()
			for key, values := range recorded.Header() {
				w.Header()[key] = values
			}
			w.WriteHeader(recorded.Code)
			w.Write(recorded.Body.Bytes())
			return
		}
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/__blinder/captcha/challenge/") {
			_, cookieErr := r.Cookie(captcha.OperatorCookieName)
			t.Logf("operator completion request: origin=%q dest=%q cookie=%t", r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Dest"), cookieErr == nil)
		}
		if laxCookie && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/__blinder/captcha/challenge/") {
			// Test-only observation of the visible child error; it grants no
			// provider access and never submits a solution or changes its value.
			recorded := httptest.NewRecorder()
			s.server.Handler.ServeHTTP(recorded, r)
			for key, values := range recorded.Header() {
				w.Header()[key] = values
			}
			w.Header().Del("Content-Length")
			w.WriteHeader(recorded.Code)
			w.Write(recorded.Body.Bytes())
			io.WriteString(w, `<script>addEventListener('message',async e=>{const frame=document.querySelector('iframe');if(!frame||e.source!==frame.contentWindow||e.origin!==new URL(frame.src).origin||!e.data||e.data.type!=='fixture-error')return;const p=document.createElement('pre');p.textContent='Observed provider denial: '+e.data.error;document.body.appendChild(p);await fetch('/review-provider-result',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(e.data)})});</script>`)
			return
		}
		s.server.Handler.ServeHTTP(w, r)
	})
	configuredOperatorOrigin := "http://" + captcha.OperatorHost + ":" + strconv.Itoa(server.Listener.Addr().(*net.TCPAddr).Port)
	mu.Lock()
	challengeOperatorOrigin = configuredOperatorOrigin
	mu.Unlock()
	if err := s.captchaOperator.SetOperatorOrigin(configuredOperatorOrigin); err != nil {
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
	id := captchaDeliveryWaitID(t, s)
	captchaFollowupWaiter(t, s, id)
	mu.Lock()
	challengeID = id
	mu.Unlock()
	u, _ := url.Parse(server.URL)
	u.Host = captcha.OperatorHost + ":" + u.Port()
	u.Path = "/review-bootstrap"
	operatorURL = u.String()
	if err := os.WriteFile("/private/tmp/blinder-flow-browser-url.txt", []byte(u.String()), 0600); err != nil {
		t.Fatal(err)
	}
	termination = "waiting for browser completion"
	select {
	case got := <-directDone:
		completed = true
		termination = "provider denial observed without completion"
		resultError = got.Error
		if !laxCookie || got.Type != "fixture-error" || got.Error != "Error: POST 400" {
			t.Errorf("proxied denial differs from direct HTTP error: %+v", got)
		}
		mu.Lock()
		observed := append([]captchaFlowRequest(nil), providerRequests...)
		relayed := append([]captchaFlowRelayRequest(nil), relayRequests...)
		mu.Unlock()
		counts := make(map[string]int)
		for _, row := range observed {
			encoded, _ := json.Marshal(row)
			counts[string(encoded)]++
			if row.PreflightMethod != "" || row.ProviderSession != "" || row.Authorization || row.OperatorCredential || row.TargetCredential {
				t.Errorf("denial request changed controls or exported credentials: %+v", row)
			}
		}
		deniedPOST := false
		for _, row := range relayed {
			encoded, _ := json.Marshal(row.Request)
			counts[string(encoded)]--
			if row.Request.Method == "POST" && row.Request.URI == "/widget/verify?mode=one&mode=two" {
				deniedPOST = row.Status == http.StatusBadRequest && row.Error == ""
			}
		}
		if !deniedPOST {
			t.Error("provider's HTTP 400 POST denial did not traverse relay")
		}
		for row, count := range counts {
			if count != 0 {
				t.Errorf("provider request bypassed relay or changed: %s (difference %d)", row, count)
			}
		}
		select {
		case <-cleanup:
		case <-time.After(25 * time.Second):
			t.Log("cleanup navigation not received")
		}
		cancel()
		<-done
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
		retriedToken := retry["token"]
		isolationTelemetry := retry["isolation"]
		probeStatus, probeCount := isolationProbeStatus, isolationProbeCount
		mu.Unlock()
		if got.err != nil || got.status != 200 || got.body != "Original request resumed" {
			t.Errorf("end-to-end flow failed: %v status=%d body=%q", got.err, got.status, got.body)
		}
		if retriedToken != captchaFlowSolution {
			t.Errorf("upstream retry did not receive the exact synthetic provider solution: got %q", retriedToken)
		}
		var isolation isolationResult
		if json.Unmarshal([]byte(isolationTelemetry), &isolation) != nil || !isolation.ParentDenied || isolation.ParentError != "SecurityError" || !isolation.OperatorFetchDenied || isolation.FetchError != "TypeError" || probeCount != 1 || probeStatus != http.StatusForbidden {
			t.Errorf("raw challenge did not demonstrate operator isolation: telemetry=%q, probe requests=%d status=%d", isolationTelemetry, probeCount, probeStatus)
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
			// Provider APIs are same-origin inside their own document. A
			// browser-added preflight exposes a changed origin relationship;
			// record the real response, never count it as a completed API call.
			if row.Request.Method == http.MethodOptions && row.Request.PreflightMethod != "" {
				t.Errorf("unexpected provider CORS preflight for %s %s: status=%d", row.Request.PreflightMethod, row.Request.URI, row.Status)
			} else {
				requestURL, err := url.ParseRequestURI(row.Request.URI)
				wantStatus := 0
				if err == nil {
					switch requestURL.Path {
					case "/widget/start":
						wantStatus = http.StatusFound
					case "/widget/frame", "/widget/api.js", "/widget/dynamic.js", "/widget/inner", "/widget/verify", "/widget/status":
						wantStatus = http.StatusOK
					default:
						if strings.HasPrefix(requestURL.Path, "/widget/method/") {
							wantStatus = http.StatusNoContent
						}
					}
				}
				if wantStatus == 0 || row.Status != wantStatus {
					t.Errorf("provider relay status for %s %s = %d, want %d", row.Request.Method, row.Request.URI, row.Status, wantStatus)
				}
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
