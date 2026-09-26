package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/Splinters-io/blinder/internal/captcha"
	"github.com/Splinters-io/blinder/internal/config"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
			r := captchaDeliveryOperatorRequest(s, http.MethodGet, strings.TrimPrefix(path, "/__blinder/captcha/"), nil)
			if tc.bearer {
				r.Header.Set("Authorization", "Bearer "+token)
			} else {
				r.AddCookie(&http.Cookie{Name: captcha.OperatorCookieName, Value: token})
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
// Operator cookies and documents must remain on the reserved operator origin,
// even when the target owns an active service worker and opens a real popup.
func TestCaptchaSessionBrowserOperatorIsolation(t *testing.T) {
	if os.Getenv("BLINDER_REVIEW_BROWSER") != "1" {
		t.Skip("opt-in local browser check")
	}
	const secret = "AcmeCorp private target page, original identity"
	const targetIdentity = "private-target.synthetic"
	const workerScript = `const operatorOrigin=OPERATOR_ORIGIN;
const observations=[];
self.addEventListener('install',e=>e.waitUntil(self.skipWaiting()));
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('fetch',e=>{
 const u=new URL(e.request.url);
 if(u.origin===operatorOrigin){
  observations.push({url:u.href,mode:e.request.mode,destination:e.request.destination});
  // If the target worker ever controls an operator navigation, make that
  // observable rather than silently forwarding it and giving a false pass.
  if(e.request.mode==='navigate'){e.respondWith(new Response('TARGET WORKER INTERCEPTED OPERATOR NAVIGATION'));return;}
 }
 if(u.origin===self.location.origin&&u.pathname==='/review-sw-positive'){
  observations.push({url:u.href,mode:e.request.mode,destination:e.request.destination});
  e.respondWith(new Response('target-worker-positive'));return;
 }
});
self.addEventListener('message',e=>{if(e.data==='snapshot'&&e.ports[0])e.ports[0].postMessage(observations);});`
	const untrusted = `<!doctype html><title>Blinder synthetic isolation check</title>
<h1>Synthetic operator isolation</h1><p>Wait for worker, fetch and iframe checks, then click once to test an authenticated popup.</p>
<button id="popup" disabled>Run popup isolation check</button><pre id="result">Checking origin boundaries...</pre><script>
(async()=>{
 const operatorOrigin=OPERATOR_ORIGIN;
 const listURL=operatorOrigin+'/__blinder/captcha/';
 const pageURL=operatorOrigin+'/__blinder/captcha/page/CHALLENGE_ID';
 const result={fixtureRan:true};let registration;
 const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
 const show=()=>document.getElementById('result').textContent=JSON.stringify(result,null,2);
 const snapshot=()=>new Promise((resolve,reject)=>{
  const channel=new MessageChannel();channel.port1.onmessage=e=>resolve(e.data);
  navigator.serviceWorker.controller.postMessage('snapshot',[channel.port2]);setTimeout(()=>reject(Error('worker snapshot missing')),3000);
 });
 const report=async()=>{
  if(registration)await registration.unregister();show();
  // A native navigation clears the host-only operator cookie on its own
  // origin; a target-origin response cannot delete that cookie correctly.
  const form=document.createElement('form');form.method='POST';form.action=operatorOrigin+'/review-complete';
  const value=document.createElement('input');value.type='hidden';value.name='report';value.value=JSON.stringify(result);form.appendChild(value);document.body.appendChild(form);form.submit();
 };
 const crossFetch=async href=>{
  try{const r=await fetch(href,{credentials:'include'});return {readable:true,status:r.status,body:await r.text()};}
  catch(e){return {readable:false,error:String(e)};}
 };
 const frame=href=>new Promise(resolve=>{
  const f=document.createElement('iframe');f.hidden=true;let done=false;
  const finish=()=>{if(done)return;done=true;let text='';try{text=f.contentDocument&&f.contentDocument.body?f.contentDocument.body.innerText:'';}catch(e){}f.remove();resolve(text);};
  f.onload=finish;f.onerror=finish;f.src=href;document.body.appendChild(f);setTimeout(finish,3000);
 });
 const readPopup=async(win,href)=>{
  let denied=false;
  for(let i=0;i<100;i++){
   if(win.closed)return {readable:false,reason:'opener severed'};
   try{const d=win.document;if(d.location.href===href&&d.readyState==='complete')return {readable:true,text:d.body?d.body.innerText:''};}catch(e){denied=true;}
   await pause(50);
  }
  return {readable:false,reason:denied?'DOM access denied':'navigation not observed'};
 };
 try {
  if(!('serviceWorker' in navigator))throw Error('Browser lacks service worker support');
  registration=await navigator.serviceWorker.register('/review-worker.js',{scope:'/'});
  await navigator.serviceWorker.ready;
  for(let i=0;i<100&&!navigator.serviceWorker.controller;i++)await pause(50);
  if(!navigator.serviceWorker.controller)throw Error('Target worker did not claim the page');
  result.workerControllerOrigin=new URL(navigator.serviceWorker.controller.scriptURL).origin;
  result.workerPositive=(await (await fetch('/review-sw-positive')).text())==='target-worker-positive';
  try{await navigator.serviceWorker.register(operatorOrigin+'/review-worker.js',{scope:operatorOrigin+'/'});result.operatorWorkerRegistrationDenied=false;}
  catch(e){result.operatorWorkerRegistrationDenied=true;}
  result.targetControlStatus=(await fetch('/__blinder/captcha/')).status;
  result.list=await crossFetch(listURL);result.page=await crossFetch(pageURL);
  result.iframeListBody=await frame(listURL);result.iframePageBody=await frame(pageURL);
 }catch(e){result.error=String(e);await report();return;}
 result.awaitingPopupClick=true;show();
 const button=document.getElementById('popup');button.disabled=false;
 button.addEventListener('click',async()=>{
  button.disabled=true;delete result.awaitingPopupClick;
  const popup=window.open(listURL,'blinder-synthetic-operator-probe');
  result.popupOpened=!!popup;
  if(!popup){result.error='Browser blocked popup: this is not evidence of isolation';await report();return;}
  try{
   result.popupList=await readPopup(popup,listURL);
   if(result.popupList.readable){popup.location.href=pageURL;result.popupPage=await readPopup(popup,pageURL);}
   // Browsers can stop an idle worker while waiting for the human click.
   // Exercise the current worker instance immediately before its snapshot.
   result.workerSnapshotPositive=(await (await fetch('/review-sw-positive')).text())==='target-worker-positive';
   result.workerObservations=await snapshot();
  }catch(e){result.error=String(e);}
  try{popup.close();}catch(e){}
  await report();
 },{once:true});
})();</script>`
	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	defer server.Close()
	listen := server.Listener.Addr().String()
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		t.Fatal(err)
	}
	operatorAuthority := net.JoinHostPort(captcha.OperatorHost, port)
	operatorOrigin := "http://" + operatorAuthority
	targetOrigin := "http://localhost:" + port
	cfg, err := config.New("https://main.example", listen, "alias.local", []string{"AcmeCorp"}, true, false, false, "", "", 0, "", "", 30, 60)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Captcha = captchaDeliveryConfig(t, captchaDeliveryBuiltin)
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.transport.(*http.Transport).CloseIdleConnections()
	defer s.captchaQueue.Shutdown()
	if err := s.captchaOperator.SetOperatorOrigin(operatorOrigin); err != nil {
		t.Fatal(err)
	}
	id := s.captchaQueue.Submit("hcaptcha", "https://"+targetIdentity+"/account", []byte(secret), "text/plain")
	originJSON, _ := json.Marshal(operatorOrigin)
	expand := func(text string) string {
		return strings.NewReplacer("OPERATOR_ORIGIN", string(originJSON), "CHALLENGE_ID", id).Replace(text)
	}
	var fixtureRequests, workerRequests, authenticatedPopups, guardedFetches, guardedFrames, targetCookieLeaks atomic.Int32
	var authVerified atomic.Bool
	s.transport = audit267SRITransport(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/fixture-page":
			fixtureRequests.Add(1)
			return audit267SRIResponse("text/html", expand(untrusted)), nil
		case "/review-worker.js":
			workerRequests.Add(1)
			resp := audit267SRIResponse("application/javascript", expand(workerScript))
			resp.Header.Set("Cache-Control", "no-store")
			resp.Header.Set("Service-Worker-Allowed", "/")
			return resp, nil
		case "/review-sw-positive":
			return audit267SRIResponse("text/plain", "worker did not intercept"), nil
		case "/favicon.ico":
			resp := audit267SRIResponse("image/x-icon", "")
			resp.StatusCode = http.StatusNoContent
			return resp, nil
		default:
			return nil, fmt.Errorf("unexpected synthetic upstream path %q", r.URL.Path)
		}
	})
	report := make(chan string, 1)
	reportBody := func(body string) {
		select {
		case report <- body:
		default:
		}
	}
	hasOperatorCookie := func(r *http.Request) bool {
		cookie, err := r.Cookie(captcha.OperatorCookieName)
		return err == nil && cookie.Value == s.CaptchaOperatorToken()
	}
	clearOperatorCookie := func(w http.ResponseWriter) {
		http.SetCookie(w, &http.Cookie{Name: captcha.OperatorCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
	mux.HandleFunc("/review-bootstrap", func(w http.ResponseWriter, r *http.Request) {
		if r.Host != operatorAuthority {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		token, _ := json.Marshal("Bearer " + s.CaptchaOperatorToken())
		fmt.Fprintf(w, `<!doctype html><body><script>(async()=>{try{const r=await fetch('/__blinder/captcha/',{headers:{Authorization:%s}});if(r.status!==200)throw Error('bearer bootstrap '+r.status);location.href='/__blinder/captcha/review-auth-probe';}catch(e){const f=document.createElement('form');f.method='POST';f.action='/review-complete';const i=document.createElement('input');i.name='report';i.value=JSON.stringify({error:String(e)});f.appendChild(i);document.body.appendChild(f);f.submit();}})()</script>`, token)
	})
	mux.HandleFunc("/__blinder/captcha/review-auth-probe", func(w http.ResponseWriter, r *http.Request) {
		probe := r.Clone(r.Context())
		probe.URL.Path = "/__blinder/captcha/"
		captured := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(captured, probe)
		if r.Host != operatorAuthority || r.Header.Get("Sec-Fetch-Dest") != "document" || r.Header.Get("Authorization") != "" || !hasOperatorCookie(r) || captured.Code != http.StatusOK {
			clearOperatorCookie(w)
			reportBody(`{"error":"Browser cookie-authenticated operator-origin document preflight did not succeed"}`)
			http.Error(w, "cookie-authenticated document preflight failed", http.StatusForbidden)
			return
		}
		authVerified.Store(true)
		http.Redirect(w, r, targetOrigin+"/fixture-page", http.StatusSeeOther)
	})
	mux.HandleFunc("/review-complete", func(w http.ResponseWriter, r *http.Request) {
		if r.Host != operatorAuthority || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid report", http.StatusBadRequest)
			return
		}
		clearOperatorCookie(w)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "Synthetic isolation checks complete. Operator cookie cleared; target worker unregistered.")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		reportBody(r.PostForm.Get("report"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Host != operatorAuthority {
			if _, err := r.Cookie(captcha.OperatorCookieName); err == nil {
				targetCookieLeaks.Add(1)
			}
		}
		if r.Host == operatorAuthority && (r.URL.Path == "/__blinder/captcha/" || r.URL.Path == "/__blinder/captcha/page/"+id) {
			captured := httptest.NewRecorder()
			s.server.Handler.ServeHTTP(captured, r)
			if r.Header.Get("Authorization") == "" {
				switch r.Header.Get("Sec-Fetch-Dest") {
				case "document":
					if hasOperatorCookie(r) && captured.Code == http.StatusOK {
						authenticatedPopups.Add(1)
					}
				case "empty":
					if r.Header.Get("Origin") == targetOrigin && captured.Code == http.StatusForbidden {
						guardedFetches.Add(1)
					}
				case "iframe":
					if captured.Code == http.StatusForbidden {
						guardedFrames.Add(1)
					}
				}
			}
			for name, values := range captured.Header() {
				w.Header()[name] = values
			}
			w.WriteHeader(captured.Code)
			w.Write(captured.Body.Bytes())
			return
		}
		s.server.Handler.ServeHTTP(w, r)
	})
	server.Start()
	if err := os.WriteFile("/private/tmp/blinder-captcha-browser-url.txt", []byte(operatorOrigin+"/review-bootstrap"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-report:
		if err := os.WriteFile("/private/tmp/blinder-captcha-browser-result.json", []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		type access struct {
			Readable                  bool
			Status                    int
			Body, Text, Reason, Error string
		}
		var got struct {
			FixtureRan                       bool
			TargetControlStatus              int
			List, Page                       access
			IframeListBody, IframePageBody   string
			PopupOpened                      bool
			PopupList, PopupPage             access
			WorkerPositive                   bool
			WorkerSnapshotPositive           bool
			WorkerControllerOrigin           string
			OperatorWorkerRegistrationDenied bool
			WorkerObservations               []struct{ URL, Mode, Destination string }
			Error                            string
		}
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatal(err)
		}
		t.Log(body)
		if got.Error != "" {
			t.Fatal(got.Error)
		}
		if !authVerified.Load() || !got.FixtureRan || fixtureRequests.Load() == 0 || targetCookieLeaks.Load() != 0 {
			t.Fatal("operator authentication, proxied fixture execution or host-only cookie preconditions failed")
		}
		if got.TargetControlStatus != http.StatusNotFound || got.List.Readable || got.Page.Readable || guardedFetches.Load() != 2 || guardedFrames.Load() != 2 {
			t.Fatalf("target/operator origin guards not demonstrated: target status=%d readable fetch=%v/%v guarded fetches=%d frames=%d", got.TargetControlStatus, got.List.Readable, got.Page.Readable, guardedFetches.Load(), guardedFrames.Load())
		}
		for _, text := range []string{got.List.Body, got.Page.Body, got.IframeListBody, got.IframePageBody} {
			if strings.Contains(text, secret) || strings.Contains(text, targetIdentity) || strings.Contains(text, id) {
				t.Fatal("ordinary proxied content read private operator evidence through fetch/iframe")
			}
		}
		if !got.PopupOpened || authenticatedPopups.Load() == 0 {
			t.Fatal("authenticated operator popup did not navigate: blocked/missing-auth popups do not establish isolation")
		}
		if got.PopupList.Readable || got.PopupPage.Readable {
			t.Fatalf("target content read authenticated operator popup DOM: %s", body)
		}
		if got.PopupList.Reason != "opener severed" && got.PopupList.Reason != "DOM access denied" {
			t.Fatalf("popup outcome was inconclusive: %s", body)
		}
		if !got.WorkerPositive || !got.WorkerSnapshotPositive || got.WorkerControllerOrigin != targetOrigin || !got.OperatorWorkerRegistrationDenied || workerRequests.Load() == 0 {
			t.Fatal("active target service worker and denied operator-worker registration were not demonstrated")
		}
		positiveObserved := false
		for _, observation := range got.WorkerObservations {
			positiveObserved = positiveObserved || observation.URL == targetOrigin+"/review-sw-positive"
			if strings.HasPrefix(observation.URL, operatorOrigin+"/") && observation.Mode == "navigate" {
				t.Fatalf("target service worker observed/controlled an operator navigation: %+v", observation)
			}
		}
		if !positiveObserved {
			t.Fatal("worker snapshot lacks its positive interception control")
		}
	case <-time.After(2 * time.Minute):
		t.Fatal("browser did not report; open the operator fixture and click Run popup isolation check")
	}
}
