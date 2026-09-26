package proxy

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/captcha"
	"github.com/Splinters-io/blinder/internal/config"
)

// Records destinations and relays only to the two local fixture servers.
func captchaRoutingSOCKS(t *testing.T, allowed map[string]bool) (string, func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	connections := map[net.Conn]bool{}
	var workers sync.WaitGroup
	stop := make(chan struct{})
	go func() {
		defer close(stop)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[c] = true
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				defer func() { mu.Lock(); delete(connections, c); mu.Unlock() }()
				c.SetDeadline(time.Now().Add(55 * time.Second))
				var greeting [2]byte
				if _, err := io.ReadFull(c, greeting[:]); err != nil {
					return
				}
				methods := make([]byte, int(greeting[1]))
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				if _, err := c.Write([]byte{5, 0}); err != nil {
					return
				}
				var header [4]byte
				if _, err := io.ReadFull(c, header[:]); err != nil {
					return
				}
				var host string
				switch header[3] {
				case 1:
					b := make([]byte, 4)
					if _, err := io.ReadFull(c, b); err != nil {
						return
					}
					host = net.IP(b).String()
				case 3:
					b := make([]byte, 1)
					if _, err := io.ReadFull(c, b); err != nil {
						return
					}
					name := make([]byte, int(b[0]))
					if _, err := io.ReadFull(c, name); err != nil {
						return
					}
					host = string(name)
				default:
					return
				}
				var port [2]byte
				if _, err := io.ReadFull(c, port[:]); err != nil {
					return
				}
				dst := net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(port[:])))
				mu.Lock()
				seen = append(seen, dst)
				mu.Unlock()
				if !allowed[dst] {
					c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				up, err := net.DialTimeout("tcp", dst, time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				copied := make(chan struct{})
				go func() { io.Copy(up, c); up.Close(); close(copied) }()
				io.Copy(c, up)
				c.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-stop
		mu.Lock()
		for c := range connections {
			c.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return ln.Addr().String(), func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

func TestCaptchaBrowserRoutingIframeAndProviderRoute(t *testing.T) {
	if os.Getenv("BLINDER_REVIEW_BROWSER") != "1" {
		t.Skip("requires local synthetic browser visit")
	}
	const secret = "AcmeCorp synthetic private challenge"
	var providerHits atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerHits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, "window.syntheticProviderLoaded=true;")
	}))
	defer provider.Close()
	providerURL, _ := url.Parse(provider.URL)
	providerURL.Host = "localhost:" + providerURL.Port()
	const pageScript = `<pre id="result">Checking browser boundaries...</pre><script>
(async()=>{
 const operatorOrigin=OPERATOR_ORIGIN;
 const result={providerLoaded:window.syntheticProviderLoaded===true};
 const frame=(path)=>new Promise(resolve=>{
  const f=document.createElement('iframe');let done=false;
  const finish=()=>{if(done)return;done=true;let state={readable:false,body:''};try{const d=f.contentDocument;if(d&&d.location.href!=='about:blank')state={readable:true,body:d.body?d.body.innerText:''};}catch(e){}f.remove();resolve(state);};
  f.onload=finish;f.onerror=finish;f.src=path;document.body.appendChild(f);setTimeout(finish,2000);
 });
 try {
  result.fetchStatus=(await fetch('/__blinder/captcha/')).status;
  result.list=await frame(operatorOrigin+'/__blinder/captcha/');
  result.page=await frame(operatorOrigin+'/__blinder/captcha/page/CHALLENGE_ID');
 }catch(e){result.error=String(e)}
 document.getElementById('result').textContent=JSON.stringify(result);
 const form=document.createElement('form');form.method='POST';form.action=operatorOrigin+'/review-report';
 const report=document.createElement('input');report.type='hidden';report.name='report';report.value=JSON.stringify(result);form.appendChild(report);document.body.appendChild(form);form.submit();
})();</script>`
	var operatorOriginURL, challengeID string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		originJSON, _ := json.Marshal(operatorOriginURL)
		page := strings.NewReplacer("OPERATOR_ORIGIN", string(originJSON), "CHALLENGE_ID", challengeID).Replace(pageScript)
		fmt.Fprintf(w, `<!doctype html><script src="%s/widget.js"></script>%s`, providerURL.String(), page)
	}))
	defer upstream.Close()
	upURL, _ := url.Parse(upstream.URL)
	socksAddr, seen := captchaRoutingSOCKS(t, map[string]bool{upURL.Host: true, providerURL.Host: true})
	capcfg := captchaDeliveryConfig(t, fmt.Sprintf("version: 1\ncaptcha:\n  custom:\n    - name: synthetic\n      resource_origins: [%s]\n      tor_policy: route-with-target\n", providerURL.String()))
	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	defer server.Close()
	listen := server.Listener.Addr().String()
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		t.Fatal(err)
	}
	operatorAuthority := net.JoinHostPort(captcha.OperatorHost, port)
	operatorOriginURL = "http://" + operatorAuthority
	targetOrigin := "http://localhost:" + port
	cfg, err := config.New(upstream.URL, listen, "alias.local", []string{"AcmeCorp"}, true, false, false, socksAddr, "", 0, "", "", 10, 60)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Captcha = capcfg
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.transport.(*http.Transport).CloseIdleConnections()
	defer s.captchaQueue.Shutdown()
	if err := s.captchaOperator.SetOperatorOrigin(operatorOriginURL); err != nil {
		t.Fatal(err)
	}
	challengeID = s.captchaQueue.Submit("synthetic", "https://private-target.synthetic/account", []byte("<p>"+secret+"</p>"), "text/html")
	report := make(chan string, 1)
	reportBody := func(body string) {
		select {
		case report <- body:
		default:
		}
	}
	var authVerified atomic.Bool
	var targetCookieLeaks atomic.Int32
	mux.HandleFunc("/review-bootstrap", func(w http.ResponseWriter, r *http.Request) {
		if r.Host != operatorAuthority {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		token, _ := json.Marshal("Bearer " + s.CaptchaOperatorToken())
		fmt.Fprintf(w, `<!doctype html><script>(async()=>{try{const r=await fetch('/__blinder/captcha/',{headers:{Authorization:%s}});if(r.status!==200)throw Error('operator bootstrap '+r.status);location.href='/review-auth-probe';}catch(e){document.body.textContent=String(e);await fetch('/review-report',{method:'POST',body:new URLSearchParams({report:JSON.stringify({error:String(e)})})});}})()</script>`, token)
	})
	mux.HandleFunc("/review-auth-probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Host != operatorAuthority {
			http.NotFound(w, r)
			return
		}
		cookie, cookieErr := r.Cookie(captcha.OperatorCookieName)
		probe := r.Clone(r.Context())
		probe.URL.Path = "/__blinder/captcha/"
		result := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(result, probe)
		if cookieErr != nil || cookie.Value != s.CaptchaOperatorToken() || r.Header.Get("Authorization") != "" || r.Header.Get("Sec-Fetch-Dest") != "document" || result.Code != http.StatusOK {
			http.SetCookie(w, &http.Cookie{Name: captcha.OperatorCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
			http.Error(w, "operator cookie verification failed", http.StatusForbidden)
			reportBody(`{"error":"operator cookie verification failed"}`)
			return
		}
		authVerified.Store(true)
		http.Redirect(w, r, targetOrigin+"/fixture-page", http.StatusSeeOther)
	})
	mux.HandleFunc("/review-report", func(w http.ResponseWriter, r *http.Request) {
		if r.Host != operatorAuthority || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid fixture report", http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: captcha.OperatorCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		io.WriteString(w, "Synthetic browser routing fixture complete.")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		reportBody(r.Form.Get("report"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Host != operatorAuthority {
			if _, err := r.Cookie(captcha.OperatorCookieName); err == nil {
				targetCookieLeaks.Add(1)
			}
		}
		s.server.Handler.ServeHTTP(w, r)
	})
	server.Start()
	if err := os.WriteFile("/private/tmp/blinder-captcha-routing-browser-url.txt", []byte(operatorOriginURL+"/review-bootstrap"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-report:
		var got struct {
			ProviderLoaded bool `json:"providerLoaded"`
			FetchStatus    int  `json:"fetchStatus"`
			List, Page     struct {
				Readable bool   `json:"readable"`
				Body     string `json:"body"`
			}
			Error string `json:"error"`
		}
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatal(err)
		}
		destinations := seen()
		evidence := map[string]any{"browser": got, "operatorAuthenticated": authVerified.Load(), "targetCookieLeaks": targetCookieLeaks.Load(), "socksDestinations": destinations, "target": upURL.Host, "provider": providerURL.Host, "providerHits": providerHits.Load()}
		b, _ := json.MarshalIndent(evidence, "", "  ")
		os.WriteFile("/private/tmp/blinder-captcha-routing-browser-result.json", b, 0600)
		t.Log(string(b))
		t.Run("iframe_isolation", func(t *testing.T) {
			// This fixture retains authenticated fetch/iframe separation checks.
			// Active target service-worker and popup isolation are exercised by
			// TestCaptchaSessionBrowserOperatorIsolation, not inferred here.
			if !authVerified.Load() || targetCookieLeaks.Load() != 0 || got.Error != "" || got.FetchStatus != http.StatusNotFound || got.List.Readable || got.Page.Readable || strings.Contains(got.List.Body+got.Page.Body, secret) {
				t.Fatalf("operator origin isolation failed: %s", b)
			}
		})
		t.Run("provider_route", func(t *testing.T) {
			targetSeen, providerSeen := false, false
			for _, dst := range destinations {
				targetSeen = targetSeen || dst == upURL.Host
				providerSeen = providerSeen || dst == providerURL.Host
			}
			if !targetSeen || !got.ProviderLoaded || providerHits.Load() == 0 {
				t.Fatalf("fixture did not exercise target and provider: %s", b)
			}
			if !providerSeen {
				t.Fatal("route-with-target provider script loaded directly while target used configured SOCKS transport")
			}
		})
	case <-time.After(55 * time.Second):
		t.Fatal("browser did not report")
	}
}

func TestCaptchaBrowserRoutingRestartOwnershipContract(t *testing.T) {
	keyDir := t.TempDir()
	const asset = "var version=1;"
	s := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/page" {
			return audit267SRIResponse("text/html", audit267SRIPage("/asset", asset)), nil
		}
		return audit267SRIResponse("application/javascript", asset), nil
	}, keyDir)
	page := audit267CacheRequest(s, "GET", "/page", nil)
	src := audit267SRIAttribute(page.Body.String(), "src")
	u, _ := url.Parse(src)
	if u == nil || u.Query().Get("__blv") == "" {
		t.Fatalf("missing version fixture: %q", src)
	}
	var forwarded string
	restarted := audit267SRIServer(t, func(r *http.Request) (*http.Response, error) {
		forwarded = r.URL.RequestURI()
		return audit267SRIResponse("application/javascript", "var version=2;"), nil
	}, keyDir)
	got := audit267CacheRequest(restarted, "GET", audit750BrowserPath(t, src), nil)
	if strings.Contains(forwarded, "__blv=") || got.Code < 400 {
		t.Fatalf("restart lost proxy metadata ownership: forwarded=%q status=%d body=%q", forwarded, got.Code, got.Body.String())
	}
}
