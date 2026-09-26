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
 const result={providerLoaded:window.syntheticProviderLoaded===true};
 const frame=(path)=>new Promise((resolve,reject)=>{const f=document.createElement('iframe');f.onload=()=>resolve(f);f.onerror=()=>reject(new Error('frame load failed'));f.src=path;document.body.appendChild(f);setTimeout(()=>resolve(f),1500)});
 try {
  result.fetchStatus=(await fetch('/__blinder/captcha/')).status;
  const list=await frame('/__blinder/captcha/');
  const link=list.contentDocument.querySelector('a');
  result.canReadList=!!link;result.listText=list.contentDocument.body.innerText;
  if(link){const id=link.getAttribute('href').split('/').pop();const p=await frame('/__blinder/captcha/page/'+id);result.pageBody=p.contentDocument.body.innerText;}
 }catch(e){result.error=String(e)}
 document.getElementById('result').textContent=JSON.stringify(result);
 await fetch('/review-report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(result)});
})();</script>`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!doctype html><script src="%s/widget.js"></script>%s`, providerURL.String(), pageScript)
	}))
	defer upstream.Close()
	upURL, _ := url.Parse(upstream.URL)
	socksAddr, seen := captchaRoutingSOCKS(t, map[string]bool{upURL.Host: true, providerURL.Host: true})
	capcfg := captchaDeliveryConfig(t, fmt.Sprintf("version: 1\ncaptcha:\n  custom:\n    - name: synthetic\n      resource_origins: [%s]\n      tor_policy: route-with-target\n", providerURL.String()))
	cfg, err := config.New(upstream.URL, "127.0.0.1:0", "alias.local", []string{"AcmeCorp"}, true, false, false, socksAddr, "", 0, "", "", 10, 60)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Captcha = capcfg
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.transport.(*http.Transport).CloseIdleConnections()
	s.captchaQueue.Submit("synthetic", "https://private-target.synthetic/account", []byte("<p>"+secret+"</p>"), "text/html")
	report := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/review-bootstrap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		token, _ := json.Marshal("Bearer " + s.CaptchaOperatorToken())
		fmt.Fprintf(w, `<!doctype html><script>(async()=>{const r=await fetch('/__blinder/captcha/',{headers:{Authorization:%s}});if(r.status===200)location.href='/fixture-page';})()</script>`, token)
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
	os.WriteFile("/private/tmp/blinder-captcha-routing-browser-url.txt", []byte(u.String()), 0600)
	select {
	case body := <-report:
		var got struct {
			ProviderLoaded bool   `json:"providerLoaded"`
			FetchStatus    int    `json:"fetchStatus"`
			CanReadList    bool   `json:"canReadList"`
			PageBody       string `json:"pageBody"`
			Error          string `json:"error"`
		}
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatal(err)
		}
		destinations := seen()
		evidence := map[string]any{"browser": got, "socksDestinations": destinations, "target": upURL.Host, "provider": providerURL.Host, "providerHits": providerHits.Load()}
		b, _ := json.MarshalIndent(evidence, "", "  ")
		os.WriteFile("/private/tmp/blinder-captcha-routing-browser-result.json", b, 0600)
		t.Log(string(b))
		t.Run("iframe_isolation", func(t *testing.T) {
			if got.CanReadList && got.PageBody == secret {
				t.Fatal("proxied script bypassed Sec-Fetch-Dest guard through readable same-origin iframes")
			}
			if got.Error != "" {
				t.Log(got.Error)
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
