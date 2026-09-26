package proxy

import (
	"context"
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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/tests/fixture"
)

// The origin in each resource URL is a reachable canary. SOCKS resolves it to a
// separate backing server. Thus even a successful browser load is not enough:
// a direct request increments the canary log, never the backing server log.
type containmentFixture struct {
	proxyURL      string
	aliasURL      string
	extraLocalURL string
	target        string
	extra         string
	client        *http.Client
	report        chan json.RawMessage
	mu            sync.Mutex
	direct        []string
	backing       []string
	socks         func() []string
}

func newContainmentFixture(t *testing.T, cert tls.Certificate, aliases ...string) *containmentFixture {
	t.Helper()
	alias := "localhost"
	if len(aliases) > 0 {
		alias = aliases[0]
	}
	f := &containmentFixture{report: make(chan json.RawMessage, 1)}
	start := func(h http.Handler) *httptest.Server {
		s := httptest.NewUnstartedServer(h)
		if len(cert.Certificate) > 0 {
			s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		}
		s.StartTLS()
		t.Cleanup(s.Close)
		return s
	}
	canary := func(origin string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			f.direct = append(f.direct, origin+" "+r.Method+" "+r.URL.RequestURI())
			f.mu.Unlock()
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "direct-canary")
		})
	}
	primaryCanary := start(canary("primary"))
	extraCanary := start(canary("extra"))
	f.target, f.extra = primaryCanary.URL, extraCanary.URL
	backing := start(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.backing = append(f.backing, r.Host+" "+r.Method+" "+r.URL.RequestURI())
		f.mu.Unlock()
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Cache-Control", "no-store")
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'none'; script-src 'self' %s; style-src 'self' 'unsafe-inline'; img-src 'self' data: %s; connect-src %s %s %s", f.target, f.target, f.target, f.extra, strings.Replace(f.target, "https://", "wss://", 1)))
			fmt.Fprintf(w, `<!doctype html><title>Local browser routing matrix</title>
<p>This fixture uses local servers only.</p><pre id="result">Running requests...</pre>
<script src="%[1]s/script"></script><img alt="primary image" src="%[1]s/image">
<link rel="stylesheet" href="/style"><div id="background" style="height:10px;width:10px"></div>
<script src="/driver"></script>`, f.target)
		case "/script":
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, `window.fixtureScriptLoaded=true;`)
		case "/image", "/css-image":
			w.Header().Set("Content-Type", "image/gif")
			w.Write([]byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"))
		case "/style":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprintf(w, `#background{background-image:url("%s/css-image")}`, f.target)
		case "/driver":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `(async()=>{
const results={documentURL:location.href,script:window.fixtureScriptLoaded===true,policyViolations:[]};
addEventListener('securitypolicyviolation',e=>results.policyViolations.push({directive:e.effectiveDirective,blockedURI:e.blockedURI}));
const probe=async(name,url)=>{try{const r=await fetch(url,{signal:AbortSignal.timeout(8000)});results[name]={url,status:r.status,body:await r.text()}}catch(e){results[name]={url,error:String(e)}}};
const submit=async()=>{const url=new URL('/submit',location.href).href;const returnURL='%[1]s/return';try{const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({returnURL}),signal:AbortSignal.timeout(8000)});results.submittedURL={url,status:r.status,body:await r.text()}}catch(e){results.submittedURL={url,error:String(e)}}};
await Promise.all([probe('primaryFetch','%[1]s/fetch'),probe('extraFetch','%[2]s/fetch'),submit()]);
await new Promise(resolve=>{const s=new WebSocket('%[3]s/ws');const timer=setTimeout(()=>{results.websocket={url:s.url,error:'timeout'};s.close();resolve()},5000);s.onmessage=e=>{results.websocket={url:s.url,message:e.data};clearTimeout(timer);s.close(1000);resolve()};s.onerror=()=>{results.websocket={url:s.url,error:'socket error'};clearTimeout(timer);resolve()}});
document.getElementById('result').textContent=JSON.stringify(results,null,2);
try{await fetch('/__review_report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(results)})}
catch(e){results.reportFetchError=String(e);const form=document.createElement('form');form.method='POST';form.action='/__review_report';const input=document.createElement('input');input.type='hidden';input.name='report';input.value=JSON.stringify(results);form.appendChild(input);document.body.appendChild(form);form.submit()}
})();`, f.target, f.extra, strings.Replace(f.target, "https://", "wss://", 1))
		case "/fetch":
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "proxied-fixture")
		case "/submit":
			w.Header().Set("Content-Type", "text/plain")
			var submission struct {
				ReturnURL string `json:"returnURL"`
			}
			if r.Method != http.MethodPost || json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&submission) != nil {
				http.Error(w, "invalid URL submission", http.StatusBadRequest)
				return
			}
			if submission.ReturnURL != f.target+"/return" {
				http.Error(w, "URL roundtrip mismatch", http.StatusUnprocessableEntity)
				return
			}
			io.WriteString(w, "url-roundtrip-ok")
		case "/ws":
			fixture.Handler().ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	pURL, _ := url.Parse(primaryCanary.URL)
	eURL, _ := url.Parse(extraCanary.URL)
	bURL, _ := url.Parse(backing.URL)
	socksAddr, seen := containmentSOCKS(t, map[string]string{pURL.Host: bURL.Host, eURL.Host: bURL.Host})
	f.socks = seen
	proxyServer := httptest.NewUnstartedServer(nil)
	cfg, err := config.New(f.target, proxyServer.Listener.Addr().String(), alias, nil, false, false, false, socksAddr, "", 0, "", "", 10, 30, f.extra)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewWithCertificate(cfg, cert)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(context.Background()); s.transport.(*http.Transport).CloseIdleConnections() })
	mux := http.NewServeMux()
	mux.HandleFunc("/__review_report", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		var body []byte
		var err error
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			err = r.ParseForm()
			body = []byte(r.Form.Get("report"))
		} else {
			body, err = io.ReadAll(r.Body)
		}
		if err != nil || !json.Valid(body) {
			http.Error(w, "invalid report", 400)
			return
		}
		select {
		case f.report <- json.RawMessage(body):
		default:
		}
		w.WriteHeader(204)
	})
	mux.Handle("/", s)
	proxyServer.Config.Handler = mux
	if len(cert.Certificate) > 0 {
		proxyServer.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	proxyServer.StartTLS()
	t.Cleanup(proxyServer.Close)
	f.proxyURL, f.client = proxyServer.URL, proxyServer.Client()
	u, _ := url.Parse(f.proxyURL)
	f.aliasURL = "https://" + alias + ":" + u.Port()
	f.extraLocalURL = s.origins.RewriteUpstreamURL(f.extra)
	return f
}

func TestTargetContainmentBrowser(t *testing.T) {
	if os.Getenv("BLINDER_REVIEW_BROWSER") != "1" {
		t.Skip("requires local browser with the acceptance certificate trusted")
	}
	dir := os.Getenv("BLINDER_REVIEW_CERT_DIR")
	if dir == "" {
		dir = "/private/tmp/blinder-acceptance-certs"
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "identity.pem"), filepath.Join(dir, "identity.pem"))
	if err != nil {
		t.Fatal(err)
	}
	f := newContainmentFixture(t, cert)
	if err := os.WriteFile("/private/tmp/blinder-containment-browser-url.txt", []byte(f.proxyURL), 0600); err != nil {
		t.Fatal(err)
	}
	var report json.RawMessage
	select {
	case report = <-f.report:
	case <-time.After(180 * time.Second):
		t.Error("browser did not send a completion report within 180 seconds")
	}
	f.mu.Lock()
	direct, backing := append([]string(nil), f.direct...), append([]string(nil), f.backing...)
	f.mu.Unlock()
	if len(direct) != 0 {
		t.Errorf("browser bypassed the SOCKS path: %v", direct)
	}
	var browser struct {
		Script       bool `json:"script"`
		PrimaryFetch struct {
			Status      int
			Body, Error string
		} `json:"primaryFetch"`
		ExtraFetch struct {
			Status      int
			Body, Error string
		} `json:"extraFetch"`
		SubmittedURL struct {
			Status      int
			Body, Error string
		} `json:"submittedURL"`
		Websocket struct{ Message, Error string } `json:"websocket"`
	}
	if err := json.Unmarshal(report, &browser); err != nil {
		t.Errorf("invalid browser result: %v", err)
	} else {
		if !browser.Script || browser.PrimaryFetch.Status != 200 || browser.PrimaryFetch.Body != "proxied-fixture" || !strings.HasSuffix(browser.Websocket.Message, " live") {
			t.Errorf("primary-origin functionality failed: %+v", browser)
		}
		if browser.ExtraFetch.Status != 200 || browser.ExtraFetch.Body != "proxied-fixture" {
			t.Errorf("extra-origin functionality failed: %+v", browser.ExtraFetch)
		}
		if browser.SubmittedURL.Status != 200 || browser.SubmittedURL.Body != "url-roundtrip-ok" {
			t.Errorf("submitted URL did not restore its original origin: %+v", browser.SubmittedURL)
		}
	}
	cssSeen := false
	for _, request := range backing {
		cssSeen = cssSeen || strings.HasSuffix(request, " GET /css-image")
	}
	if !cssSeen {
		t.Error("CSS image was not requested through SOCKS")
	}
	evidence := map[string]any{
		"proxyURL": f.proxyURL, "aliasURL": f.aliasURL, "extraLocalURL": f.extraLocalURL,
		"upstreamOrigins": map[string]string{"primary": f.target, "extra": f.extra},
		"browser":         report, "directCanaryRequests": direct, "backingRequests": backing, "socksDestinations": f.socks(),
		"results": map[string]bool{
			"reportReceived":           len(report) > 0,
			"primaryScriptLoaded":      browser.Script,
			"primaryFetchSucceeded":    browser.PrimaryFetch.Status == 200 && browser.PrimaryFetch.Body == "proxied-fixture",
			"primaryWebSocketReceived": strings.HasSuffix(browser.Websocket.Message, " live"),
			"cssImageViaSOCKS":         cssSeen,
			"noDirectCanaryRequests":   len(direct) == 0,
			"extraFetchSucceeded":      browser.ExtraFetch.Status == 200 && browser.ExtraFetch.Body == "proxied-fixture",
			"submittedURLRestored":     browser.SubmittedURL.Status == 200 && browser.SubmittedURL.Body == "url-roundtrip-ok",
		},
	}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/private/tmp/blinder-containment-browser-result.json", data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
}

// This wire test complements actual browser evidence: a canary URL must be
// translated to the proxy origin, not merely have its hostname anonymized.
func TestTargetContainmentPrimaryURLRoutes(t *testing.T) {
	f := newContainmentFixture(t, tls.Certificate{})
	for _, tc := range []struct{ name, path, resource string }{
		{"html_script", "/", "/script"},
		{"css_image", "/style", "/css-image"},
		{"dynamic_fetch", "/driver", "/fetch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := f.client.Get(f.proxyURL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 || !strings.Contains(string(body), f.proxyURL+tc.resource) {
				t.Errorf("resource did not retain the validated entry origin: status=%d wanted=%q body=%s", resp.StatusCode, f.proxyURL+tc.resource, body)
			}
		})
	}
}

func TestTargetContainmentIPAliasDoesNotCorruptRoutes(t *testing.T) {
	f := newContainmentFixture(t, tls.Certificate{}, "127.0.0.1")
	resp, err := f.client.Get(f.proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `src="`+f.proxyURL+`/script"`) {
		t.Errorf("IP alias was corrupted by another scrub pass: %s", body)
	}
}

func containmentSOCKS(t *testing.T, routes map[string]string) (string, func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var destinations []string
	active := map[net.Conn]bool{}
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			active[c] = true
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				defer func() { mu.Lock(); delete(active, c); mu.Unlock() }()
				c.SetDeadline(time.Now().Add(180 * time.Second))
				var greeting [2]byte
				if _, err := io.ReadFull(c, greeting[:]); err != nil || greeting[0] != 5 {
					return
				}
				if _, err := io.CopyN(io.Discard, c, int64(greeting[1])); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				var h [4]byte
				if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 || h[1] != 1 {
					return
				}
				var host string
				switch h[3] {
				case 1:
					ip := make([]byte, 4)
					if _, err := io.ReadFull(c, ip); err != nil {
						return
					}
					host = net.IP(ip).String()
				case 3:
					var length [1]byte
					if _, err := io.ReadFull(c, length[:]); err != nil {
						return
					}
					name := make([]byte, length[0])
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
				destination := net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(port[:])))
				mu.Lock()
				destinations = append(destinations, destination)
				mu.Unlock()
				route, ok := routes[destination]
				if !ok {
					c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				up, err := net.DialTimeout("tcp", route, time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				done := make(chan struct{})
				go func() { io.Copy(up, c); up.Close(); close(done) }()
				io.Copy(c, up)
				c.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-acceptDone
		mu.Lock()
		for c := range active {
			c.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return ln.Addr().String(), func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), destinations...) }
}
