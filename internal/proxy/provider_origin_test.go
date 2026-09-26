package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/captcha"
	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/rewriter"
)

type providerOriginObservation struct {
	Method, URI, Host, Body string
	Header                  http.Header
}

type providerOriginRecorder struct {
	mu   sync.Mutex
	rows []providerOriginObservation
}

func (p *providerOriginRecorder) record(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rows = append(p.rows, providerOriginObservation{r.Method, r.RequestURI, r.Host, string(body), r.Header.Clone()})
}

func (p *providerOriginRecorder) snapshot() []providerOriginObservation {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]providerOriginObservation(nil), p.rows...)
}

func providerOriginFixture(t *testing.T, target *httptest.Server, providers []*httptest.Server, restricted bool, configure ...func(*Server) http.Handler) (*Server, *httptest.Server, *http.Client, []*url.URL, func() []string) {
	t.Helper()
	allowed := map[string]bool{}
	targetURL, _ := url.Parse(target.URL)
	allowed[targetURL.Host] = true
	var yaml strings.Builder
	yaml.WriteString("version: 1\ncaptcha:\n  custom:\n")
	for i, provider := range providers {
		u, _ := url.Parse(provider.URL)
		allowed[u.Host] = true
		fmt.Fprintf(&yaml, "    - name: fixture-%d\n      resource_origins: [%q]\n      tor_policy: route-with-target\n", i, provider.URL)
		if restricted {
			fmt.Fprintf(&yaml, "      resource_url_regex: [%q]\n", "^"+regexp.QuoteMeta(provider.URL)+"/v1/")
		}
	}
	capcfg, err := captcha.ParseConfig([]byte(yaml.String()))
	if err != nil {
		t.Fatal(err)
	}
	socks, seen := captchaRoutingSOCKS(t, allowed)
	local := httptest.NewUnstartedServer(nil)
	cfg, err := config.New(target.URL, local.Listener.Addr().String(), "target.test", []string{"AcmeCorp"}, true, false, false, socks, "", 0, "", "", 5, 30)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Captcha = capcfg
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	local.Config.Handler = s
	if len(configure) > 0 {
		local.Config.Handler = configure[0](s)
	}
	if err := s.configureProviderRoutes("http"); err != nil {
		t.Fatal(err)
	}
	local.Start()
	t.Cleanup(local.Close)
	t.Cleanup(s.captchaQueue.Shutdown)
	if transport, ok := s.transport.(*http.Transport); ok {
		t.Cleanup(transport.CloseIdleConnections)
	}
	var aliases []*url.URL
	for _, provider := range providers {
		var alias *url.URL
		for _, route := range s.providerRoutes.Routes() {
			if route.Upstream.String() == provider.URL {
				alias = route.Local
			}
		}
		if alias == nil {
			t.Fatalf("no isolated origin for %s", provider.URL)
		}
		aliases = append(aliases, alias)
	}
	// Connect the synthetic aliases to this listener without depending on the
	// host OS resolver. Host and scheme are still validated by Blinder itself.
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, local.Listener.Addr().String())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return s, local, client, aliases, seen
}

func providerOriginDo(t *testing.T, client *http.Client, method, raw, body string, headers http.Header) (int, http.Header, string) {
	t.Helper()
	r, err := http.NewRequest(method, raw, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if headers != nil {
		r.Header = headers.Clone()
	}
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header.Clone(), string(bytes)
}

func TestProviderOriginRoutesKeepPortsMethodsAndOpaqueBytes(t *testing.T) {
	var targetSeen, firstSeen, secondSeen providerOriginRecorder
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetSeen.record(r)
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "target AcmeCorp")
	}))
	defer target.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstSeen.record(r)
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("ETag", `"provider-AcmeCorp"`)
		w.Header().Set("X-Provider", "AcmeCorp")
		io.WriteString(w, `window.providerBrand="AcmeCorp";`)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondSeen.record(r)
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "second opaque provider")
	}))
	defer second.Close()
	s, _, client, aliases, socksSeen := providerOriginFixture(t, target, []*httptest.Server{first, second}, true)
	if aliases[0].Host == aliases[1].Host || aliases[0].Hostname() == captcha.OperatorHost || aliases[0].Host == s.cfg.ListenAddr {
		t.Fatalf("provider origins collapsed: %v", aliases)
	}
	const suffix = "/v1/a%2fb?x=AcmeCorp%2fz&dup=1&dup=2&empty=&bare"
	const body = "AcmeCorp opaque request body"
	status, headers, got := providerOriginDo(t, client, "vendor.sync", aliases[0].String()+suffix, body, http.Header{"Content-Type": {"application/octet-stream"}, "X-Opaque": {"AcmeCorp"}})
	if status != 200 || got != `window.providerBrand="AcmeCorp";` || headers.Get("ETag") != `"provider-AcmeCorp"` || headers.Get("X-Provider") != "AcmeCorp" {
		t.Fatalf("provider response entered target rewriting: status=%d headers=%v body=%s", status, headers, got)
	}
	rows := firstSeen.snapshot()
	if len(rows) != 1 || rows[0].Method != "vendor.sync" || rows[0].URI != suffix || rows[0].Body != body || rows[0].Header.Get("X-Opaque") != "AcmeCorp" {
		t.Fatalf("provider request changed: %+v", rows)
	}
	for i := 0; i < 2; i++ {
		providerOriginDo(t, client, "GET", aliases[0].String()+"/v1/cache.js", "", nil)
	}
	if len(firstSeen.snapshot()) != 3 || s.sriCache.Len() != 0 {
		t.Fatal("provider resources entered target response caching or SRI prefetch")
	}
	_, _, got = providerOriginDo(t, client, "GET", aliases[1].String()+"/v1/item", "", nil)
	if got != "second opaque provider" || len(secondSeen.snapshot()) != 1 || len(targetSeen.snapshot()) != 0 {
		t.Fatalf("wrong upstream selected: body=%s target=%v second=%v", got, targetSeen.snapshot(), secondSeen.snapshot())
	}
	for _, provider := range []*httptest.Server{first, second} {
		u, _ := url.Parse(provider.URL)
		found := false
		for _, destination := range socksSeen() {
			found = found || destination == u.Host
		}
		if !found {
			t.Errorf("provider %s bypassed SOCKS", provider.URL)
		}
	}
}

func TestProviderOriginRejectsWrongAuthorityAndUnmatchedResource(t *testing.T) {
	var targetSeen, providerSeen providerOriginRecorder
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetSeen.record(r) }))
	defer target.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { providerSeen.record(r) }))
	defer provider.Close()
	s, _, client, aliases, _ := providerOriginFixture(t, target, []*httptest.Server{provider}, true)
	wrongPort := *aliases[0]
	wrongPort.Host = net.JoinHostPort(wrongPort.Hostname(), "1")
	for _, raw := range []string{wrongPort.String() + "/v1/item", aliases[0].String() + "/outside", aliases[0].String() + "/__blinder/captcha/"} {
		status, _, _ := providerOriginDo(t, client, "GET", raw, "", nil)
		if status < 400 || status >= 500 {
			t.Errorf("invalid provider route not rejected locally: %s returned %d", raw, status)
		}
	}
	r := httptest.NewRequest("GET", "https://"+aliases[0].Host+"/v1/item", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code < 400 || w.Code >= 500 || len(providerSeen.snapshot()) != 0 || len(targetSeen.snapshot()) != 0 {
		t.Fatalf("invalid provider authority reached an upstream: status=%d provider=%v target=%v", w.Code, providerSeen.snapshot(), targetSeen.snapshot())
	}
}

func TestProviderOriginForwardsRealCORSAndUpstreamErrors(t *testing.T) {
	var providerSeen providerOriginRecorder
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "target") }))
	defer target.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerSeen.record(r)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Vary", "Origin")
		if r.URL.Path == "/v1/deny" {
			w.WriteHeader(403)
			io.WriteString(w, "provider denied AcmeCorp")
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", target.URL)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Methods", r.Header.Get("Access-Control-Request-Method"))
			w.Header().Set("Access-Control-Allow-Headers", r.Header.Get("Access-Control-Request-Headers"))
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(500)
		io.WriteString(w, "provider SQLSTATE AcmeCorp")
	}))
	defer provider.Close()
	_, local, client, aliases, _ := providerOriginFixture(t, target, []*httptest.Server{provider}, true)
	requestHeaders := http.Header{"Origin": {local.URL}, "Access-Control-Request-Method": {"vendor.sync"}, "Access-Control-Request-Headers": {"X-Opaque, Content-Type"}}
	status, headers, body := providerOriginDo(t, client, "OPTIONS", aliases[0].String()+"/v1/check", "", requestHeaders)
	if status != 204 || headers.Get("Access-Control-Allow-Origin") != local.URL || headers.Get("Access-Control-Allow-Methods") != "vendor.sync" || body != "" {
		t.Fatalf("provider preflight decision was replaced: status=%d headers=%v body=%q", status, headers, body)
	}
	status, headers, body = providerOriginDo(t, client, "OPTIONS", aliases[0].String()+"/v1/deny", "", requestHeaders)
	if status != 403 || headers.Get("Access-Control-Allow-Origin") != "" || body != "provider denied AcmeCorp" {
		t.Fatalf("denied upstream preflight acquired a local grant: status=%d headers=%v body=%q", status, headers, body)
	}
	status, headers, body = providerOriginDo(t, client, "vendor.sync", aliases[0].String()+"/v1/check", "opaque", http.Header{"Origin": {local.URL}})
	if status != 500 || headers.Get("Access-Control-Allow-Origin") != local.URL || body != "provider SQLSTATE AcmeCorp" {
		t.Fatalf("upstream error changed: status=%d headers=%v body=%q", status, headers, body)
	}
	rows := providerSeen.snapshot()
	if len(rows) != 3 || rows[0].Method != "OPTIONS" || rows[1].Method != "OPTIONS" || rows[2].Method != "vendor.sync" {
		t.Fatalf("preflight was answered locally: %+v", rows)
	}
	for _, row := range rows {
		if row.Header.Get("Origin") != target.URL {
			t.Errorf("provider saw local origin instead of upstream peer: %+v", row)
		}
	}
}

func TestProviderOriginDocumentMethodRoundTrip(t *testing.T) {
	var providerSeen providerOriginRecorder
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "target") }))
	defer target.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerSeen.record(r)
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Methods", "vendor.sync")
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(500)
		io.WriteString(w, "opaque provider failure")
	}))
	defer provider.Close()
	s, _, client, aliases, _ := providerOriginFixture(t, target, []*httptest.Server{provider}, true)
	const source = `fetch(endpoint.href,{method:'vendor.sync',headers:{'X-Provider-Probe':'opaque'},body:'opaque'});`
	got := string(rewriter.RewriteBody([]byte(source), "application/javascript", "/app.js", s.gate, false).Body)
	_, methodValue, found := strings.Cut(got, "method:'")
	methodValue, _, closed := strings.Cut(methodValue, "'")
	if !found || !closed || methodValue == "vendor.sync" {
		t.Fatalf("fixture did not issue a method alias: %s", got)
	}
	status, headers, _ := providerOriginDo(t, client, "OPTIONS", aliases[0].String()+"/v1/api", "", http.Header{"Access-Control-Request-Method": {methodValue}})
	if status != 204 || headers.Get("Access-Control-Allow-Methods") != methodValue {
		t.Fatalf("preflight lost original permission: %d %v", status, headers)
	}
	status, _, body := providerOriginDo(t, client, methodValue, aliases[0].String()+"/v1/api", "", nil)
	rows := providerSeen.snapshot()
	if status != 500 || body != "opaque provider failure" || len(rows) != 2 || rows[0].Header.Get("Access-Control-Request-Method") != "vendor.sync" || rows[1].Method != "vendor.sync" {
		t.Fatalf("method failed round trip: status=%d body=%q rows=%+v", status, body, rows)
	}
}

func TestProviderOriginBrowserCookieScopesExcludeTargetAndOperator(t *testing.T) {
	var providerSeen providerOriginRecorder
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "target") }))
	defer target.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerSeen.record(r)
		http.SetCookie(w, &http.Cookie{Name: "provider_session", Value: "provider-only", Path: "/v1/"})
		io.WriteString(w, "provider")
	}))
	defer provider.Close()
	s, local, client, aliases, _ := providerOriginFixture(t, target, []*httptest.Server{provider}, true)
	targetURL, _ := url.Parse(local.URL)
	operatorURL := &url.URL{Scheme: "http", Host: net.JoinHostPort(captcha.OperatorHost, targetURL.Port())}
	client.Jar.SetCookies(targetURL, []*http.Cookie{{Name: "target_session", Value: "target-only", Path: "/"}})
	client.Jar.SetCookies(operatorURL, []*http.Cookie{{Name: captcha.OperatorCookieName, Value: "operator-only", Path: "/"}})
	providerOriginDo(t, client, "GET", aliases[0].String()+"/v1/first", "", nil)
	providerOriginDo(t, client, "GET", aliases[0].String()+"/v1/second", "", nil)
	rows := providerSeen.snapshot()
	if len(rows) != 2 {
		t.Fatalf("provider requests=%+v", rows)
	}
	for _, row := range rows {
		if strings.Contains(row.Header.Get("Cookie"), "target-only") || strings.Contains(row.Header.Get("Cookie"), "operator-only") || row.Header.Get("Authorization") != "" {
			t.Fatalf("target/operator credentials reached provider: %+v", row)
		}
	}
	if !strings.Contains(rows[1].Header.Get("Cookie"), "provider_session=provider-only") {
		t.Fatalf("provider's own cookie did not return: %+v", rows[1])
	}
	if s.sriCache.Len() != 0 {
		t.Fatal("provider requests entered target SRI cache")
	}
}

// These are browser decisions, not just rewritten-string assertions. The
// opt-in fixture runs the original page and its proxy representation in the
// same browser, without changing trust or granting any browser permissions.
type providerOriginBrowserOutcome struct {
	Script        bool   `json:"script"`
	Fetch         string `json:"fetch"`
	Status        int    `json:"status"`
	Body          string `json:"body"`
	FrameReported bool   `json:"frameReported"`
	FrameIsolated bool   `json:"frameIsolated"`
}

type providerOriginBrowserReport struct {
	Phase string                                  `json:"phase"`
	Cases map[string]providerOriginBrowserOutcome `json:"cases"`
}

type providerOriginRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn providerOriginRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

func TestProviderOriginBrowserControlPairs(t *testing.T) {
	if os.Getenv("BLINDER_PROVIDER_BROWSER") != "1" {
		t.Skip("set BLINDER_PROVIDER_BROWSER=1 and open the printed local URL in Chrome")
	}
	var providerSeen providerOriginRecorder
	var proxyProviderMu sync.Mutex
	proxyProviderRequests := make(map[string]int)
	var targetURL, proxyURL string
	reports := make(chan providerOriginBrowserReport, 2)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerSeen.record(r)
		w.Header().Set("Cache-Control", "no-store")
		switch r.URL.Path {
		case "/v1/script.js":
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, `window.providerScriptRan=true;window.providerBrand="AcmeCorp";`)
		case "/v1/frame", "/v1/frame-deny":
			w.Header().Set("Content-Type", "text/html")
			policy := "default-src 'none'; script-src 'self'; frame-ancestors " + targetURL
			if r.URL.Path == "/v1/frame-deny" {
				policy = "default-src 'none'; script-src 'none'; frame-ancestors " + targetURL
			}
			w.Header().Set("Content-Security-Policy", policy)
			io.WriteString(w, `<!doctype html><title>Provider fixture</title><script src="/v1/frame.js"></script>`)
		case "/v1/frame.js":
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, `let isolated=false;try{void parent.document.body}catch(e){isolated=e.name==='SecurityError'}parent.postMessage({fixture:'provider-frame',isolated},'*');`)
		case "/v1/api/allow", "/v1/api/preflight-deny", "/v1/api/acao-deny":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Vary", "Origin")
			if r.Method == "OPTIONS" && r.URL.Path == "/v1/api/preflight-deny" {
				w.WriteHeader(http.StatusForbidden)
				io.WriteString(w, "provider preflight denied")
				return
			}
			// Only the real target's serialized origin is authorized. This
			// makes incorrect request Origin translation visible to Chrome.
			if r.Header.Get("Origin") == targetURL && (r.Method == "OPTIONS" || r.URL.Path != "/v1/api/acao-deny") {
				w.Header().Set("Access-Control-Allow-Origin", targetURL)
				w.Header().Set("Access-Control-Allow-Methods", "vendor.sync")
				w.Header().Set("Access-Control-Allow-Headers", "X-Provider-Probe")
			}
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, "SQLSTATE AcmeCorp provider failure")
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	names := []string{"script-allow", "script-self-deny", "cors-allow", "cors-preflight-deny", "cors-acao-deny", "frame-isolated", "frame-script-deny"}
	want := map[string]providerOriginBrowserOutcome{
		"script-allow":        {Script: true},
		"script-self-deny":    {},
		"cors-allow":          {Fetch: "response", Status: 500, Body: "SQLSTATE AcmeCorp provider failure"},
		"cors-preflight-deny": {Fetch: "denied"},
		"cors-acao-deny":      {Fetch: "denied"},
		"frame-isolated":      {FrameReported: true, FrameIsolated: true},
		"frame-script-deny":   {},
	}
	caseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/case/")
		if _, ok := want[name]; !ok || !strings.HasPrefix(r.URL.Path, "/case/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "no-store")
		policy := "default-src 'none'; script-src 'nonce-provider-driver' " + provider.URL + "; connect-src " + provider.URL + "; frame-src " + provider.URL
		if name == "script-self-deny" {
			policy = "default-src 'none'; script-src 'nonce-provider-driver' 'self'"
		}
		w.Header().Set("Content-Security-Policy", policy)
		var markup string
		switch {
		case strings.HasPrefix(name, "script-"):
			markup = `<script src="` + provider.URL + `/v1/script.js"></script>`
		case strings.HasPrefix(name, "cors-"):
			kind := strings.TrimPrefix(name, "cors-")
			markup = `<a id="endpoint" href="` + provider.URL + `/v1/api/` + kind + `">Endpoint</a>`
		case name == "frame-isolated":
			markup = `<iframe id="provider" src="` + provider.URL + `/v1/frame"></iframe>`
		case name == "frame-script-deny":
			markup = `<iframe id="provider" src="` + provider.URL + `/v1/frame-deny"></iframe>`
		}
		// Endpoint URLs live in ordinary HTML attributes, so this fixture
		// measures static origin routing without assuming dynamic JS support.
		fmt.Fprintf(w, `<!doctype html><title>%s</title><script nonce="provider-driver">
const outcome={script:false,fetch:'',status:0,body:'',frameReported:false,frameIsolated:false};
addEventListener('message',e=>{const frame=document.getElementById('provider');if(!frame||e.source!==frame.contentWindow||e.origin!==new URL(frame.src).origin||!e.data||e.data.fixture!=='provider-frame')return;outcome.frameReported=true;outcome.frameIsolated=e.data.isolated===true});
addEventListener('load',async()=>{const endpoint=document.getElementById('endpoint');if(endpoint){try{const response=await fetch(endpoint.href,{method:'vendor.sync',headers:{'X-Provider-Probe':'opaque'},body:'opaque'});outcome.fetch='response';outcome.status=response.status;outcome.body=await response.text()}catch(e){outcome.fetch='denied'}}setTimeout(()=>{outcome.script=window.providerScriptRan===true;parent.postMessage({fixture:'provider-control',name:location.pathname.split('/').pop(),outcome},location.origin)},350)});
</script>%s`, html.EscapeString(name), markup)
	})
	front := func(phase string, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/__provider_review":
				namesJSON, _ := json.Marshal(names)
				phaseJSON, _ := json.Marshal(phase)
				nextURL := ""
				if phase == "direct" {
					nextURL = proxyURL + "/__provider_review"
				}
				nextJSON, _ := json.Marshal(nextURL)
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Cache-Control", "no-store")
				fmt.Fprintf(w, `<!doctype html><title>Provider origin control pairs</title><h1>Provider origin control pairs</h1><p>Local HTTP fixtures; direct baseline followed by Blinder. No trust changes.</p><pre id="result">Running...</pre><script>
const phase=%s,names=%s,nextURL=%s,cases={},frames={};let done=false;
async function finish(){if(done)return;done=true;const report={phase,cases};document.getElementById('result').textContent=JSON.stringify(report,null,2);const r=await fetch('/__provider_report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(report)});if(!r.ok)throw Error('report rejected');if(nextURL)location.href=nextURL;else document.getElementById('result').prepend('Both phases completed.\n')}
addEventListener('message',e=>{const d=e.data;if(e.origin!==location.origin||!d||d.fixture!=='provider-control'||!names.includes(d.name)||e.source!==frames[d.name].contentWindow)return;cases[d.name]=d.outcome;if(Object.keys(cases).length===names.length)finish()});
for(const name of names){const f=document.createElement('iframe');f.src='/case/'+name;f.title=name;frames[name]=f;document.body.appendChild(f)}setTimeout(finish,12000);
</script>`, phaseJSON, namesJSON, nextJSON)
			case "/__provider_report":
				var report providerOriginBrowserReport
				if r.Method != http.MethodPost || json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&report) != nil || report.Phase != phase {
					http.Error(w, "invalid report", 400)
					return
				}
				select {
				case reports <- report:
				default:
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				next.ServeHTTP(w, r)
			}
		})
	}
	target := httptest.NewServer(front("direct", caseHandler))
	defer target.Close()
	targetURL = target.URL
	_, local, _, _, socksSeen := providerOriginFixture(t, target, []*httptest.Server{provider}, true, func(s *Server) http.Handler {
		transport := s.transport
		providerURL, _ := url.Parse(provider.URL)
		// Count each actual provider request entering the genuine SOCKS
		// transport. Connection counts alone cannot establish that individual
		// assets did not bypass the relay through direct browser requests.
		s.transport = providerOriginRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == providerURL.Host {
				proxyProviderMu.Lock()
				proxyProviderRequests[r.Method+" "+r.URL.RequestURI()]++
				proxyProviderMu.Unlock()
			}
			return transport.RoundTrip(r)
		})
		t.Cleanup(transport.(*http.Transport).CloseIdleConnections)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host == s.cfg.ListenAddr {
				front("proxy", s).ServeHTTP(w, r)
				return
			}
			s.ServeHTTP(w, r)
		})
	})
	proxyURL = local.URL
	ready := target.URL + "/__provider_review"
	if err := os.WriteFile("/private/tmp/blinder-provider-browser-url.txt", []byte(ready), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("Open Chrome at %s", ready)
	timer := time.NewTimer(3 * time.Minute)
	defer timer.Stop()
	var received []providerOriginBrowserReport
	for _, phase := range []string{"direct", "proxy"} {
		select {
		case report := <-reports:
			received = append(received, report)
			if report.Phase != phase || !reflect.DeepEqual(report.Cases, want) {
				t.Errorf("%s browser controls differ: got=%+v want=%+v", phase, report, want)
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for %s browser report", phase)
		}
	}
	rows := providerSeen.snapshot()
	counts := make(map[string]int)
	for _, row := range rows {
		counts[row.Method+" "+row.URI]++
	}
	wantCounts := map[string]int{
		"GET /v1/script.js": 2, "GET /v1/frame": 2, "GET /v1/frame-deny": 2, "GET /v1/frame.js": 2,
		"OPTIONS /v1/api/allow": 2, "vendor.sync /v1/api/allow": 2,
		"OPTIONS /v1/api/preflight-deny": 2,
		"OPTIONS /v1/api/acao-deny":      2, "vendor.sync /v1/api/acao-deny": 2,
	}
	if !reflect.DeepEqual(counts, wantCounts) {
		t.Errorf("provider request decisions differ: got=%v want=%v", counts, wantCounts)
	}
	proxyProviderMu.Lock()
	proxied := make(map[string]int, len(proxyProviderRequests))
	for request, count := range proxyProviderRequests {
		proxied[request] = count
	}
	proxyProviderMu.Unlock()
	for request, count := range wantCounts {
		if proxied[request] != count/2 {
			t.Errorf("provider route bypass or duplication: %s got=%d want=%d", request, proxied[request], count/2)
		}
	}
	if len(proxied) != len(wantCounts) {
		t.Errorf("unexpected proxy provider requests: %v", proxied)
	}
	evidence, _ := json.MarshalIndent(struct {
		Reports  []providerOriginBrowserReport `json:"reports"`
		Upstream map[string]int                `json:"upstreamRequests"`
		Proxied  map[string]int                `json:"proxiedRequests"`
		Requests []providerOriginObservation   `json:"requestDetails"`
	}{received, counts, proxied, rows}, "", "  ")
	if err := os.WriteFile("/private/tmp/blinder-provider-browser-report.json", evidence, 0600); err != nil {
		t.Error(err)
	}
	providerURL, _ := url.Parse(provider.URL)
	providerDials := 0
	for _, destination := range socksSeen() {
		if destination == providerURL.Host {
			providerDials++
		}
	}
	if providerDials == 0 {
		t.Fatal("proxy phase did not route provider traffic through SOCKS")
	}
	t.Logf("7 browser control pairs, request counts %v; provider SOCKS connections=%d", counts, providerDials)
}
