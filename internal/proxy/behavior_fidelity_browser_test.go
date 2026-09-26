package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/rewriter"
	xhtml "golang.org/x/net/html"
)

const behaviorPayload = `window.audit="AcmeCorp";void(0)`
const behaviorLoad = `window.imageLoads=(window.imageLoads||0)+1;window.imageIdentity="AcmeCorp";`
const behaviorError = `window.imageErrors=(window.imageErrors||0)+1;window.imageIdentity="AcmeCorp";`
const behaviorDriverNonce = "behavior-driver"
const behaviorDriver = `window.behaviorViolations=[];
addEventListener('securitypolicyviolation',function(e){window.behaviorViolations.push({directive:e.effectiveDirective,disposition:e.disposition})});
addEventListener('load',function(){const link=document.getElementById('action');if(link)link.click();setTimeout(function(){const img=document.getElementById('sample');const name=location.pathname.slice(location.pathname.lastIndexOf('/')+1);let comments=0;const walker=document.createTreeWalker(document,NodeFilter.SHOW_COMMENT);while(walker.nextNode())comments++;parent.postMessage({fixture:'behavior-fidelity',name:name,outcome:{audit:typeof window.audit==='string',auditTail:name==='javascript-isomorphic-hash-allow'&&typeof window.audit==='string'?window.audit.slice(-3):'',loads:window.imageLoads||0,errors:window.imageErrors||0,imageIdentity:typeof window.imageIdentity==='string',complete:!!img&&img.complete,width:img?img.naturalWidth:0,height:img?img.naturalHeight:0,marker:!!document.getElementById('marker'),truncated:!!document.getElementById('truncated'),comments:comments},violations:window.behaviorViolations},location.origin)},200)});`

type behaviorOutcome struct {
	Audit         bool   `json:"audit"`
	AuditTail     string `json:"auditTail,omitempty"`
	Loads         int    `json:"loads"`
	Errors        int    `json:"errors"`
	ImageIdentity bool   `json:"imageIdentity"`
	Complete      bool   `json:"complete"`
	Width         int    `json:"width"`
	Height        int    `json:"height"`
	Marker        bool   `json:"marker"`
	Truncated     bool   `json:"truncated"`
	Comments      int    `json:"comments"`
}

type behaviorCase struct {
	name, markup, policy string
	expect               behaviorOutcome
	violations, requests int
	rawTail              bool
}

type behaviorCaseReport struct {
	Name       string             `json:"name"`
	Outcome    behaviorOutcome    `json:"outcome"`
	Violations []controlViolation `json:"violations"`
}

type behaviorBrowserReport struct {
	Phase string                        `json:"phase"`
	Cases map[string]behaviorCaseReport `json:"cases"`
}

type behaviorAsset struct {
	body        []byte
	contentType string
	status      int
}

type behaviorFixture struct {
	baseline, proxy *httptest.Server
	cases           []behaviorCase
	reports         chan behaviorBrowserReport
	mu              sync.Mutex
	requests        map[string]map[string]int
}

func (f *behaviorFixture) requestCounts() map[string]map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make(map[string]map[string]int)
	for phase, counts := range f.requests {
		result[phase] = make(map[string]int)
		for name, count := range counts {
			result[phase][name] = count
		}
	}
	return result
}

func newBehaviorFixture(t *testing.T, cert tls.Certificate) *behaviorFixture {
	t.Helper()
	f := &behaviorFixture{reports: make(chan behaviorBrowserReport, 2), requests: map[string]map[string]int{"direct": {}, "proxy": {}}}
	pixels := image.NewRGBA(image.Rect(0, 0, 3, 2))
	pixels.SetRGBA(0, 0, color.RGBA{R: 230, A: 255})
	pixels.SetRGBA(1, 0, color.RGBA{G: 230, A: 255})
	pixels.SetRGBA(2, 1, color.RGBA{B: 230, A: 255})
	assets := make(map[string]behaviorAsset)
	for _, format := range []string{"png", "jpeg", "gif"} {
		var body bytes.Buffer
		var err error
		switch format {
		case "png":
			err = png.Encode(&body, pixels)
		case "jpeg":
			err = jpeg.Encode(&body, pixels, nil)
		case "gif":
			err = gif.Encode(&body, pixels, nil)
		}
		if err != nil {
			t.Fatal(err)
		}
		assets["image-"+format] = behaviorAsset{body.Bytes(), "image/" + format, http.StatusOK}
	}
	assets["image-invalid"] = behaviorAsset{[]byte("AcmeCorp invalid image bytes"), "image/png", http.StatusOK}
	assets["image-missing"] = behaviorAsset{[]byte("AcmeCorp image not found"), "image/png", http.StatusNotFound}
	assets["image-csp-denied"] = assets["image-png"]
	caseHandler := func(phase string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if r.URL.Path == "/__behavior_driver" {
				w.Header().Set("Content-Type", "application/javascript")
				io.WriteString(w, behaviorDriver)
				return
			}
			if name := strings.TrimPrefix(r.URL.Path, "/asset/AcmeCorp/"); name != r.URL.Path {
				if asset, ok := assets[name]; ok {
					f.mu.Lock()
					f.requests[phase][name]++
					f.mu.Unlock()
					w.Header().Set("Content-Type", asset.contentType)
					w.WriteHeader(asset.status)
					w.Write(asset.body)
					return
				}
			}
			for _, tc := range f.cases {
				if r.URL.Path != "/case/"+tc.name {
					continue
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if tc.policy != "" {
					w.Header().Set("Content-Security-Policy", tc.policy)
				}
				fmt.Fprintf(w, `<!doctype html><html><head><title>Local behavior fixture</title><script nonce="%s" src="/__behavior_driver"></script></head><body>%s`, behaviorDriverNonce, tc.markup)
				if !tc.rawTail {
					io.WriteString(w, `</body></html>`)
				}
				return
			}
			http.NotFound(w, r)
		})
	}
	target := httptest.NewServer(caseHandler("proxy"))
	t.Cleanup(target.Close)
	f.proxy = httptest.NewUnstartedServer(nil)
	cfg, err := config.New(target.URL, f.proxy.Listener.Addr().String(), "127.0.0.1", []string{"AcmeCorp"}, true, false, false, "", "", 0, "", "", 10, 30)
	if err != nil {
		t.Fatal(err)
	}
	cfg.VersionKeyDir = t.TempDir()
	if err := os.Chmod(cfg.VersionKeyDir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := NewWithCertificate(cfg, cert)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Shutdown(context.Background())
		s.transport.(*http.Transport).CloseIdleConnections()
	})
	link := `<a id="action" href="javascript:` + html.EscapeString(behaviorPayload) + `">Run fixture</a>`
	transformedBody := rewriter.RewriteBody([]byte(link), "text/html", "/case/javascript-transformed-deny", s.gate, false).Body
	var transformedURL string
	z := xhtml.NewTokenizer(bytes.NewReader(transformedBody))
	for tt := z.Next(); tt != xhtml.ErrorToken; tt = z.Next() {
		if tt != xhtml.StartTagToken {
			continue
		}
		token := z.Token()
		if token.Data == "a" {
			for _, attr := range token.Attr {
				if attr.Key == "href" {
					transformedURL = attr.Val
				}
			}
		}
	}
	if transformedURL == "" || transformedURL == "javascript:"+behaviorPayload || strings.Contains(transformedURL, "AcmeCorp") {
		t.Fatal("fixture payload must have its configured identity masked")
	}
	policy := func(sources string) string {
		return "default-src 'none'; script-src 'nonce-" + behaviorDriverNonce + "' " + sources
	}
	const encodedURL = `javascript:window.audit=%22AcmeCorp%22;void(0)`
	const isomorphicURL = `javascript:window.audit=%22AcmeCorp%C3%A9%FF%22;void(0)`
	const isomorphicDecodedURL = `javascript:window.audit="AcmeCorpÃ©ÿ";void(0)`
	f.cases = []behaviorCase{
		{name: "javascript-allow", markup: link, expect: behaviorOutcome{Audit: true}},
		{name: "javascript-deny", markup: link, policy: policy(""), violations: 1},
		{name: "javascript-hash-allow", markup: link, policy: policy("'unsafe-hashes' " + controlHash("javascript:"+behaviorPayload)), expect: behaviorOutcome{Audit: true}},
		{name: "javascript-encoded-decoded-hash-allow", markup: `<a id="action" href="` + encodedURL + `">Run encoded fixture</a>`, policy: policy("'unsafe-hashes' " + controlHash("javascript:"+behaviorPayload)), expect: behaviorOutcome{Audit: true}},
		{name: "javascript-encoded-spelling-hash-deny", markup: `<a id="action" href="` + encodedURL + `">Run encoded fixture</a>`, policy: policy("'unsafe-hashes' " + controlHash(encodedURL)), violations: 1},
		{name: "javascript-transformed-deny", markup: link, policy: policy("'unsafe-hashes' " + controlHash(transformedURL)), violations: 1},
		{name: "javascript-isomorphic-hash-allow", markup: `<a id="action" href="` + isomorphicURL + `">Run byte decoding fixture</a>`, policy: policy("'unsafe-hashes' " + controlHash(isomorphicDecodedURL)), expect: behaviorOutcome{Audit: true, AuditTail: "Ã©ÿ"}},
	}
	for _, name := range []string{"image-png", "image-jpeg", "image-gif", "image-invalid", "image-missing", "image-csp-denied"} {
		imgSource := "'self'"
		expected := behaviorOutcome{Loads: 1, ImageIdentity: true, Complete: true, Width: 3, Height: 2}
		requests, violations := 1, 0
		if name == "image-invalid" || name == "image-missing" || name == "image-csp-denied" {
			expected = behaviorOutcome{Errors: 1, ImageIdentity: true, Complete: true}
		}
		if name == "image-csp-denied" {
			imgSource, requests, violations = "'none'", 0, 1
		}
		f.cases = append(f.cases, behaviorCase{
			name: name, markup: `<img id="sample" src="/asset/AcmeCorp/` + name + `" onload="` + html.EscapeString(behaviorLoad) + `" onerror="` + html.EscapeString(behaviorError) + `">`,
			policy: policy("'unsafe-hashes' "+controlHash(behaviorLoad)+" "+controlHash(behaviorError)) + "; img-src " + imgSource,
			expect: expected, violations: violations, requests: requests,
		})
	}
	f.cases = append(f.cases,
		behaviorCase{name: "malformed-comment-script", markup: `<!--AcmeCorp--!><script>window.audit="AcmeCorp";</script><p id="marker">After comment</p>`, expect: behaviorOutcome{Audit: true, Marker: true, Comments: 1}},
		behaviorCase{name: "truncated-tag", markup: `<p id="marker">Before truncation</p><section id=truncated data-note="AcmeCorp`, rawTail: true, expect: behaviorOutcome{Marker: true}},
	)
	frontHandler := func(phase string, next http.Handler) http.Handler {
		mux := http.NewServeMux()
		mux.HandleFunc("/__review", func(w http.ResponseWriter, r *http.Request) {
			var names []string
			for _, tc := range f.cases {
				names = append(names, tc.name)
			}
			namesJSON, _ := json.Marshal(names)
			phaseJSON, _ := json.Marshal(phase)
			nextURL := ""
			if phase == "direct" {
				nextURL = f.proxy.URL + "/__review"
			}
			nextJSON, _ := json.Marshal(nextURL)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			fmt.Fprintf(w, `<!doctype html><title>Local behavior comparison</title><h1>Local behavior comparison</h1><p>Local synthetic resources only. Direct then Blinder: JavaScript URLs, image outcomes and malformed source.</p><pre id="result">Running...</pre><script>
const names=%s,phase=%s,nextURL=%s,reports={},frames={};let finished=false;
async function finish(){if(finished)return;finished=true;const result={phase,cases:reports};document.getElementById('result').textContent=JSON.stringify(result,null,2);const response=await fetch('/__review_report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(result)});if(!response.ok)throw new Error('report rejected');if(nextURL)location.href=nextURL;else document.getElementById('result').prepend('Completed direct and Blinder behavior comparison.\n')}
addEventListener('message',e=>{const report=e.data;if(e.origin!==location.origin||!report||report.fixture!=='behavior-fidelity'||!names.includes(report.name)||e.source!==frames[report.name].contentWindow)return;reports[report.name]={name:report.name,outcome:report.outcome,violations:report.violations};if(Object.keys(reports).length===names.length)finish()});
for(const name of names){const frame=document.createElement('iframe');frame.title=name;frame.src='/case/'+name;frames[name]=frame;document.body.appendChild(frame)}setTimeout(finish,12000);
</script>`, namesJSON, phaseJSON, nextJSON)
		})
		mux.HandleFunc("/__review_report", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "POST required", http.StatusMethodNotAllowed)
				return
			}
			var report behaviorBrowserReport
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&report) != nil || report.Phase != phase {
				http.Error(w, "invalid report", http.StatusBadRequest)
				return
			}
			select {
			case f.reports <- report:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
		})
		mux.Handle("/", next)
		return mux
	}
	start := func(front *httptest.Server) {
		if len(cert.Certificate) > 0 {
			front.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		}
		front.StartTLS()
		t.Cleanup(front.Close)
	}
	f.proxy.Config.Handler = frontHandler("proxy", s)
	start(f.proxy)
	f.baseline = httptest.NewUnstartedServer(frontHandler("direct", caseHandler("direct")))
	start(f.baseline)
	return f
}

// Chrome executes both copies. The nonce-authorized observer is identical and
// reports explicit successful and blocked controls; two equal failures do not pass.
func TestBehaviorFidelityBrowser(t *testing.T) {
	if os.Getenv("BLINDER_REVIEW_BROWSER") != "1" {
		t.Skip("requires local Chrome with the acceptance certificate trusted")
	}
	dir := os.Getenv("BLINDER_REVIEW_CERT_DIR")
	if dir == "" {
		dir = "/private/tmp/blinder-acceptance-certs"
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "identity.pem"), filepath.Join(dir, "identity.pem"))
	if err != nil {
		t.Fatal(err)
	}
	f := newBehaviorFixture(t, cert)
	if err := os.WriteFile("/private/tmp/blinder-behavior-browser-url.txt", []byte(f.baseline.URL+"/__review"), 0600); err != nil {
		t.Fatal(err)
	}
	reports := make(map[string]behaviorBrowserReport)
	timer := time.NewTimer(180 * time.Second)
	defer timer.Stop()
wait:
	for len(reports) < 2 {
		select {
		case report := <-f.reports:
			reports[report.Phase] = report
		case <-timer.C:
			t.Error("browser did not complete both behavior stages within 180 seconds")
			break wait
		}
	}
	counts := f.requestCounts()
	for _, phase := range []string{"direct", "proxy"} {
		for _, tc := range f.cases {
			t.Run(phase+"/"+tc.name, func(t *testing.T) {
				report, ok := reports[phase].Cases[tc.name]
				if !ok {
					t.Fatal("missing browser outcome")
				}
				if report.Outcome != tc.expect {
					t.Errorf("outcome = %+v, want %+v", report.Outcome, tc.expect)
				}
				if len(report.Violations) != tc.violations {
					t.Errorf("policy violations = %+v, want %d", report.Violations, tc.violations)
				}
				if count := counts[phase][tc.name]; count != tc.requests {
					t.Errorf("asset upstream requests = %d, want %d", count, tc.requests)
				}
				if phase == "proxy" {
					direct := reports["direct"].Cases[tc.name]
					if report.Outcome != direct.Outcome || !sameControlViolations(report.Violations, direct.Violations) {
						t.Errorf("proxy differs from direct browser outcome: proxy=%+v direct=%+v", report, direct)
					}
				}
			})
		}
	}
	evidence := map[string]any{"directURL": f.baseline.URL, "proxyURL": f.proxy.URL, "reports": reports, "assetRequests": counts, "pairs": len(f.cases), "passed": !t.Failed()}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/private/tmp/blinder-behavior-browser-result.json", data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
}

// The browser cannot expose unfinished markup through outerHTML: the tokenizer
// discards its final token. Preserve the source boundary separately as evidence.
func TestBehaviorFidelityTruncatedSourceWire(t *testing.T) {
	f := newBehaviorFixture(t, tls.Certificate{})
	resp, err := f.proxy.Client().Get(f.proxy.URL + "/case/truncated-tag")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	const tail = `<section id=truncated data-note="`
	start := bytes.Index(body, []byte(tail))
	if start < 0 {
		t.Fatal("incomplete final source tag was omitted")
	}
	value := body[start+len(tail):]
	if len(value) != len("AcmeCorp") || bytes.ContainsAny(value, `"<>`) || bytes.Contains(body, []byte("AcmeCorp")) {
		t.Fatalf("identity masking changed incomplete-tag boundary or exposed source: tail=%q", body[start:])
	}
}
