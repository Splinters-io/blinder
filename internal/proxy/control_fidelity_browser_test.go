package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/rewriter"
	xhtml "golang.org/x/net/html"
)

const controlPayload = `window.fixturePayloadRan = "AcmeCorp";`
const controlStyle = `#sample { color: rgb(1, 2, 3); --identity: "AcmeCorp"; }`
const controlDriverNonce = "cm-driver-nonce"
const controlDriver = `window.fixtureViolations=[];
addEventListener('securitypolicyviolation',function(e){window.fixtureViolations.push({directive:e.effectiveDirective,disposition:e.disposition})});
addEventListener('load',function(){const handler=document.getElementById('handler');if(handler)handler.click();setTimeout(function(){parent.postMessage({fixture:'control-fidelity',name:location.pathname.slice(location.pathname.lastIndexOf('/')+1),outcome:{payload:typeof window.fixturePayloadRan==='string',before:typeof window.fixtureBeforeRan==='string',color:getComputedStyle(document.getElementById('sample')).color,count:window.fixtureExecutionCount||0},violations:window.fixtureViolations},location.origin)},150)});`

type controlCase struct {
	name, markup   string
	headers        http.Header
	expect         controlOutcome
	violations     []controlViolation
	externalDriver bool
}

type controlOutcome struct {
	Payload bool   `json:"payload"`
	Before  bool   `json:"before"`
	Color   string `json:"color"`
	Count   int    `json:"count"`
}

type controlViolation struct {
	Directive   string `json:"directive"`
	Disposition string `json:"disposition"`
}

type controlCaseReport struct {
	Name       string             `json:"name"`
	Outcome    controlOutcome     `json:"outcome"`
	Violations []controlViolation `json:"violations"`
}

type controlBrowserReport struct {
	Phase string                       `json:"phase"`
	Cases map[string]controlCaseReport `json:"cases"`
}

type controlFixture struct {
	baseline, proxy *httptest.Server
	cases           []controlCase
	reports         chan controlBrowserReport
}

func controlHash(body string) string {
	digest := sha256.Sum256([]byte(body))
	return "'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
}

func newControlFixture(t *testing.T, cert tls.Certificate) *controlFixture {
	t.Helper()
	f := &controlFixture{reports: make(chan controlBrowserReport, 2)}
	caseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__control_driver" {
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Set("Cache-Control", "no-store")
			io.WriteString(w, controlDriver)
			return
		}
		for _, tc := range f.cases {
			if r.URL.Path != "/case/"+tc.name {
				continue
			}
			for name, values := range tc.headers {
				w.Header()[name] = append([]string(nil), values...)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			driver := `<script nonce="` + controlDriverNonce + `">` + controlDriver + `</script>`
			if tc.externalDriver {
				driver = `<script src="/__control_driver"></script>`
			}
			fmt.Fprintf(w, `<!doctype html><html><head><title>Local control fixture</title>%s%s</head><body><div id="sample">Control sample</div></body></html>`, driver, tc.markup)
			return
		}
		http.NotFound(w, r)
	})
	target := httptest.NewServer(caseHandler)
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
	transformed := rewriter.RewriteBody([]byte(controlPayload), "application/javascript", "/case/hash-transformed-deny", s.gate, false).Body
	if string(transformed) == controlPayload {
		t.Fatal("fixture identity must change the script bytes")
	}
	driverSource := "'nonce-" + controlDriverNonce + "'"
	script := `<script id="payload">` + controlPayload + `</script>`
	crlfPayload := "\r\n" + controlPayload + "\r\n"
	unpaddedHash := strings.TrimRight(strings.TrimSuffix(controlHash(controlPayload), "'"), "=") + "'"
	extraPaddedHash := strings.TrimSuffix(controlHash(controlPayload), "'") + "='"
	malformedPayload := "// \xff\n" + controlPayload
	decodedMalformedPayload := "// \ufffd\n" + controlPayload
	handler := `<button id="handler" onclick="` + html.EscapeString(controlPayload) + `">Execute fixture handler</button>`
	convergencePrefix := `window.fixtureExecutionCount = (window.fixtureExecutionCount || 0) + 1; window.fixturePayloadRan = `
	convergenceAllowed := convergencePrefix + fmt.Sprintf("%q;", target.URL+"/value")
	convergenceDenied := convergencePrefix + fmt.Sprintf("%q;", strings.Replace(target.URL, "http://", "HTTP://", 1)+"/value")
	policy := func(sources string) string { return "default-src 'none'; script-src " + driverSource + " " + sources }
	header := func(value string) http.Header { return http.Header{"Content-Security-Policy": {value}} }
	allowed := controlOutcome{Payload: true, Color: "rgb(0, 0, 0)"}
	blocked := controlOutcome{Color: "rgb(0, 0, 0)"}
	deniedViolation := []controlViolation{{Directive: "script-src-elem", Disposition: "enforce"}}
	f.cases = []controlCase{
		{name: "hash-allow", markup: script, headers: header(policy(controlHash(controlPayload))), expect: allowed},
		{name: "hash-transformed-deny", markup: script, headers: header(policy(controlHash(string(transformed)))), expect: blocked, violations: deniedViolation},
		{name: "hash-transformed-unsafe-inline-deny", markup: script, headers: header("default-src 'none'; script-src 'self' 'unsafe-inline' " + controlHash(string(transformed))), expect: blocked, violations: deniedViolation, externalDriver: true},
		{name: "hash-crlf-allow", markup: `<script id="payload">` + crlfPayload + `</script>`, headers: header(policy(controlHash(strings.ReplaceAll(crlfPayload, "\r\n", "\n")))), expect: allowed},
		{name: "hash-unpadded-allow", markup: script, headers: header(policy(unpaddedHash)), expect: allowed},
		{name: "hash-extra-padding-deny", markup: script, headers: header(policy(extraPaddedHash)), expect: blocked, violations: deniedViolation},
		{name: "hash-malformed-utf8-comment-allow", markup: `<script id="payload">` + malformedPayload + `</script>`, headers: header(policy(controlHash(decodedMalformedPayload))), expect: allowed},
		{name: "hash-distinct-source-convergence", markup: `<script id="allowed-source">` + convergenceAllowed + `</script><script id="denied-source">` + convergenceDenied + `</script>`, headers: header(policy(controlHash(convergenceAllowed))), expect: controlOutcome{Payload: true, Color: "rgb(0, 0, 0)", Count: 1}, violations: deniedViolation},
		{name: "nonce-allow", markup: `<script id="payload" nonce="payload-nonce">` + controlPayload + `</script>`, headers: header(policy("'nonce-payload-nonce'")), expect: allowed},
		{name: "nonce-deny", markup: `<script id="payload" nonce="different-nonce">` + controlPayload + `</script>`, headers: header(policy("'nonce-payload-nonce'")), expect: blocked, violations: deniedViolation},
		{name: "nonce-identity-allow", markup: `<script id="payload" nonce="AcmeCorp">` + controlPayload + `</script>`, headers: header(policy("'nonce-AcmeCorp'")), expect: allowed},
		{name: "nonce-identity-mismatch-deny", markup: `<script id="payload" nonce="AcmeCorp-other">` + controlPayload + `</script>`, headers: header(policy("'nonce-AcmeCorp'")), expect: blocked, violations: deniedViolation},
		{name: "style-hash-allow", markup: `<style id="payload-style">` + controlStyle + `</style>`, headers: header(policy("") + "; style-src " + controlHash(controlStyle)), expect: controlOutcome{Color: "rgb(1, 2, 3)"}},
		{name: "handler-hash-allow", markup: handler, headers: header(policy("'unsafe-hashes' " + controlHash(controlPayload))), expect: allowed},
		{name: "handler-hash-without-opt-in-deny", markup: handler, headers: header(policy(controlHash(controlPayload))), expect: blocked, violations: []controlViolation{{Directive: "script-src-attr", Disposition: "enforce"}}},
		{name: "handler-before-meta-allow", markup: `<title id="handler" onclick="` + html.EscapeString(controlPayload) + `">Handler sample</title><meta http-equiv="Content-Security-Policy" content="` + html.EscapeString(policy("'unsafe-hashes' "+controlHash(controlPayload))) + `">`, expect: allowed},
		{name: "policies-intersect", markup: script, headers: http.Header{"Content-Security-Policy": {policy(controlHash(controlPayload)), policy("")}}, expect: blocked, violations: deniedViolation},
		{name: "report-only", markup: script, headers: http.Header{"Content-Security-Policy-Report-Only": {policy("")}}, expect: allowed, violations: []controlViolation{{Directive: "script-src-elem", Disposition: "report"}}},
		{name: "meta-position", markup: `<script>window.fixtureBeforeRan = "AcmeCorp";</script><meta http-equiv="Content-Security-Policy" content="` + html.EscapeString(policy("")) + `">` + script, expect: controlOutcome{Before: true, Color: "rgb(0, 0, 0)"}, violations: deniedViolation},
		{name: "meta-hash-allow", markup: `<meta http-equiv="Content-Security-Policy" content="` + html.EscapeString(policy(controlHash(controlPayload))) + `">` + script, expect: allowed},
	}
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
			fmt.Fprintf(w, `<!doctype html><title>Local CSP control comparison</title><h1>Local CSP control comparison</h1><p>Local synthetic resources only. The direct baseline runs first, then Blinder.</p><pre id="result">Running...</pre><script>
const names=%s, phase=%s, nextURL=%s, reports={}, frames={};
let finished=false;
async function finish(){if(finished)return;finished=true;const result={phase,cases:reports};document.getElementById('result').textContent=JSON.stringify(result,null,2);const response=await fetch('/__review_report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(result)});if(!response.ok)throw new Error('report rejected');if(nextURL)location.href=nextURL;else document.getElementById('result').prepend('Completed direct and Blinder CSP comparison.\n')}
addEventListener('message',e=>{const report=e.data;if(e.origin!==location.origin||!report||report.fixture!=='control-fidelity'||!names.includes(report.name)||e.source!==frames[report.name].contentWindow)return;reports[report.name]={name:report.name,outcome:report.outcome,violations:report.violations};if(Object.keys(reports).length===names.length)finish()});
for(const name of names){const frame=document.createElement('iframe');frame.title=name;frame.src='/case/'+name;frames[name]=frame;document.body.appendChild(frame)}
setTimeout(finish,12000);
</script>`, namesJSON, phaseJSON, nextJSON)
		})
		mux.HandleFunc("/__review_report", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "POST required", http.StatusMethodNotAllowed)
				return
			}
			var report controlBrowserReport
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
	f.baseline = httptest.NewUnstartedServer(frontHandler("direct", caseHandler))
	start(f.baseline)
	return f
}

// This is an actual browser test: Go only hosts the fixture and checks reports.
// The controller is outside the proxy; every measured iframe travels through
// either the original handler or Blinder. No browser trust settings are changed.
func TestControlFidelityBrowser(t *testing.T) {
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
	f := newControlFixture(t, cert)
	if err := os.WriteFile("/private/tmp/blinder-csp-browser-url.txt", []byte(f.baseline.URL+"/__review"), 0600); err != nil {
		t.Fatal(err)
	}
	reports := make(map[string]controlBrowserReport)
	timer := time.NewTimer(180 * time.Second)
	defer timer.Stop()
wait:
	for len(reports) < 2 {
		select {
		case report := <-f.reports:
			reports[report.Phase] = report
		case <-timer.C:
			t.Error("browser did not complete both CSP stages within 180 seconds")
			break wait
		}
	}
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
				if !sameControlViolations(report.Violations, tc.violations) {
					t.Errorf("policy violations = %+v, want %+v", report.Violations, tc.violations)
				}
				if phase == "proxy" {
					direct := reports["direct"].Cases[tc.name]
					if report.Outcome != direct.Outcome || !sameControlViolations(report.Violations, direct.Violations) {
						t.Errorf("proxy result differs from direct browser baseline: proxy=%+v direct=%+v", report, direct)
					}
				}
			})
		}
	}
	evidence := map[string]any{"directURL": f.baseline.URL, "proxyURL": f.proxy.URL, "reports": reports, "passed": !t.Failed()}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/private/tmp/blinder-csp-browser-result.json", data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
}

func sameControlViolations(a, b []controlViolation) bool {
	counts := func(values []controlViolation) map[controlViolation]int {
		result := make(map[controlViolation]int)
		for _, value := range values {
			result[value]++
		}
		return result
	}
	return reflect.DeepEqual(counts(a), counts(b))
}

// Browser execution is still the acceptance test. This ordinary wire regression
// makes a missing hash translation fail without requiring an interactive browser.
func TestControlFidelityCSPWire(t *testing.T) {
	f := newControlFixture(t, tls.Certificate{})
	for _, tc := range []struct{ name, tag, source string }{
		{"hash-allow", "script", controlPayload},
		{"hash-crlf-allow", "script", "\r\n" + controlPayload + "\r\n"},
		{"style-hash-allow", "style", controlStyle},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := f.proxy.Client().Get(f.proxy.URL + "/case/" + tc.name)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			var payload string
			z := xhtml.NewTokenizer(strings.NewReader(string(body)))
			for tt := z.Next(); tt != xhtml.ErrorToken; tt = z.Next() {
				if tt != xhtml.StartTagToken {
					continue
				}
				tok := z.Token()
				if tok.Data != tc.tag {
					continue
				}
				for _, attr := range tok.Attr {
					if attr.Key == "id" && strings.HasPrefix(attr.Val, "payload") && z.Next() == xhtml.TextToken {
						payload = string(z.Text())
					}
				}
			}
			if payload == "" || payload == tc.source || strings.Contains(payload, "AcmeCorp") {
				t.Fatalf("fixture payload was not masked: %q", payload)
			}
			csp := resp.Header.Get("Content-Security-Policy")
			if !strings.Contains(csp, controlHash(payload)) {
				t.Errorf("CSP does not permit the actual rewritten bytes: policy=%q expected=%q", csp, controlHash(payload))
			}
		})
	}
}

func TestControlFidelityHandlerBeforeMetaWire(t *testing.T) {
	f := newControlFixture(t, tls.Certificate{})
	resp, err := f.proxy.Client().Get(f.proxy.URL + "/case/handler-before-meta-allow")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var handler, policy string
	z := xhtml.NewTokenizer(resp.Body)
	for tt := z.Next(); tt != xhtml.ErrorToken; tt = z.Next() {
		if tt != xhtml.StartTagToken {
			continue
		}
		tok := z.Token()
		for _, attr := range tok.Attr {
			if attr.Key == "onclick" {
				handler = attr.Val
			}
			if tok.Data == "meta" && attr.Key == "content" {
				policy = attr.Val
			}
		}
	}
	if handler == "" || handler == controlPayload || strings.Contains(handler, "AcmeCorp") {
		t.Fatalf("handler was not masked: %q", handler)
	}
	if !strings.Contains(policy, controlHash(handler)) {
		t.Errorf("meta policy no longer allows its earlier handler when executed after policy installation: policy=%q handler=%q expected=%q", policy, handler, controlHash(handler))
	}
}
