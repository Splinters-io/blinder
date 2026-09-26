package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
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
	"github.com/Splinters-io/blinder/internal/rewriter"
	xhtml "golang.org/x/net/html"
)

const externalControlPayload = `window.fixturePayloadRan="AcmeCorp";window.fixtureExecutionCount=(window.fixtureExecutionCount||0)+1;`
const externalControlDriver = `window.fixtureViolations=[];window.fixtureResourceErrors=[];
addEventListener('securitypolicyviolation',function(e){window.fixtureViolations.push({directive:e.effectiveDirective,disposition:e.disposition})});
addEventListener('error',function(e){if(e.target instanceof HTMLScriptElement)window.fixtureResourceErrors.push(e.target.id)},true);
addEventListener('load',function(){setTimeout(function(){parent.postMessage({fixture:'external-control-fidelity',name:location.pathname.slice(location.pathname.lastIndexOf('/')+1),count:window.fixtureExecutionCount||0,violations:window.fixtureViolations,resourceErrors:window.fixtureResourceErrors},location.origin)},150)});`

type externalControlCase struct {
	name, markup string
	headers      http.Header
	count        int
	violations   []controlViolation
	errors       []string
}

type externalControlCaseReport struct {
	Name           string             `json:"name"`
	Count          int                `json:"count"`
	Violations     []controlViolation `json:"violations"`
	ResourceErrors []string           `json:"resourceErrors"`
}

type externalControlReport struct {
	Phase string                               `json:"phase"`
	Cases map[string]externalControlCaseReport `json:"cases"`
}

type externalControlFixture struct {
	baseline, proxy *httptest.Server
	cases           []externalControlCase
	reports         chan externalControlReport
	mu              sync.Mutex
	requests        map[string]map[string]int
	assets          map[string]externalControlAsset
}

type externalControlAsset struct{ body, cacheControl string }

func externalControlDigest(body, algorithm string) string {
	if algorithm == "sha512" {
		digest := sha512.Sum512([]byte(body))
		return algorithm + "-" + base64.StdEncoding.EncodeToString(digest[:])
	}
	digest := sha256.Sum256([]byte(body))
	return "sha256-" + base64.StdEncoding.EncodeToString(digest[:])
}

func (f *externalControlFixture) requestCounts() map[string]map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make(map[string]map[string]int)
	for phase, requests := range f.requests {
		result[phase] = make(map[string]int)
		for path, count := range requests {
			result[phase][path] = count
		}
	}
	return result
}

func newExternalControlFixture(t *testing.T, cert tls.Certificate) *externalControlFixture {
	t.Helper()
	f := &externalControlFixture{reports: make(chan externalControlReport, 2), requests: map[string]map[string]int{"direct": {}, "proxyUpstream": {}}, assets: make(map[string]externalControlAsset)}
	caseHandler := func(phase string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/asset/") {
				f.mu.Lock()
				f.requests[phase][r.URL.Path]++
				f.mu.Unlock()
				asset, ok := f.assets[r.URL.Path]
				if !ok {
					asset = externalControlAsset{externalControlPayload, "public, max-age=3600"}
				}
				w.Header().Set("Content-Type", "application/javascript")
				w.Header().Set("Cache-Control", asset.cacheControl)
				io.WriteString(w, asset.body)
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
				fmt.Fprintf(w, `<!doctype html><html><head><title>Local external CSP fixture</title><script nonce="%s">%s</script>%s</head><body>Local external resource control fixture</body></html>`, controlDriverNonce, externalControlDriver, tc.markup)
				return
			}
			http.NotFound(w, r)
		})
	}
	target := httptest.NewServer(caseHandler("proxyUpstream"))
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
	t.Cleanup(func() { s.Shutdown(context.Background()); s.transport.(*http.Transport).CloseIdleConnections() })
	transformed := string(rewriter.RewriteBody([]byte(externalControlPayload), "application/javascript", "/asset/transformed-deny", s.gate, false).Body)
	if transformed == externalControlPayload {
		t.Fatal("external resource fixture must change its identity-bearing bytes")
	}
	d256, d512 := externalControlDigest(externalControlPayload, "sha256"), externalControlDigest(externalControlPayload, "sha512")
	invalidWeaker := externalControlDigest(transformed, "sha256")
	d256Unpadded := strings.TrimRight(d256, "=")
	d256URLSafe := strings.NewReplacer("+", "-", "/", "_").Replace(d256)
	if d256URLSafe == d256 {
		t.Fatal("spelling fixture needs a SHA256 digest containing '+' or '/'")
	}
	quote := func(source string) string { return "'" + source + "'" }
	policy := func(sources string) string {
		return "default-src 'none'; script-src 'nonce-" + controlDriverNonce + "' " + sources
	}
	header := func(value string) http.Header { return http.Header{"Content-Security-Policy": {value}} }
	script := func(id, path, integrity, nonce string) string {
		extra := ""
		if nonce != "" {
			extra = ` nonce="` + html.EscapeString(nonce) + `"`
		}
		return `<script id="` + id + `" src="` + path + `" integrity="` + integrity + `"` + extra + `></script>`
	}
	denied := []controlViolation{{Directive: "script-src-elem", Disposition: "enforce"}}
	// Each case has its own neutral marker, so a previously cached case cannot
	// establish the source identity for a later document-order regression.
	collisionSources := func(label string) (string, string) {
		prefix := `window.fixtureCollisionCase=` + fmt.Sprintf("%q;", label) + `window.fixtureURL=`
		a := prefix + fmt.Sprintf("%q;", target.URL+"/value") + externalControlPayload
		b := prefix + fmt.Sprintf("%q;", strings.Replace(target.URL, "http://", "HTTP://", 1)+"/value") + externalControlPayload
		return a, b
	}
	extFirst, extFirstInline := collisionSources("external-first")
	inlineFirstExternal, inlineFirst := collisionSources("inline-first")
	pairA, pairB := collisionSources("external-pair")
	noStoreA, noStoreB := collisionSources("no-store-pair")
	f.assets["/asset/collision-external-first"] = externalControlAsset{extFirst, "public, max-age=3600"}
	f.assets["/asset/collision-inline-first"] = externalControlAsset{inlineFirstExternal, "public, max-age=3600"}
	f.assets["/asset/collision-pair-a"] = externalControlAsset{pairA, "public, max-age=3600"}
	f.assets["/asset/collision-pair-b"] = externalControlAsset{pairB, "public, max-age=3600"}
	f.assets["/asset/collision-no-store-a"] = externalControlAsset{noStoreA, "no-store"}
	f.assets["/asset/collision-no-store-b"] = externalControlAsset{noStoreB, "no-store"}
	inline := func(body string) string { return `<script id="inline-payload">` + body + `</script>` }
	hash := func(body string) string { return externalControlDigest(body, "sha256") }
	reported := []controlViolation{{Directive: "script-src-elem", Disposition: "report"}}
	rewriteLocalJS := func(body string) string {
		return string(rewriter.RewriteBody([]byte(body), "application/javascript", "/asset/collision-setup", s.gate, false, rewriter.RewriteOpts{Origins: s.origins.ForRequestHost(cfg.ListenAddr)}).Body)
	}
	// C -> A -> B: A contains the literal alias generated from C, which the
	// second rewrite must escape. Swapping invalid weak H(B) to H(A) must not
	// create permission for the otherwise blocked inline C -> A.
	weakInline := `window.fixtureCollisionCase="invalid-weak-inline";` + externalControlPayload
	weakExternal := rewriteLocalJS(weakInline)
	weakRewritten := rewriteLocalJS(weakExternal)
	if weakInline == weakExternal || weakExternal == weakRewritten {
		t.Fatal("invalid-weak fixture needs two distinct transformation steps")
	}
	weakMetadata := hash(weakRewritten) + " " + externalControlDigest(weakExternal, "sha512")
	f.assets["/asset/collision-invalid-weak-inline"] = externalControlAsset{weakExternal, "public, max-age=3600"}
	// A is an already-local URL literal and is unchanged by rewriting. B has
	// the upstream URL and converges onto A. Authorising B must not authorise
	// an earlier, originally denied reference to A or cause a prefetch for it.
	deniedSensitive := `window.fixtureCollisionCase="denied-reference";window.fixtureURL=` + fmt.Sprintf("%q;", target.URL+"/value") + `window.fixtureExecutionCount=(window.fixtureExecutionCount||0)+1;`
	deniedNeutral := rewriteLocalJS(deniedSensitive)
	if deniedSensitive == deniedNeutral || rewriteLocalJS(deniedNeutral) != deniedNeutral {
		t.Fatal("denied-reference fixture needs a sensitive source converging onto an unchanged local source")
	}
	f.assets["/asset/collision-denied-neutral"] = externalControlAsset{deniedNeutral, "public, max-age=3600"}
	f.assets["/asset/collision-authorized-sensitive"] = externalControlAsset{deniedSensitive, "public, max-age=3600"}
	f.cases = []externalControlCase{
		{name: "original-sha256-allow", markup: script("payload", "/asset/order-256-512", d256, ""), headers: header(policy(quote(d256))), count: 1},
		// Modern Chrome ignores classic nomodule scripts entirely. This is
		// browser-specific acceptance, not a claim about legacy browsers.
		{name: "chrome-classic-nomodule-ignored", markup: `<script id="payload" nomodule src="/asset/nomodule-ignored" integrity="` + d256 + `"></script>`, headers: header(policy(quote(d256)))},
		{name: "cached-sha512-after-sha256", markup: script("payload", "/asset/order-256-512", d512, ""), headers: header(policy(quote(d512))), count: 1},
		{name: "original-sha512-allow", markup: script("payload", "/asset/order-512-256", d512, ""), headers: header(policy(quote(d512))), count: 1},
		{name: "cached-sha256-after-sha512", markup: script("payload", "/asset/order-512-256", d256, ""), headers: header(policy(quote(d256))), count: 1},
		{name: "chrome-legacy-sha-256-allow", markup: script("payload", "/asset/legacy-sha-256", strings.Replace(d256, "sha256-", "sha-256-", 1), ""), headers: header(policy(quote(d256))), count: 1},
		{name: "chrome-uppercase-unknown-weaker-ignored", markup: script("payload", "/asset/uppercase-ignored", strings.Replace(invalidWeaker, "sha256-", "SHA256-", 1)+" "+d512, ""), headers: header(policy(quote(d512))), count: 1},
		{name: "unpadded-integrity-padded-csp", markup: script("payload", "/asset/unpadded-mixed", d256Unpadded, ""), headers: header(policy(quote(d256))), count: 1},
		{name: "both-unpadded-allow", markup: script("payload", "/asset/both-unpadded", d256Unpadded, ""), headers: header(policy(quote(d256Unpadded))), count: 1},
		{name: "urlsafe-integrity-standard-csp", markup: script("payload", "/asset/urlsafe-mixed", d256URLSafe, ""), headers: header(policy(quote(d256))), count: 1},
		{name: "transformed-hash-deny", markup: script("payload", "/asset/transformed-deny", d256, ""), headers: header(policy(quote(externalControlDigest(transformed, "sha256")))), violations: denied, errors: []string{"payload"}},
		{name: "multiple-integrity-allow", markup: script("payload", "/asset/multiple-allow", d256+" "+d512, ""), headers: header(policy(quote(d256) + " " + quote(d512))), count: 1},
		{name: "invalid-weaker-valid-stronger-allow", markup: script("payload", "/asset/invalid-weaker-allow", invalidWeaker+" "+d512, ""), headers: header(policy(quote(invalidWeaker) + " " + quote(d512))), count: 1},
		{name: "invalid-weaker-missing-report-only", markup: script("payload", "/asset/invalid-weaker-report", invalidWeaker+" "+d512, ""), headers: http.Header{"Content-Security-Policy-Report-Only": {policy(quote(d512))}}, count: 1, violations: []controlViolation{{Directive: "script-src-elem", Disposition: "report"}}},
		{name: "missing-weaker-csp-deny", markup: script("payload", "/asset/missing-weaker", d256+" "+d512, ""), headers: header(policy(quote(d512))), violations: denied, errors: []string{"payload"}},
		{name: "host-alternative-allow", markup: script("payload", "/asset/host-alternative", d256, ""), headers: header(policy("'self' " + quote(externalControlDigest(transformed, "sha256")))), count: 1},
		{name: "nonce-alternative-allow", markup: script("payload", "/asset/nonce-alternative", d256, "AcmeCorp"), headers: header(policy("'nonce-AcmeCorp'")), count: 1},
		{name: "policy-intersection-deny", markup: script("payload", "/asset/intersection", d256, ""), headers: http.Header{"Content-Security-Policy": {policy(quote(d256)), policy("")}}, violations: denied, errors: []string{"payload"}},
		{name: "report-only-allow", markup: script("payload", "/asset/report-only", d256, ""), headers: http.Header{"Content-Security-Policy-Report-Only": {policy(quote(externalControlDigest(transformed, "sha256")))}}, count: 1, violations: []controlViolation{{Directive: "script-src-elem", Disposition: "report"}}},
		{name: "report-only-unpadded-mixed", markup: script("payload", "/asset/report-unpadded-mixed", d256Unpadded, ""), headers: http.Header{"Content-Security-Policy-Report-Only": {policy(quote(d256))}}, count: 1},
		{name: "report-only-extra-padding", markup: script("payload", "/asset/report-extra-padding", d256, ""), headers: http.Header{"Content-Security-Policy-Report-Only": {policy(quote(d256 + "="))}}, count: 1, violations: []controlViolation{{Directive: "script-src-elem", Disposition: "report"}}},
		{name: "meta-before-allow", markup: `<meta http-equiv="Content-Security-Policy" content="` + html.EscapeString(policy(quote(d256))) + `">` + script("payload", "/asset/meta-before", d256, ""), count: 1},
		{name: "meta-after-position", markup: script("before", "/asset/meta-early", d256, "") + `<meta http-equiv="Content-Security-Policy" content="` + html.EscapeString(policy("")) + `">` + script("after", "/asset/meta-late", d256, ""), count: 1, violations: denied, errors: []string{"after"}},
		{name: "collision-external-before-inline", markup: script("external-payload", "/asset/collision-external-first", hash(extFirst), "") + inline(extFirstInline), headers: header(policy(quote(hash(extFirst)))), count: 1, violations: denied},
		{name: "collision-inline-before-external", markup: inline(inlineFirst) + script("external-payload", "/asset/collision-inline-first", hash(inlineFirstExternal), ""), headers: header(policy(quote(hash(inlineFirstExternal)))), count: 1, violations: denied},
		{name: "collision-external-pair-report-only", markup: script("first", "/asset/collision-pair-a", hash(pairA), "") + script("second", "/asset/collision-pair-b", hash(pairB), ""), headers: http.Header{"Content-Security-Policy-Report-Only": {policy(quote(hash(pairA)))}}, count: 2, violations: reported},
		{name: "collision-no-store-refetch-report-only", markup: script("first", "/asset/collision-no-store-a", hash(noStoreA), "") + script("second", "/asset/collision-no-store-b", hash(noStoreB), ""), headers: http.Header{"Content-Security-Policy-Report-Only": {policy(quote(hash(noStoreA)))}}, count: 2, violations: reported},
		{name: "collision-invalid-weak-inline-deny", markup: script("external-payload", "/asset/collision-invalid-weak-inline", weakMetadata, "") + inline(weakInline), headers: header(policy(quote(hash(weakRewritten)) + " " + quote(externalControlDigest(weakExternal, "sha512")))), count: 1, violations: denied},
		{name: "collision-denied-reference-stays-denied", markup: script("neutral", "/asset/collision-denied-neutral", hash(deniedNeutral), "") + script("sensitive", "/asset/collision-authorized-sensitive", hash(deniedSensitive), ""), headers: header(policy(quote(hash(deniedSensitive)))), count: 1, violations: denied, errors: []string{"neutral"}},
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
			fmt.Fprintf(w, `<!doctype html><title>External CSP and SRI comparison</title><h1>External CSP and SRI comparison</h1><p>Local direct baseline, then Blinder. Cases run sequentially to verify cache algorithm order.</p><pre id="result">Running...</pre><script>
const names=%s,phase=%s,nextURL=%s,reports={},frames={};let index=0,finished=false;
async function finish(){if(finished)return;finished=true;const report={phase,cases:reports};document.getElementById('result').textContent=JSON.stringify(report,null,2);const response=await fetch('/__review_report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(report)});if(!response.ok)throw new Error('report rejected');if(nextURL)location.href=nextURL;else document.getElementById('result').prepend('Completed direct and Blinder external-control comparison.\n')}
function next(){if(index===names.length){finish();return}const name=names[index++],frame=document.createElement('iframe');frames[name]=frame;frame.title=name;frame.src='/case/'+name;document.body.appendChild(frame)}
addEventListener('message',e=>{const data=e.data;if(e.origin!==location.origin||!data||data.fixture!=='external-control-fidelity'||!names.includes(data.name)||!frames[data.name]||e.source!==frames[data.name].contentWindow||reports[data.name])return;reports[data.name]={name:data.name,count:data.count,violations:data.violations,resourceErrors:data.resourceErrors};next()});next();setTimeout(finish,30000);
</script>`, namesJSON, phaseJSON, nextJSON)
		})
		mux.HandleFunc("/__review_report", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "POST required", http.StatusMethodNotAllowed)
				return
			}
			var report externalControlReport
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

func TestExternalControlFidelityBrowser(t *testing.T) {
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
	f := newExternalControlFixture(t, cert)
	if err := os.WriteFile("/private/tmp/blinder-external-csp-browser-url.txt", []byte(f.baseline.URL+"/__review"), 0600); err != nil {
		t.Fatal(err)
	}
	reports := make(map[string]externalControlReport)
	timer := time.NewTimer(180 * time.Second)
	defer timer.Stop()
wait:
	for len(reports) < 2 {
		select {
		case report := <-f.reports:
			reports[report.Phase] = report
		case <-timer.C:
			t.Error("browser did not complete both external CSP stages within 180 seconds")
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
				if report.Count != tc.count || !sameControlViolations(report.Violations, tc.violations) || strings.Join(report.ResourceErrors, ",") != strings.Join(tc.errors, ",") {
					t.Errorf("browser result=%+v; want count=%d violations=%+v resourceErrors=%v", report, tc.count, tc.violations, tc.errors)
				}
				if phase == "proxy" {
					direct := reports["direct"].Cases[tc.name]
					if report.Count != direct.Count || !sameControlViolations(report.Violations, direct.Violations) || strings.Join(report.ResourceErrors, ",") != strings.Join(direct.ResourceErrors, ",") {
						t.Errorf("proxy diverged from direct browser: proxy=%+v direct=%+v", report, direct)
					}
				}
			})
		}
	}
	counts := f.requestCounts()
	for _, names := range [][2]string{{"original-sha256-allow", "cached-sha512-after-sha256"}, {"original-sha512-allow", "cached-sha256-after-sha512"}} {
		if reports["direct"].Cases[names[0]].Count+reports["direct"].Cases[names[1]].Count != 2 {
			t.Errorf("direct baseline did not execute both algorithm references: %v", names)
		}
	}
	// Browser HTTP cache reuse is not the proxy contract. Chrome may perform a
	// second request when the integrity metadata changes; preserve the observed
	// direct counts as evidence, and require our representation cache to reuse.
	for _, path := range []string{"/asset/order-256-512", "/asset/order-512-256"} {
		if got := counts["proxyUpstream"][path]; got != 1 {
			t.Errorf("proxyUpstream fetched %s %d times; expected one cached representation across algorithm references", path, got)
		}
	}
	for _, path := range []string{"/asset/transformed-deny", "/asset/missing-weaker", "/asset/intersection", "/asset/meta-late", "/asset/collision-denied-neutral", "/asset/nomodule-ignored"} {
		for _, phase := range []string{"direct", "proxyUpstream"} {
			if counts[phase][path] != 0 {
				t.Errorf("%s fetched CSP-blocked resource %s: %d", phase, path, counts[phase][path])
			}
		}
	}
	evidence := map[string]any{"directURL": f.baseline.URL, "proxyURL": f.proxy.URL, "reports": reports, "upstreamResourceCounts": counts, "passed": !t.Failed()}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/private/tmp/blinder-external-csp-browser-result.json", data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
}

type externalControlReference struct{ id, src, integrity string }

func externalControlReferences(body []byte) ([]externalControlReference, []string) {
	var references []externalControlReference
	var policies []string
	z := xhtml.NewTokenizer(strings.NewReader(string(body)))
	for token := z.Next(); token != xhtml.ErrorToken; token = z.Next() {
		if token != xhtml.StartTagToken && token != xhtml.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		attrs := make(map[string]string)
		for _, attr := range tok.Attr {
			if _, exists := attrs[attr.Key]; !exists {
				attrs[attr.Key] = attr.Val
			}
		}
		if tok.Data == "script" && attrs["src"] != "" {
			references = append(references, externalControlReference{attrs["id"], attrs["src"], attrs["integrity"]})
		}
		if tok.Data == "meta" && strings.EqualFold(attrs["http-equiv"], "content-security-policy") {
			policies = append(policies, attrs["content"])
		}
	}
	return references, policies
}

func TestExternalControlFidelityWire(t *testing.T) {
	f := newExternalControlFixture(t, tls.Certificate{})
	for _, tc := range []struct {
		name       string
		algorithms []string
		policies   int
		allowed    bool
	}{
		{"original-sha256-allow", []string{"sha256"}, 1, true},
		{"cached-sha512-after-sha256", []string{"sha512"}, 1, true},
		{"original-sha512-allow", []string{"sha512"}, 1, true},
		{"cached-sha256-after-sha512", []string{"sha256"}, 1, true},
		{"multiple-integrity-allow", []string{"sha256", "sha512"}, 1, true},
		{"missing-weaker-csp-deny", []string{"sha256", "sha512"}, 1, false},
		{"transformed-hash-deny", []string{"sha256"}, 1, false},
		{"policy-intersection-deny", []string{"sha256"}, 2, false},
		{"meta-before-allow", []string{"sha256"}, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := f.proxy.Client().Get(f.proxy.URL + "/case/" + tc.name)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			refs, policies := externalControlReferences(body)
			policies = append(resp.Header.Values("Content-Security-Policy"), policies...)
			if len(refs) != 1 || len(policies) != tc.policies {
				t.Fatalf("references=%+v policies=%v", refs, policies)
			}
			resourceURL, err := url.Parse(refs[0].src)
			if err != nil {
				t.Fatal(err)
			}
			integrity := strings.Fields(refs[0].integrity)
			if len(integrity) != len(tc.algorithms) {
				t.Errorf("integrity metadata lost algorithms: %v want %v", integrity, tc.algorithms)
			}
			resource := []byte(externalControlPayload)
			if tc.allowed {
				baseURL, _ := url.Parse(f.proxy.URL)
				resp, err = f.proxy.Client().Get(baseURL.ResolveReference(resourceURL).String())
				if err != nil {
					t.Fatal(err)
				}
				resource, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != http.StatusOK || strings.Contains(string(resource), "AcmeCorp") {
					t.Fatalf("resource was not served masked: status=%d body=%s", resp.StatusCode, resource)
				}
			} else if calls := f.requestCounts()["proxyUpstream"][resourceURL.Path]; calls != 0 {
				t.Errorf("proxy prefetched a resource that CSP should block before loading: path=%q count=%d", resourceURL.Path, calls)
			}
			for _, algorithm := range tc.algorithms {
				wanted := externalControlDigest(string(resource), algorithm)
				if !strings.Contains(" "+refs[0].integrity+" ", " "+wanted+" ") {
					t.Errorf("integrity metadata is inconsistent (allowed=%v): %q want %q", tc.allowed, refs[0].integrity, wanted)
				}
			}
			allPoliciesAllow := true
			for _, policy := range policies {
				for _, entry := range integrity {
					if !strings.Contains(policy, "'"+entry+"'") {
						allPoliciesAllow = false
					}
				}
			}
			if allPoliciesAllow != tc.allowed {
				t.Errorf("CSP/SRI hash permission changed: allPoliciesAllow=%v want=%v policies=%v integrity=%v", allPoliciesAllow, tc.allowed, policies, integrity)
			}
		})
	}
	counts := f.requestCounts()["proxyUpstream"]
	for _, path := range []string{"/asset/order-256-512", "/asset/order-512-256"} {
		if counts[path] != 1 {
			t.Errorf("SRI cache did not share the representation across reference algorithms: %s fetched %d times", path, counts[path])
		}
	}
}
