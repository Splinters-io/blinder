package proxy

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/har"
)

func sha256b64(data []byte) string {
	h := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(h[:])
}

func sha384b64p(data []byte) string {
	h := sha512.Sum384(data)
	return base64.StdEncoding.EncodeToString(h[:])
}

func sha512b64(data []byte) string {
	h := sha512.Sum512(data)
	return base64.StdEncoding.EncodeToString(h[:])
}

func TestProxy_SRICacheServesScrubbedResource(t *testing.T) {
	jsBody := []byte(`var company = "AcmeCorp"; alert(company);`)
	integrity := "sha384-" + sha384b64p(jsBody)

	resourceFetches := 0
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/data" integrity="%s" crossorigin="anonymous"></script></html>`, integrity)
		case "/data":
			resourceFetches++
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(jsBody)
		}
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	client := testClient()

	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTML request: %v", err)
	}
	htmlBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	htmlStr := string(htmlBody)

	if strings.Contains(htmlStr, integrity) {
		t.Error("original integrity should be replaced (content was scrubbed)")
	}
	if !strings.Contains(htmlStr, `integrity="sha384-`) {
		t.Errorf("replacement integrity should be present, got: %s", htmlStr)
	}
	if !strings.Contains(htmlStr, `crossorigin="anonymous"`) {
		t.Error("crossorigin should be preserved")
	}

	if resourceFetches != 1 {
		t.Errorf("pipeline should fetch resource once during HTML rewrite, got %d", resourceFetches)
	}

	resp2, err := client.Get("https://" + addr + "/data")
	if err != nil {
		t.Fatalf("resource request: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("cached resource should return 200, got %d", resp2.StatusCode)
	}
	if strings.Contains(string(body), "AcmeCorp") {
		t.Error("cached resource should have identity scrubbed")
	}
	if resourceFetches != 1 {
		t.Errorf("resource should be served from cache (no second upstream fetch), got %d fetches", resourceFetches)
	}
}

func TestProxy_SRIInvalidOriginalBlocked(t *testing.T) {
	jsBody := []byte(`alert("hello");`)
	wrongIntegrity := "sha384-" + sha384b64p([]byte("attacker controlled content here"))

	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/data" integrity="%s"></script></html>`, wrongIntegrity)
		case "/data":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(jsBody)
		}
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTML request: %v", err)
	}
	htmlBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	htmlStr := string(htmlBody)

	if strings.Contains(htmlStr, `<script`) {
		t.Errorf("entire script element must be omitted for failed verification, got: %s", htmlStr)
	}

	resp2, err := client.Get("https://" + addr + "/data")
	if err != nil {
		t.Fatalf("resource request: %v", err)
	}
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("cached resource should still return 200 via cache, got %d", resp2.StatusCode)
	}
}

func TestProxy_SRISessionIsolation(t *testing.T) {
	jsBody := []byte(`var x = "AcmeCorp";`)
	integrity := "sha384-" + sha384b64p(jsBody)

	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/data" integrity="%s"></script></html>`, integrity)
		case "/data":
			w.Header().Set("Content-Type", "application/javascript")
			if r.Header.Get("Cookie") != "" {
				w.Write([]byte(`var x = "AcmeCorp"; var role = "admin";`))
			} else {
				w.Write(jsBody)
			}
		}
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	// User A: authenticated
	clientA := testClient()
	reqA, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	reqA.Header.Set("Cookie", "session=user-a")
	respA, err := clientA.Do(reqA)
	if err != nil {
		t.Fatalf("user A request: %v", err)
	}
	respA.Body.Close()

	// User B: unauthenticated
	clientB := testClient()
	respB, err := clientB.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("user B request: %v", err)
	}
	respB.Body.Close()

	// User B requests the resource -- should NOT get user A's cached content
	respResource, err := clientB.Get("https://" + addr + "/data")
	if err != nil {
		t.Fatalf("user B resource request: %v", err)
	}
	body, _ := io.ReadAll(respResource.Body)
	respResource.Body.Close()

	if strings.Contains(string(body), "admin") {
		t.Error("unauthenticated user should not receive authenticated user's cached resource")
	}
}

func TestProxy_SRIFindingsRecorded(t *testing.T) {
	jsBody := []byte(`var org = "AcmeCorp";`)
	integrity := "sha384-" + sha384b64p(jsBody)

	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/data" integrity="%s"></script></html>`, integrity)
		case "/data":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(jsBody)
		}
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	srv, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	findings := srv.SRIFindings()
	if len(findings) != 1 {
		t.Fatalf("expected 1 SRI finding, got %d", len(findings))
	}
	if !findings[0].UpstreamValid {
		t.Error("finding should show upstream valid")
	}
	if findings[0].OriginalIntegrity != integrity {
		t.Errorf("finding original integrity = %q, want %q", findings[0].OriginalIntegrity, integrity)
	}
	if findings[0].ReplacementHash == "" {
		t.Error("finding should have replacement hash")
	}
}

func TestProxy_SRICacheGETOnly(t *testing.T) {
	jsBody := []byte(`var x = "AcmeCorp";`)
	integrity := "sha384-" + sha384b64p(jsBody)

	postReceived := false
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/data" integrity="%s"></script></html>`, integrity)
		case "/data":
			if r.Method == http.MethodPost {
				postReceived = true
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"status":"created"}`))
				return
			}
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(jsBody)
		}
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	// Populate the SRI cache via HTML fetch
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTML request: %v", err)
	}
	resp.Body.Close()

	// POST to the same URL should NOT be served from cache
	resp2, err := client.Post("https://"+addr+"/data", "application/json", strings.NewReader(`{"key":"val"}`))
	if err != nil {
		t.Fatalf("POST request: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if !postReceived {
		t.Error("POST should reach upstream, not be swallowed by SRI cache")
	}
	if !strings.Contains(string(body), "created") {
		t.Error("POST response should come from upstream, not SRI cache")
	}
}

func TestProxy_SRICachePreservesHeaders(t *testing.T) {
	jsBody := []byte(`var company = "AcmeCorp";`)
	integrity := "sha384-" + sha384b64p(jsBody)

	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/data" integrity="%s" crossorigin="anonymous"></script></html>`, integrity)
		case "/data":
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
			w.Write(jsBody)
		}
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	// Populate cache
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTML request: %v", err)
	}
	resp.Body.Close()

	// Fetch resource from cache: should preserve upstream headers
	resp2, err := client.Get("https://" + addr + "/data")
	if err != nil {
		t.Fatalf("resource request: %v", err)
	}
	resp2.Body.Close()

	if resp2.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("cached response should preserve X-Content-Type-Options")
	}
}

func TestProxy_SRIProtocolRelativeNotFetched(t *testing.T) {
	fetchedHosts := make(map[string]bool)
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		fetchedHosts[r.Host] = true
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><script src="//unconfigured.invalid:8443/asset" integrity="sha384-xxx" crossorigin="anonymous"></script></html>`)
		default:
			w.Write([]byte(`var x = 1;`))
		}
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTML request: %v", err)
	}
	resp.Body.Close()

	if fetchedHosts["unconfigured.invalid:8443"] {
		t.Error("protocol-relative URL to unconfigured host should not trigger a fetch")
	}
}

func TestProxy_SRIDocumentRelativeResolution(t *testing.T) {
	jsBody := []byte(`var x = "AcmeCorp";`)
	integrity := "sha384-" + sha384b64p(jsBody)

	var fetchedPaths []string
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nested/page":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="asset" integrity="%s"></script></html>`, integrity)
		default:
			fetchedPaths = append(fetchedPaths, r.URL.Path)
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(jsBody)
		}
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/nested/page")
	if err != nil {
		t.Fatalf("HTML request: %v", err)
	}
	resp.Body.Close()

	found := false
	for _, p := range fetchedPaths {
		if p == "/nested/asset" {
			found = true
		}
		if p == "/asset" {
			t.Error("relative URL 'asset' at /nested/page should resolve to /nested/asset, not /asset")
		}
	}
	if !found {
		t.Errorf("expected fetch of /nested/asset, got paths: %v", fetchedPaths)
	}
}

func TestProxy_SRICrossoriginPreservedWithoutIntegrity(t *testing.T) {
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><script src="/bundle.js" crossorigin="anonymous"></script></html>`)
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTML request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if !strings.Contains(string(body), `crossorigin="anonymous"`) {
		t.Error("crossorigin should be preserved when no integrity attribute is present")
	}
}

// Defect 1: Failed upstream verification must not become valid after scrubbing.
// Page declares integrity matching the SCRUBBED bytes. Original verification fails
// because upstream bytes differ. The src must be stripped so the browser never loads
// the resource -- independent of what hash is emitted.
func TestProxy_SRIFailedBecomesValidBlocked(t *testing.T) {
	originalJS := []byte(`var company = "AcmeCorp"; alert(1);`)
	originalHash := "sha384-" + sha384b64p(originalJS)

	// Step 1: Get the scrubbed hash via a valid pipeline run.
	correctTarget := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/asset.js" integrity="%s"></script></html>`, originalHash)
		case "/asset.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(originalJS)
		}
	})
	defer correctTarget.Close()

	cfg1 := newTestConfig(t, correctTarget.URL)
	_, addr1 := startTestProxy(t, cfg1)

	resp1, _ := testClient().Get("https://" + addr1 + "/")
	htmlBody1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()

	htmlStr1 := string(htmlBody1)
	idx := strings.Index(htmlStr1, `integrity="`)
	if idx < 0 {
		t.Fatal("expected integrity in valid-case response")
	}
	afterIntegrity := htmlStr1[idx+len(`integrity="`):]
	endQuote := strings.IndexByte(afterIntegrity, '"')
	scrubbedHash := afterIntegrity[:endQuote]

	// Step 2: Attack scenario -- page uses the scrubbed hash as integrity.
	// Upstream serves original bytes. Verification fails. src must be stripped.
	attackTarget := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/asset.js" integrity="%s"></script></html>`, scrubbedHash)
		case "/asset.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(originalJS)
		}
	})
	defer attackTarget.Close()

	cfg2 := newTestConfig(t, attackTarget.URL)
	_, addr2 := startTestProxy(t, cfg2)

	resp2, _ := testClient().Get("https://" + addr2 + "/")
	htmlBody2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	htmlStr2 := string(htmlBody2)

	if strings.Contains(htmlStr2, `<script`) {
		t.Fatalf("entire script element must be omitted for failed verification, got: %s", htmlStr2)
	}
}

// Sentinel-body: serving the exact bytes that a fixed poison hash would match
// must still be blocked by src-stripping rather than relying on hash mismatch.
func TestProxy_SRISentinelBodyBlocked(t *testing.T) {
	sentinelBody := []byte("blinder:poison:verification-failed")
	wrongIntegrity := "sha384-" + sha384b64p([]byte("not the sentinel"))

	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/sentinel.js" integrity="%s"></script></html>`, wrongIntegrity)
		case "/sentinel.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(sentinelBody)
		}
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTML request: %v", err)
	}
	htmlBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	htmlStr := string(htmlBody)

	if strings.Contains(htmlStr, `<script`) {
		t.Errorf("entire script element must be omitted for sentinel body, got: %s", htmlStr)
	}
}

// All three SRI algorithms must block via src-stripping on verification failure.
func TestProxy_SRIBlockAllAlgorithms(t *testing.T) {
	jsBody := []byte(`var x = 1;`)
	wrongHash256 := "sha256-" + sha256b64([]byte("wrong"))
	wrongHash384 := "sha384-" + sha384b64p([]byte("wrong"))
	wrongHash512 := "sha512-" + sha512b64([]byte("wrong"))

	for _, tc := range []struct {
		name      string
		integrity string
	}{
		{"sha256", wrongHash256},
		{"sha384", wrongHash384},
		{"sha512", wrongHash512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/":
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprintf(w, `<html><script src="/lib.js" integrity="%s"></script></html>`, tc.integrity)
				case "/lib.js":
					w.Header().Set("Content-Type", "application/javascript")
					w.Write(jsBody)
				}
			})
			defer target.Close()

			cfg := newTestConfig(t, target.URL)
			_, addr := startTestProxy(t, cfg)

			resp, err := testClient().Get("https://" + addr + "/")
			if err != nil {
				t.Fatalf("HTML request: %v", err)
			}
			htmlBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			htmlStr := string(htmlBody)

			if strings.Contains(htmlStr, `<script`) {
				t.Errorf("%s: entire script element must be omitted, got: %s", tc.name, htmlStr)
			}
		})
	}
}

// Removing src from a script with a nonempty body turns it into an executable
// inline script. The entire element must be omitted. Classic script variant.
func TestProxy_SRIBlockOmitsClassicScriptBody(t *testing.T) {
	jsBody := []byte(`console.log("external");`)
	wrongIntegrity := "sha384-" + sha384b64p([]byte("wrong"))

	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/ext.js" integrity="%s">document.title="EXECUTED";</script><p>preserved</p></html>`, wrongIntegrity)
		case "/ext.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(jsBody)
		}
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTML request: %v", err)
	}
	htmlBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	htmlStr := string(htmlBody)

	if strings.Contains(htmlStr, `<script`) {
		t.Errorf("entire script element (including body) must be omitted, got: %s", htmlStr)
	}
	if strings.Contains(htmlStr, "EXECUTED") {
		t.Errorf("inline body must not appear in output, got: %s", htmlStr)
	}
	if !strings.Contains(htmlStr, "<p") {
		t.Errorf("following markup must be preserved, got: %s", htmlStr)
	}
	if !strings.Contains(htmlStr, "preserved") {
		t.Errorf("following text must be preserved, got: %s", htmlStr)
	}
}

// Module script variant: type="module" scripts also execute inline body when src
// is removed, so the entire element must be omitted.
func TestProxy_SRIBlockOmitsModuleScriptBody(t *testing.T) {
	jsBody := []byte(`export default 1;`)
	wrongIntegrity := "sha384-" + sha384b64p([]byte("wrong"))

	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script type="module" src="/mod.js" integrity="%s">document.title="MODULE_EXEC";</script><p>safe</p></html>`, wrongIntegrity)
		case "/mod.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(jsBody)
		}
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTML request: %v", err)
	}
	htmlBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	htmlStr := string(htmlBody)

	if strings.Contains(htmlStr, `<script`) {
		t.Errorf("module script element must be omitted, got: %s", htmlStr)
	}
	if strings.Contains(htmlStr, "MODULE_EXEC") {
		t.Errorf("module inline body must not appear in output, got: %s", htmlStr)
	}
	if !strings.Contains(htmlStr, "<p") {
		t.Errorf("following markup must be preserved, got: %s", htmlStr)
	}
}

// In HTML, <script ... /> still opens a script element -- the slash does not
// make it void. Body suppression must fire regardless of the token type.
func TestProxy_SRIBlockSlashEndedClassicScript(t *testing.T) {
	jsBody := []byte(`var y = 1;`)
	wrongIntegrity := "sha384-" + sha384b64p([]byte("wrong"))

	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/ext.js" integrity="%s" />document.title="SLASH_EXEC";</script><p>after</p></html>`, wrongIntegrity)
		case "/ext.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(jsBody)
		}
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTML request: %v", err)
	}
	htmlBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	htmlStr := string(htmlBody)

	if strings.Contains(htmlStr, `<script`) {
		t.Errorf("slash-ended script element must be fully omitted, got: %s", htmlStr)
	}
	if strings.Contains(htmlStr, "SLASH_EXEC") {
		t.Errorf("inline body must not survive slash-ended script, got: %s", htmlStr)
	}
	if !strings.Contains(htmlStr, "<p") {
		t.Errorf("following markup must be preserved, got: %s", htmlStr)
	}
}

func TestProxy_SRIBlockSlashEndedModuleScript(t *testing.T) {
	jsBody := []byte(`export const z = 1;`)
	wrongIntegrity := "sha384-" + sha384b64p([]byte("wrong"))

	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script type="module" src="/mod.js" integrity="%s" />document.title="MOD_SLASH";</script><p>safe</p></html>`, wrongIntegrity)
		case "/mod.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(jsBody)
		}
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTML request: %v", err)
	}
	htmlBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	htmlStr := string(htmlBody)

	if strings.Contains(htmlStr, `<script`) {
		t.Errorf("slash-ended module script must be fully omitted, got: %s", htmlStr)
	}
	if strings.Contains(htmlStr, "MOD_SLASH") {
		t.Errorf("module inline body must not survive, got: %s", htmlStr)
	}
	if !strings.Contains(htmlStr, "<p") {
		t.Errorf("following markup must be preserved, got: %s", htmlStr)
	}
}

// Defect 2: Origin restrictions must enforce scheme and port.
func TestProxy_SRIOriginSchemePortEnforced(t *testing.T) {
	jsBody := []byte(`var x = 1;`)
	integrity := "sha384-" + sha384b64p(jsBody)

	fetchedPaths := make(map[string]bool)
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		fetchedPaths[r.URL.Path] = true
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			// Reference resource with HTTP scheme (wrong -- target is HTTPS)
			// and with a different port. Both should be rejected.
			fmt.Fprintf(w, `<html>`+
				`<script src="http://127.0.0.1:9999/wrong-scheme.js" integrity="%s"></script>`+
				`<script src="https://127.0.0.1:9999/wrong-port.js" integrity="%s"></script>`+
				`</html>`, integrity, integrity)
		default:
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(jsBody)
		}
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTML request: %v", err)
	}
	htmlBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	htmlStr := string(htmlBody)

	// Neither wrong-scheme nor wrong-port resources should be fetched by the pipeline
	if fetchedPaths["/wrong-scheme.js"] {
		t.Error("resource with wrong scheme should not be fetched")
	}
	if fetchedPaths["/wrong-port.js"] {
		t.Error("resource with wrong port should not be fetched")
	}

	// Original integrity should be preserved (not proxied, so no pipeline processing)
	if !strings.Contains(htmlStr, integrity) {
		t.Errorf("integrity for non-proxied resources should be preserved, got: %s", htmlStr)
	}
}

// Defect 3: Prefetch must restore aliased cookie names before sending upstream.
func TestProxy_SRIPrefetchCookieRestoration(t *testing.T) {
	jsBody := []byte(`var secret = "AcmeCorp";`)
	integrity := "sha384-" + sha384b64p(jsBody)

	var prefetchCookieHeader string
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			// Set a cookie that the proxy will alias
			w.Header().Set("Set-Cookie", "sid=session123; Path=/")
			fmt.Fprintf(w, `<html><script src="/data.js" integrity="%s"></script></html>`, integrity)
		case "/data.js":
			prefetchCookieHeader = r.Header.Get("Cookie")
			w.Header().Set("Content-Type", "application/javascript")
			w.Write(jsBody)
		}
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)
	client := testClient()

	// First request to get the Set-Cookie (which aliases the name)
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("page request: %v", err)
	}
	resp.Body.Close()

	// Second request with the aliased cookie -- the pipeline should de-alias
	// before sending upstream. Since this is same-origin, creds are sent.
	setCookie := resp.Header.Get("Set-Cookie")
	if setCookie == "" {
		t.Skip("no Set-Cookie header in response")
	}
	// Extract cookie name=value from Set-Cookie
	cookiePart := strings.Split(setCookie, ";")[0]
	req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	req.Header.Set("Cookie", cookiePart)
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	resp2.Body.Close()

	// The prefetch cookie header should contain the ORIGINAL cookie name "sid",
	// not the aliased "ck_<hash>" name.
	if prefetchCookieHeader != "" && strings.Contains(prefetchCookieHeader, "ck_") {
		t.Errorf("prefetch sent aliased cookie name upstream: %s", prefetchCookieHeader)
	}
	if prefetchCookieHeader != "" && !strings.Contains(prefetchCookieHeader, "sid=") {
		t.Errorf("prefetch should send restored cookie name 'sid', got: %s", prefetchCookieHeader)
	}
}

// Defect 4: Failed prefetches must appear in HAR with full evidence.

func readHAREntries(t *testing.T, harPath string) []har.Entry {
	t.Helper()
	data, err := os.ReadFile(harPath)
	if err != nil {
		t.Fatalf("read HAR: %v", err)
	}
	var h har.HARFile
	if err := json.Unmarshal(data, &h); err != nil {
		t.Fatalf("parse HAR: %v", err)
	}
	return h.Log.Entries
}

func findHAREntry(entries []har.Entry, pathSubstring string) *har.Entry {
	for i := range entries {
		if strings.Contains(entries[i].Request.URL, pathSubstring) {
			return &entries[i]
		}
	}
	return nil
}

// 503 response: headers and body must be preserved, not replaced with error text.
func TestProxy_HAR503PreservesEvidence(t *testing.T) {
	jsBody := []byte(`var x = "AcmeCorp";`)
	integrity := "sha384-" + sha384b64p(jsBody)

	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/fail503" integrity="%s"></script></html>`, integrity)
		case "/fail503":
			w.Header().Set("X-Debug-Info", "backend-pool-3")
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("service temporarily unavailable"))
		}
	})
	defer target.Close()

	tmpDir := t.TempDir()
	harPath := tmpDir + "/test.har"
	cfg := newTestConfig(t, target.URL)
	cfg.HAR = &config.HARConfig{FilePath: harPath, MaxBodySize: 1024 * 1024}

	srv, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("page request: %v", err)
	}
	resp.Body.Close()

	if err := srv.FlushHAR(); err != nil {
		t.Fatalf("flush HAR: %v", err)
	}

	entries := readHAREntries(t, harPath)
	entry := findHAREntry(entries, "/fail503")
	if entry == nil {
		t.Fatal("HAR must contain the /fail503 fetch")
	}

	if entry.Response.Status != 503 {
		t.Errorf("HAR status should be 503, got %d", entry.Response.Status)
	}
	if entry.Response.Content.Comment == "" {
		t.Error("HAR comment should contain the error text")
	}
	if !strings.Contains(entry.Response.Content.Comment, "503") {
		t.Errorf("HAR comment should mention 503, got: %s", entry.Response.Content.Comment)
	}
}

// Truncated 200: partial body bytes preserved, error in comment, not as body content.
func TestProxy_HARTruncatedBodyPreservesBytes(t *testing.T) {
	partialBody := []byte("partial javascript cont")
	integrity := "sha384-" + sha384b64p([]byte("wrong hash"))

	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/truncated" integrity="%s"></script></html>`, integrity)
		case "/truncated":
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Set("Content-Length", "10000")
			w.WriteHeader(http.StatusOK)
			w.Write(partialBody)
			// Connection closes before Content-Length is satisfied,
			// producing a read error with partial body.
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				if conn != nil {
					conn.Close()
				}
			}
		}
	})
	defer target.Close()

	tmpDir := t.TempDir()
	harPath := tmpDir + "/test.har"
	cfg := newTestConfig(t, target.URL)
	cfg.HAR = &config.HARConfig{FilePath: harPath, MaxBodySize: 1024 * 1024}

	srv, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("page request: %v", err)
	}
	resp.Body.Close()

	if err := srv.FlushHAR(); err != nil {
		t.Fatalf("flush HAR: %v", err)
	}

	entries := readHAREntries(t, harPath)
	entry := findHAREntry(entries, "/truncated")
	if entry == nil {
		t.Fatal("HAR must contain the /truncated fetch")
	}

	if entry.Response.Content.Comment == "" {
		t.Error("HAR comment should describe the read error")
	}
	if strings.Contains(entry.Response.Content.Comment, "read body:") && entry.Response.Content.Text == entry.Response.Content.Comment {
		t.Error("HAR body should contain partial bytes, not the error message as body")
	}
}

// Transport disconnect: status 0, error in statusText, not an invented 502.
func TestProxy_HARTransportErrorNotFake502(t *testing.T) {
	jsBody := []byte(`var z = 1;`)
	integrity := "sha384-" + sha384b64p(jsBody)

	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><script src="/disconnect" integrity="%s"></script></html>`, integrity)
		case "/disconnect":
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				if conn != nil {
					conn.Close()
				}
			}
		}
	})
	defer target.Close()

	tmpDir := t.TempDir()
	harPath := tmpDir + "/test.har"
	cfg := newTestConfig(t, target.URL)
	cfg.HAR = &config.HARConfig{FilePath: harPath, MaxBodySize: 1024 * 1024}

	srv, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("page request: %v", err)
	}
	resp.Body.Close()

	if err := srv.FlushHAR(); err != nil {
		t.Fatalf("flush HAR: %v", err)
	}

	entries := readHAREntries(t, harPath)
	entry := findHAREntry(entries, "/disconnect")
	if entry == nil {
		t.Fatal("HAR must contain the /disconnect fetch")
	}

	if entry.Response.Status == 502 {
		t.Error("transport error must NOT be recorded as 502 (that's an invented status)")
	}
	if entry.Response.Status != 0 {
		t.Errorf("transport error should have status 0, got %d", entry.Response.Status)
	}
	if entry.Response.Content.Comment == "" {
		t.Error("transport error should have error description in content comment")
	}
}
