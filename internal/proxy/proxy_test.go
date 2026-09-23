package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/config"
)

func startTestTarget(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewTLSServer(handler)
}

func newTestConfig(t *testing.T, targetURL string) *config.Config {
	t.Helper()
	cfg, err := config.New(
		targetURL,
		"127.0.0.1:0",
		"target-001.local",
		[]string{"AcmeCorp"},
		false,
		false,
		false,
		"", "", 0, "", "", 30, 30,
	)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func startTestProxy(t *testing.T, cfg *config.Config) (*Server, string) {
	t.Helper()
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("proxy new: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go srv.ListenAndServeOnListener(ln)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})

	time.Sleep(50 * time.Millisecond)
	return srv, ln.Addr().String()
}

func testClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestProxy_BasicHTMLScrubbing(t *testing.T) {
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "nginx/1.25")
		fmt.Fprint(w, `<html><head><title>AcmeCorp Portal</title></head><body><p>Welcome to acmecorp.io</p></body></html>`)
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if strings.Contains(bodyStr, "AcmeCorp") {
		t.Error("identity token 'AcmeCorp' should be scrubbed from body")
	}
	if strings.Contains(bodyStr, "acmecorp.io") {
		t.Error("domain 'acmecorp.io' should be scrubbed from body")
	}
	if !strings.Contains(bodyStr, "[Blinder: title removed]") {
		t.Error("title should be replaced")
	}
	if resp.Header.Get("Server") != "nginx/1.25" {
		t.Errorf("Server header should pass through, got: %s", resp.Header.Get("Server"))
	}
}

func TestProxy_JSONScrubbing(t *testing.T) {
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"company":"AcmeCorp","url":"https://megacorp.io/api","ip":"93.184.216.34"}`)
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/api")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if strings.Contains(bodyStr, "AcmeCorp") {
		t.Error("identity token should be scrubbed from JSON")
	}
	if strings.Contains(bodyStr, "megacorp.io") {
		t.Error("domain should be scrubbed from JSON")
	}
	if strings.Contains(bodyStr, "93.184.216.34") {
		t.Error("public IP should be replaced")
	}
	if !strings.Contains(bodyStr, "203.0.113.1") {
		t.Errorf("public IP should be replaced with TEST-NET-3, got: %s", bodyStr)
	}
}

func TestProxy_HeaderScrubbing(t *testing.T) {
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Location", "https://megacorp.io/new-location")
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("Server", "Apache/2.4")
		w.WriteHeader(302)
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/redirect")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	if strings.Contains(loc, "megacorp.io") {
		t.Errorf("Location header should be scrubbed, got: %s", loc)
	}
	if !strings.Contains(loc, "target-001.local") {
		t.Errorf("Location should contain alias domain, got: %s", loc)
	}

	if resp.Header.Get("X-Powered-By") != "Express" {
		t.Error("X-Powered-By should pass through")
	}
	if resp.Header.Get("Server") != "Apache/2.4" {
		t.Error("Server header should pass through")
	}
}

func TestProxy_ImageReplacement(t *testing.T) {
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		w.Write([]byte("fake jpeg data with AcmeCorp in it"))
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/logo.jpg")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(body), "AcmeCorp") {
		t.Error("image body should not contain identity token")
	}

	if len(body) < 3 || body[0] != 0x47 || body[1] != 0x49 || body[2] != 0x46 {
		t.Error("image should be replaced with transparent GIF (GIF89a header)")
	}
}

func TestProxy_RejectLargeContentLength(t *testing.T) {
	if maxRequestBody != 50*1024*1024 {
		t.Fatalf("expected maxRequestBody to be 50MB, got %d", maxRequestBody)
	}

	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	srv, _ := startTestProxy(t, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/upload", strings.NewReader("small body"))
	req.ContentLength = maxRequestBody + 1

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", rec.Code)
	}
}

func TestProxy_StatsTracking(t *testing.T) {
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "hello")
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	srv, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	requests, bytes, errors, scrubbed := srv.GetStats()
	if requests != 1 {
		t.Errorf("expected 1 request, got %d", requests)
	}
	if bytes != 5 {
		t.Errorf("expected 5 bytes, got %d", bytes)
	}
	if errors != 0 {
		t.Errorf("expected 0 errors, got %d", errors)
	}
	if scrubbed != 1 {
		t.Errorf("expected 1 scrubbed, got %d", scrubbed)
	}
}

func TestProxy_UpstreamError(t *testing.T) {
	cfg := newTestConfig(t, "https://127.0.0.1:1")
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "127.0.0.1:1") {
		t.Error("error response should not leak target address")
	}
}

func TestProxy_PreservesFormStructure(t *testing.T) {
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<form action="/login" method="post"><input type="text" name="username"><input type="password" name="password"><input type="hidden" name="csrf" value="tok123"></form>`)
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/login")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, `name="username"`) {
		t.Error("form field 'username' should be preserved")
	}
	if !strings.Contains(bodyStr, `name="password"`) {
		t.Error("form field 'password' should be preserved")
	}
	if !strings.Contains(bodyStr, `name="csrf"`) {
		t.Error("CSRF field should be preserved")
	}
	if !strings.Contains(bodyStr, `method="post"`) {
		t.Error("form method should be preserved")
	}
}

func TestProxy_MetadataHeader(t *testing.T) {
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		w.Write([]byte("%PDF-1.7\n/JavaScript (alert)\n%%EOF"))
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	_, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/doc.pdf")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	meta := resp.Header.Get("X-Blinder-Meta")
	if meta == "" {
		t.Fatal("expected X-Blinder-Meta header for PDF content")
	}
	if !strings.Contains(meta, `"pdf"`) {
		t.Errorf("expected format 'pdf' in metadata, got: %s", meta)
	}
	if !strings.Contains(meta, `"has_javascript":true`) {
		t.Errorf("expected has_javascript:true in metadata, got: %s", meta)
	}
}

func TestProxy_ManifestRecordsRequest(t *testing.T) {
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	srv, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/check")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	reqs := srv.Manifest().Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 manifest request, got %d", len(reqs))
	}
	if reqs[0].Path != "/check" {
		t.Errorf("expected path '/check', got %q", reqs[0].Path)
	}
}

func TestProxy_AliasTracking(t *testing.T) {
	target := startTestTarget(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>Visit megacorp.io today</body></html>`)
	})
	defer target.Close()

	cfg := newTestConfig(t, target.URL)
	srv, addr := startTestProxy(t, cfg)

	resp, err := testClient().Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	aliases := srv.Gate().Aliases()
	if len(aliases) == 0 {
		t.Error("expected at least one domain alias to be tracked")
	}

	foundMegacorp := false
	for _, real := range aliases {
		if real == "megacorp.io" {
			foundMegacorp = true
		}
	}
	if !foundMegacorp {
		t.Errorf("expected megacorp.io in alias map, got: %v", aliases)
	}
}

func TestExtractSubdomains(t *testing.T) {
	tests := []struct {
		host   string
		expect int
	}{
		{"example.com", 0},
		{"www.example.com", 1},
		{"api.www.example.com", 2},
	}
	for _, tt := range tests {
		subs := extractSubdomains(tt.host)
		if len(subs) != tt.expect {
			t.Errorf("extractSubdomains(%q) = %v, want %d subs", tt.host, subs, tt.expect)
		}
	}
}
