//go:build functional

// These black-box tests build and run the real CLI. They deliberately avoid
// importing proxy, scrub, or rewriter so assertions cover the shipped boundary.
package functional_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/tests/fixture"
)

var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "blinder-functional-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binaryPath = filepath.Join(dir, "blinder")
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../.."))
	build := exec.Command("go", "build", "-race", "-o", binaryPath, "./cmd/blinder")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build CLI: %v\n%s", err, output)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type process struct {
	cmd     *exec.Cmd
	done    chan struct{}
	err     error // read only after done closes
	logPath string
	baseURL string
}

func launch(t *testing.T, args ...string) *process {
	t.Helper()
	// Normal product startup persists certificates. Existing synthetic workflows
	// opt out so the test suite never writes into the operator's certificate store.
	hasCertificateMode := false
	for _, arg := range args {
		if arg == "--cert-dir" || strings.HasPrefix(arg, "--cert-dir=") || arg == "--ephemeral-cert" {
			hasCertificateMode = true
		}
	}
	if !hasCertificateMode {
		args = append(args, "--ephemeral-cert")
	}
	logPath := filepath.Join(t.TempDir(), "blinder.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	p := &process{cmd: exec.Command(binaryPath, args...), done: make(chan struct{}), logPath: logPath}
	p.cmd.Stdout, p.cmd.Stderr = logFile, logFile
	if err := p.cmd.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	go func() {
		p.err = p.cmd.Wait()
		logFile.Close()
		close(p.done)
	}()
	t.Cleanup(func() {
		p.stop()
		if strings.Contains(p.logs(), "WARNING: DATA RACE") {
			t.Error("race detector reported a race in the CLI subprocess")
		}
		if t.Failed() {
			t.Logf("CLI output:\n%s", p.logs())
		}
	})
	return p
}

func (p *process) logs() string {
	data, _ := os.ReadFile(p.logPath)
	return string(data)
}

func (p *process) stop() error {
	select {
	case <-p.done:
		return p.err
	default:
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	select {
	case <-p.done:
		return p.err
	case <-time.After(5 * time.Second):
		p.cmd.Process.Kill()
		<-p.done
		return fmt.Errorf("CLI did not shut down within five seconds")
	}
}

func client(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Jar: jar, Timeout: 3 * time.Second}
}

func start(t *testing.T, target string, args ...string) *process {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := ln.Addr().String()
	ln.Close()
	flags := []string{"--target", target, "--listen", address, "--identity", "AcmeCorp"}
	p := launch(t, append(flags, args...)...)
	p.baseURL = "https://" + address
	c := client(t)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-p.done:
			t.Fatalf("CLI exited before readiness: %v\n%s", p.err, p.logs())
		default:
		}
		resp, err := c.Get(p.baseURL + "/health")
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			// A 502 is still a ready listener (used to test upstream TLS failures).
			return p
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("CLI listener was not ready\n%s", p.logs())
	return nil
}

func request(t *testing.T, c *http.Client, method, address, body string, headers http.Header) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, address, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if headers != nil {
		req.Header = headers.Clone()
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(data)
}

func noIdentity(t *testing.T, value string) {
	t.Helper()
	if strings.Contains(strings.ToLower(value), "acmecorp") {
		t.Errorf("client-visible identity remains: %s", value)
	}
}

func TestCLIValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"missing_target", nil, "--target is required"},
		{"hostless_target", []string{"--target", "https:///path"}, "hostname"},
		{"onion_requires_tor", []string{"--target", "http://fixture.ONION."}, "require --tor"},
		{"short_identity", []string{"--target", "http://127.0.0.1", "-i", "xy"}, "at least 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, binaryPath, tc.args...).CombinedOutput()
			if err == nil || ctx.Err() != nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("want prompt nonzero exit containing %q; err=%v output=%s", tc.want, err, out)
			}
		})
	}
}

func TestLoginJSONAndEvidence(t *testing.T) {
	upstream := httptest.NewServer(fixture.Handler())
	defer upstream.Close()
	dir := t.TempDir()
	harPath := filepath.Join(dir, "session.har")
	outputDir := filepath.Join(dir, "evidence")
	p := start(t, upstream.URL, "--har", harPath, "--output", outputDir)
	c := client(t)
	loginBody := "username=tester&password=fixture-only"

	t.Run("unauthenticated", func(t *testing.T) {
		resp, _ := request(t, c, "GET", p.baseURL+"/account", "", nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status=%d", resp.StatusCode)
		}
	})
	t.Run("html_scrubbing", func(t *testing.T) {
		resp, body := request(t, c, "GET", p.baseURL+"/", "", nil)
		if resp.StatusCode != 200 || !strings.Contains(body, `action="/login"`) {
			t.Fatalf("login form lost: status=%d body=%s", resp.StatusCode, body)
		}
		noIdentity(t, body)
	})
	t.Run("login_cookie_and_relative_redirect", func(t *testing.T) {
		resp, body := request(t, c, "POST", p.baseURL+"/login", loginBody, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if resp.StatusCode != 200 || resp.Request.URL.Path != "/account" || !strings.Contains(body, "session-ok") {
			t.Fatalf("session broken: status=%d url=%s body=%s", resp.StatusCode, resp.Request.URL, body)
		}
		noIdentity(t, body)
		u, _ := url.Parse(p.baseURL)
		cookies := c.Jar.Cookies(u)
		if len(cookies) != 1 || cookies[0].Name == fixture.SessionName || cookies[0].Value != "synthetic-session" {
			t.Fatalf("unexpected client cookies: %v", cookies)
		}
	})
	t.Run("escaped_json_and_integer_fidelity", func(t *testing.T) {
		resp, body := request(t, c, "GET", p.baseURL+"/api?probe=one", "", nil)
		var decoded map[string]any
		decoder := json.NewDecoder(strings.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&decoded); err != nil {
			t.Fatal(err)
		}
		if decoded["id"] != json.Number("9007199254740993") || decoded["ok"] != true {
			t.Fatalf("JSON semantics changed: %s", body)
		}
		if resp.Header.Get("Content-Type") != "application/vnd.api+json" {
			t.Fatalf("MIME type changed: %s", resp.Header.Get("Content-Type"))
		}
		noIdentity(t, fmt.Sprint(decoded))
		noIdentity(t, fmt.Sprint(resp.Header))
	})
	t.Run("gzip", func(t *testing.T) {
		resp, body := request(t, c, "GET", p.baseURL+"/gzip", "", nil)
		if resp.StatusCode != 200 || !json.Valid([]byte(body)) || !strings.Contains(body, `"ok":true`) || resp.Header.Get("Content-Encoding") != "" {
			t.Fatalf("gzip failed: status=%d body=%s", resp.StatusCode, body)
		}
		noIdentity(t, body)
	})
	t.Run("unsupported_encoding_fails_closed", func(t *testing.T) {
		resp, body := request(t, c, "GET", p.baseURL+"/unsupported", "", nil)
		if resp.StatusCode != 502 || strings.TrimSpace(body) != "upstream error" {
			t.Fatalf("expected generic 502: status=%d body=%s", resp.StatusCode, body)
		}
	})
	t.Run("logout", func(t *testing.T) {
		request(t, c, "GET", p.baseURL+"/logout", "", nil)
		resp, _ := request(t, c, "GET", p.baseURL+"/account", "", nil)
		if resp.StatusCode != 401 {
			t.Fatalf("session survived logout: %d", resp.StatusCode)
		}
	})
	if err := p.stop(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	t.Run("artifacts", func(t *testing.T) {
		for _, path := range []string{harPath, filepath.Join(outputDir, "blinder-manifest.json"), filepath.Join(outputDir, "blinder-dealias.json"), filepath.Join(outputDir, "blinder-scrub-report.json")} {
			data, err := os.ReadFile(path)
			if err != nil || !json.Valid(data) {
				t.Fatalf("missing or invalid artifact %s: %v", path, err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("artifact must be owner-only: %s (stat error %v)", path, err)
			}
		}
		var har struct {
			Log struct {
				Entries []struct {
					Request struct {
						URL      string
						PostData struct{ Text string }
					}
					Response struct{ Content struct{ Text string } }
				}
			}
		}
		data, _ := os.ReadFile(harPath)
		if err := json.Unmarshal(data, &har); err != nil {
			t.Fatal(err)
		}
		var loginFound, originalFound bool
		for _, entry := range har.Log.Entries {
			if !strings.HasPrefix(entry.Request.URL, upstream.URL+"/") {
				t.Errorf("HAR URL is not upstream: %s", entry.Request.URL)
			}
			if entry.Request.URL == upstream.URL+"/login" && entry.Request.PostData.Text == loginBody {
				loginFound = true
			}
			if strings.Contains(entry.Response.Content.Text, "AcmeCorp") {
				originalFound = true
			}
		}
		if !loginFound || !originalFound {
			t.Fatalf("HAR lost original evidence: login=%v original=%v", loginFound, originalFound)
		}
	})
}

func TestUpstreamTLSVerification(t *testing.T) {
	upstream := httptest.NewTLSServer(fixture.Handler())
	defer upstream.Close()
	for _, insecure := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit_insecure_%v", insecure), func(t *testing.T) {
			var args []string
			want := 502
			if insecure {
				args, want = []string{"--no-verify-tls"}, 200
			}
			p := start(t, upstream.URL, args...)
			resp, body := request(t, client(t), "GET", p.baseURL+"/api", "", nil)
			if resp.StatusCode != want {
				t.Fatalf("want status %d, got %d: %s", want, resp.StatusCode, body)
			}
			noIdentity(t, body)
			if err := p.stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWebSocketFragmentAndShutdown(t *testing.T) {
	handler := fixture.Handler()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" && r.Header.Get("Origin") != "http://"+r.Host {
			http.Error(w, "origin rejected", http.StatusForbidden)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer upstream.Close()
	p := start(t, upstream.URL)
	conn, rd, resp := websocketRequest(t, p.baseURL)
	if resp.StatusCode != 101 || resp.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("invalid handshake: %v", resp)
	}
	message := readTextMessage(t, rd)
	if !strings.HasSuffix(message, " live") {
		t.Fatalf("text semantics lost: %q", message)
	}
	noIdentity(t, message)
	if err := p.stop(); err != nil {
		t.Fatalf("shutdown with live WebSocket: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := rd.ReadByte(); err == nil {
		t.Fatal("expected WebSocket to be closed on shutdown")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("WebSocket was left open after shutdown")
	}
}

func websocketRequest(t *testing.T, baseURL string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	u, _ := url.Parse(baseURL)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", u.Host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", u.Host, baseURL)
	rd := bufio.NewReader(conn)
	resp, err := http.ReadResponse(rd, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	return conn, rd, resp
}

func readTextMessage(t *testing.T, rd *bufio.Reader) string {
	t.Helper()
	var message strings.Builder
	for frame := 0; frame < 8; frame++ {
		var header [2]byte
		if _, err := io.ReadFull(rd, header[:]); err != nil {
			t.Fatal(err)
		}
		opcode := header[0] & 0x0f
		if header[0]&0x70 != 0 || header[1]&0x80 != 0 || (frame == 0 && opcode != 1) || (frame > 0 && opcode != 0) {
			t.Fatalf("invalid server text frame: %x", header)
		}
		size := uint64(header[1] & 0x7f)
		if size == 126 {
			var ext [2]byte
			if _, err := io.ReadFull(rd, ext[:]); err != nil {
				t.Fatal(err)
			}
			size = uint64(binary.BigEndian.Uint16(ext[:]))
		} else if size == 127 {
			t.Fatal("unexpected large fixture message")
		}
		if size > 4096 {
			t.Fatal("unexpected large fixture message")
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(rd, payload); err != nil {
			t.Fatal(err)
		}
		message.Write(payload)
		if header[0]&0x80 != 0 {
			return message.String()
		}
	}
	t.Fatal("message did not finish")
	return ""
}
