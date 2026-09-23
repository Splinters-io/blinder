//go:build functional

package functional_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/tests/fixture"
)

func TestCertificatePreflightAndVerifiedRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binaryPath, "--preflight", "--cert-dir", dir).CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 || !strings.Contains(string(out), "Platform trust: setup needed") {
		t.Fatalf("preflight must create the certificate and report missing trust without a target: err=%v output=%s", err, out)
	}
	if !strings.Contains(string(out), "Detected OS: ") || !strings.Contains(string(out), "curl --cacert") || !strings.Contains(string(out), "--preflight still exits 2") {
		t.Fatalf("preflight is missing OS/client guidance: %s", out)
	}
	public, err := os.ReadFile(filepath.Join(dir, "certificate.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(public) {
		t.Fatal("missing public certificate")
	}
	upstream := httptest.NewServer(fixture.Handler())
	defer upstream.Close()
	var fingerprint string
	for i := 0; i < 2; i++ {
		p := start(t, upstream.URL, "--cert-dir", dir)
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
		c := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		resp, body := request(t, c, "GET", p.baseURL+"/api", "", nil)
		transport.CloseIdleConnections()
		if resp.StatusCode != 200 || !strings.Contains(body, "9007199254740993") {
			t.Fatalf("verified TLS request failed: status=%d body=%s", resp.StatusCode, body)
		}
		if i == 0 {
			if curl, err := exec.LookPath("curl"); err == nil {
				curlOut, err := exec.Command(curl, "--noproxy", "*", "--max-time", "5", "--fail", "--silent", "--show-error", "--cacert", filepath.Join(dir, "certificate.pem"), p.baseURL+"/api").CombinedOutput()
				if err != nil || !strings.Contains(string(curlOut), "9007199254740993") {
					t.Fatalf("documented curl certificate verification failed: %v\n%s", err, curlOut)
				}
			} else {
				t.Log("curl not installed; verified HTTPS using Go's explicit trust pool only")
			}
		}
		for _, line := range strings.Split(p.logs(), "\n") {
			if strings.HasPrefix(line, "SHA-256: ") {
				if fingerprint != "" && fingerprint != line {
					t.Fatal("fingerprint changed on restart")
				}
				fingerprint = line
			}
		}
		if err := p.stop(); err != nil {
			t.Fatal(err)
		}
	}
	if fingerprint == "" {
		t.Fatal("preflight did not expose a reviewable fingerprint")
	}
}

func TestCertificateTrustCanBeDeclined(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, "--trust-cert", "--cert-dir", filepath.Join(t.TempDir(), "certs"))
	cmd.Stdin = strings.NewReader("no\n")
	out, err := cmd.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 || ctx.Err() != nil {
		t.Fatalf("declined/unavailable trust must exit 2: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Trust installation declined") && !strings.Contains(string(out), "Automatic trust installation is unavailable") {
		t.Fatalf("unexpected trust result: %s", out)
	}
}
