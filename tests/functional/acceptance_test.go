//go:build functional

package functional_test

import (
	"errors"
	"net"
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

// Acceptance tests assert the desired operator experience. They are intentionally
// not skipped when the current product fails: see docs/testing.md for the baseline.
func TestAcceptanceOccupiedPortExits(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	p := launch(t, "--target", "http://127.0.0.1:1", "--listen", ln.Addr().String())
	select {
	case <-p.done:
		var exit *exec.ExitError
		if !errors.As(p.err, &exit) || exit.ExitCode() <= 0 || !strings.Contains(p.logs(), "address already in use") {
			t.Fatalf("expected nonzero exit reporting a bind failure: %v", p.err)
		}
		if strings.Contains(p.logs(), "Proxy listening") {
			t.Fatal("bind failure was announced as a ready listener")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bind failure left CLI running; startup must exit nonzero without a signal")
	}
}

func TestAcceptanceArtifactFailureExitsNonzero(t *testing.T) {
	upstream := httptest.NewServer(fixture.Handler())
	defer upstream.Close()
	for _, flag := range []string{"--har", "--output"} {
		t.Run(strings.TrimPrefix(flag, "--"), func(t *testing.T) {
			blocker := filepath.Join(t.TempDir(), "regular-file")
			if err := os.WriteFile(blocker, []byte("not a directory"), 0600); err != nil {
				t.Fatal(err)
			}
			// A path below a regular file fails deterministically, even as root.
			otherFlag, otherFile := "--output", "blinder-manifest.json"
			if flag == "--output" {
				otherFlag, otherFile = "--har", ""
			}
			otherPath := filepath.Join(t.TempDir(), "successful-evidence")
			p := start(t, upstream.URL, flag, filepath.Join(blocker, "evidence"), otherFlag, otherPath)
			request(t, client(t), "GET", p.baseURL+"/api", "", nil)
			err := p.stop()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() <= 0 || !strings.Contains(p.logs(), "not a directory") {
				t.Fatalf("%s evidence could not be written; want a nonzero exit reporting the write failure, got %v", flag, err)
			}
			if _, err := os.Stat(filepath.Join(otherPath, otherFile)); err != nil {
				t.Fatalf("a failed evidence write prevented the other artifact being saved: %v", err)
			}
		})
	}
}

func TestAcceptanceBrowserOriginForm(t *testing.T) {
	upstream := httptest.NewServer(fixture.Handler())
	defer upstream.Close()
	c := client(t)
	// Establish that the fixture accepts the same-origin browser request directly.
	resp, body := request(t, c, "POST", upstream.URL+"/form", "message=hello", http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"}, "Origin": {upstream.URL},
	})
	if resp.StatusCode != 200 || body != "form accepted" {
		t.Fatalf("fixture baseline failed: %d %s", resp.StatusCode, body)
	}
	p := start(t, upstream.URL)
	resp, body = request(t, c, "POST", p.baseURL+"/form", "message=hello", http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"}, "Origin": {p.baseURL}, "Referer": {p.baseURL + "/form"},
	})
	if resp.StatusCode != 200 || body != "form accepted" {
		t.Fatalf("browser-origin POST fails through documented loopback URL: status=%d body=%q", resp.StatusCode, body)
	}
	for _, origin := range []string{"null", "https://unrelated.example", p.baseURL + "/not-an-origin"} {
		resp, _ := request(t, c, "POST", p.baseURL+"/form", "message=hello", http.Header{
			"Content-Type": {"application/x-www-form-urlencoded"}, "Origin": {origin},
		})
		if resp.StatusCode != 403 {
			t.Fatalf("unrelated/invalid origin %q was repaired: status=%d", origin, resp.StatusCode)
		}
	}
}
