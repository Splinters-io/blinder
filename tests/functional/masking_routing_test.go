//go:build functional

package functional_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParanoidWorksWithDirectRouting(t *testing.T) {
	const prose = "Original ordinary prose with enough room to keep the local page size stable after content masking."
	const page = "<!doctype html><p>" + prose + "</p>"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/error" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			io.WriteString(w, "<pre>E_INPUT: AcmeCorp value rejected</pre>")
			return
		}
		io.WriteString(w, page)
	}))
	defer upstream.Close()
	for _, fromFile := range []bool{false, true} {
		name := "flag"
		if fromFile {
			name = "yaml"
		}
		t.Run(name, func(t *testing.T) {
			args := []string{"--paranoid"}
			if fromFile {
				path := filepath.Join(t.TempDir(), "blinder.yaml")
				if err := os.WriteFile(path, []byte("paranoid: true\ntor:\n  enabled: false\n"), 0600); err != nil {
					t.Fatal(err)
				}
				args = []string{"--config", path}
			}
			p := start(t, upstream.URL, args...)
			resp, body := request(t, client(t), "GET", p.baseURL+"/", "", nil)
			if resp.StatusCode != http.StatusOK || strings.Contains(body, prose) || len(body) != len(page) || resp.Header.Get("X-Blinder-Body-Size-Match") != "exact" {
				t.Fatalf("direct CLI masking failed: status=%d bytes=%d body=%q", resp.StatusCode, len(body), body)
			}
			resp, body = request(t, client(t), "GET", p.baseURL+"/error", "", nil)
			if resp.StatusCode != 422 || !strings.Contains(body, "E_INPUT:") {
				t.Fatalf("diagnostic lost: status=%d body=%q", resp.StatusCode, body)
			}
			noIdentity(t, body)
			if err := p.stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
