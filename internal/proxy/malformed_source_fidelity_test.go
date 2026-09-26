package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestMalformedHTMLSourceKeepsStatusDiagnosticsAndActualSize(t *testing.T) {
	for _, suffix := range []string{
		`<?E_INPUT AcmeCorp?>`,
		`<!E_INPUT AcmeCorp>`,
		`<!-- E_INPUT AcmeCorp --!>`,
		`<!-- E_INPUT AcmeCorp`,
		`<div data-note='AcmeCorp`,
	} {
		t.Run(suffix, func(t *testing.T) {
			const diagnostic = `<pre>SQLSTATE[42000]: invalid input near SELECT</pre>`
			source := diagnostic + suffix
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusServiceUnavailable)
				io.WriteString(w, source)
			}))
			defer target.Close()
			s := mappingReviewEphemeralServer(t, target.URL, []string{"AcmeCorp"}, nil)
			s.cfg.Paranoid = true
			defer s.transport.(*http.Transport).CloseIdleConnections()
			local := httptest.NewServer(s)
			defer local.Close()
			response, err := local.Client().Get(local.URL + "/fixture")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 503 || len(body) != len(source) || response.Header.Get("Content-Length") != strconv.Itoa(len(source)) {
				t.Fatalf("real response status/size drifted: status=%d bytes=%d headers=%v", response.StatusCode, len(body), response.Header)
			}
			if !strings.HasPrefix(string(body), diagnostic) || strings.Contains(string(body), "AcmeCorp") {
				t.Fatalf("diagnostic lost or identity exposed: %q", body)
			}
			if restored := s.gate.RestoreBody(string(body)); restored != source {
				t.Fatalf("malformed source syntax changed beyond masking: %q -> %q", source, restored)
			}
		})
	}
}
