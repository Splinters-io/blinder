package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestErrorTitleFidelityThroughProxy(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(strconv.FormatBool(compressed), func(t *testing.T) {
			const original = `<title>AcmeCorp at main.example: SQLSTATE[42000] syntax error near &#39;</title><p>Retry.</p>`
			encoded := []byte(original)
			if compressed {
				var buf bytes.Buffer
				gz := gzip.NewWriter(&buf)
				if _, err := gz.Write(encoded); err != nil {
					t.Fatal(err)
				}
				if err := gz.Close(); err != nil {
					t.Fatal(err)
				}
				encoded = buf.Bytes()
			}
			s := mappingReviewServer(t, "https://main.example", []string{"AcmeCorp"}, func(*http.Request) (*http.Response, error) {
				resp := audit267SRIResponse("text/html", "")
				resp.StatusCode = 500
				resp.Body = io.NopCloser(bytes.NewReader(encoded))
				resp.ContentLength = int64(len(encoded))
				resp.Header.Set("Content-Length", strconv.Itoa(len(encoded)))
				resp.Header.Set("X-Application-Error", "AcmeCorp: E_QUERY")
				if compressed {
					resp.Header.Set("Content-Encoding", "gzip")
				}
				return resp, nil
			})
			s.cfg.Paranoid = true
			got := audit267CacheRequest(s, "GET", "/error", nil)
			if got.Code != 500 || !strings.Contains(got.Body.String(), "SQLSTATE[42000] syntax error near") || strings.Contains(got.Body.String(), "AcmeCorp") || strings.Contains(got.Body.String(), "main.example") {
				t.Fatalf("upstream title diagnostic/status not preserved while masking: status=%d body=%s", got.Code, got.Body.String())
			}
			if value := got.Header().Get("X-Application-Error"); !strings.Contains(value, "E_QUERY") || strings.Contains(value, "AcmeCorp") {
				t.Fatalf("diagnostic header changed: %q", value)
			}
			if got.Header().Get("Content-Length") != strconv.Itoa(got.Body.Len()) || got.Header().Get("Content-Encoding") != "" {
				t.Fatalf("downstream size/encoding mismatch: %v", got.Header())
			}
			metrics := lastResponseMetrics(t, s)
			if metrics.OriginalBodyBytes != int64(len(original)) || metrics.RewrittenBodyBytes != int64(got.Body.Len()) || metrics.DownstreamBytes != int64(got.Body.Len()) {
				t.Fatalf("incorrect decoded size measurements: %+v", metrics)
			}
		})
	}
}
