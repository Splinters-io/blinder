package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCSPNonceSubmissionRestoresOriginal(t *testing.T) {
	var received []byte
	s := codexSRIServer(t, func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			received, _ = io.ReadAll(r.Body)
			if r.ContentLength != int64(len(received)) {
				t.Errorf("upstream ContentLength=%d, bytes=%d", r.ContentLength, len(received))
			}
			return codexSRIResponse("text/plain", "accepted"), nil
		}
		response := codexSRIResponse("text/html", `<script nonce="AcmeCorp">window.ok = true;</script>`)
		response.Header.Set("Content-Security-Policy", "script-src 'nonce-AcmeCorp'")
		return response, nil
	})
	page := codexSRIRequest(s, http.MethodGet, "/", "", "")
	nonce := codexSRIAttribute(page.Body.String(), "nonce")
	if nonce == "" || nonce == "AcmeCorp" || !strings.Contains(page.Header().Get("Content-Security-Policy"), "'nonce-"+nonce+"'") {
		t.Fatalf("missing coordinated masked nonce: %q %v", page.Body.String(), page.Header())
	}
	for _, ct := range []string{"application/json", "application/x-www-form-urlencoded"} {
		t.Run(ct, func(t *testing.T) {
			var body string
			if ct == "application/json" {
				data, _ := json.Marshal(map[string]string{"nonce": nonce})
				body = string(data)
			} else {
				body = url.Values{"nonce": {nonce}}.Encode()
			}
			request := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:18099/submit", strings.NewReader(body))
			request.Header.Set("Content-Type", ct)
			response := httptest.NewRecorder()
			s.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var value string
			if ct == "application/json" {
				var values map[string]string
				if err := json.Unmarshal(received, &values); err != nil {
					t.Fatal(err)
				}
				value = values["nonce"]
			} else {
				values, err := url.ParseQuery(string(received))
				if err != nil {
					t.Fatal(err)
				}
				value = values.Get("nonce")
			}
			if value != "AcmeCorp" {
				t.Fatalf("upstream nonce=%q", value)
			}
		})
	}
}
