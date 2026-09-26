package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestCompactIdentityPreservesActualResponseSizeAndDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body string
		status                  int
	}{
		{"plain", "text/plain", "AcmeCorp / ACMECORP / OtherOrg", 200},
		{"json", "application/json", `{"name":"AcmeCorp","ACMECORP":"OtherOrg","number":900719925474099312345}`, 200},
		{"attribute", "text/html", `<INPUT DISABLED value='AcmeCorp' keep="&#39;">`, 200},
		{"diagnostic", "text/html", `<pre>SQLSTATE[42000]: AcmeCorp unavailable</pre>`, 503},
		{"long_identity", "text/plain", strings.Repeat("PrivateName", 20), 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer target.Close()
			s := mappingReviewEphemeralServer(t, target.URL, []string{"AcmeCorp", "OtherOrg", strings.Repeat("PrivateName", 20)}, nil)
			s.cfg.Paranoid = true
			defer s.transport.(*http.Transport).CloseIdleConnections()
			completed := make(chan struct{}, 1)
			local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				s.ServeHTTP(w, r)
				completed <- struct{}{}
			}))
			defer local.Close()
			resp, err := local.Client().Get(local.URL + "/fixture")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			<-completed
			if resp.StatusCode != tc.status || len(body) != len(tc.body) || resp.Header.Get("Content-Length") != strconv.Itoa(len(tc.body)) || resp.Header.Get("X-Blinder-Body-Size-Match") != "exact" {
				t.Fatalf("decoded/actual body size changed: status=%d, %d -> %d, headers=%v", resp.StatusCode, len(tc.body), len(body), resp.Header)
			}
			m := lastResponseMetrics(t, s)
			if !m.BodyComplete || m.OriginalBodyBytes != int64(len(tc.body)) || m.DownstreamBytes != int64(len(tc.body)) || *m.RewriteDeltaBytes != 0 {
				t.Fatalf("emitted size was not measured exactly: %+v", m)
			}
			for _, identity := range []string{"AcmeCorp", "ACMECORP", "OtherOrg", "PrivateName"} {
				if bytes.Contains(body, []byte(identity)) {
					t.Fatal("configured identity remains in emitted body")
				}
			}
			restored := s.gate.RestoreBody(string(body))
			if tc.contentType == "application/json" {
				restored = string(s.gate.RestoreJSON(body))
			}
			if restored != tc.body {
				t.Fatalf("size matching changed source evidence: %q -> %q", tc.body, restored)
			}
		})
	}
}

func TestCompactIdentitySubmittedValuesRestoreThroughRealTransport(t *testing.T) {
	const original = "AcmeCorp"
	received := make(chan string, 2)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<input name="value" value="AcmeCorp">`)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		received <- string(body)
		w.WriteHeader(202)
	}))
	defer target.Close()
	s := mappingReviewEphemeralServer(t, target.URL, []string{original}, nil)
	defer s.transport.(*http.Transport).CloseIdleConnections()
	page := audit267CacheRequest(s, "GET", "/", nil)
	z := html.NewTokenizer(bytes.NewReader(page.Body.Bytes()))
	if z.Next() != html.StartTagToken {
		t.Fatal("missing input")
	}
	var alias string
	for _, attr := range z.Token().Attr {
		if attr.Key == "value" {
			alias = attr.Val
		}
	}
	if len(alias) != len(original) || alias == original {
		t.Fatalf("input did not retain byte budget: %q", alias)
	}
	for _, contentType := range []string{"application/json", "application/x-www-form-urlencoded"} {
		var body, expected string
		if contentType == "application/json" {
			data, _ := json.Marshal(map[string]string{"value": alias})
			body, expected = string(data), `{"value":"AcmeCorp"}`
		} else {
			body, expected = url.Values{"value": {alias}}.Encode(), "value=AcmeCorp"
		}
		r := httptest.NewRequest("vendor.sync", "https://127.0.0.1:18099/submit", strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		got := httptest.NewRecorder()
		s.ServeHTTP(got, r)
		if got.Code != 202 || <-received != expected {
			t.Fatalf("submitted value did not restore correctly through HTTP transport: %s, status=%d", contentType, got.Code)
		}
	}
}
