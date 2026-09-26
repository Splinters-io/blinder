package har

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Set BLINDER_HAR_COMPAT_OUTPUT to retain a synthetic fixture for an independent
// validator. This never captures a live site or real operator credentials.
func TestHARCompatibilityFixture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compat.har")
	w := NewWriter(path, 1024, 3)
	text := []byte("diagnostic café\n")
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	gz.Write(text)
	gz.Close()
	for _, fixture := range []struct {
		method, path, ct  string
		status            int
		request, response []byte
		headers           http.Header
		encoded           int64
	}{
		{"GET", "/text?a=1&a=2", "text/plain", 200, nil, text, nil, int64(len(text))},
		{"GET", "/gzip", "text/plain", 200, nil, text, http.Header{"Content-Encoding": {"gzip"}}, int64(compressed.Len())},
		{"POST", "/binary", "application/octet-stream", 200, []byte{0, 255, 1}, []byte{0, 255, 2}, nil, 3},
		{"GET", "/redirect", "text/plain", 302, nil, nil, http.Header{"Location": {"https://fixture.invalid/destination"}, "Set-Cookie": {"fixture-session=two; Path=/; Secure; HttpOnly; SameSite=Lax"}}, 0},
		{"GET", "/socket", "application/octet-stream", 101, nil, nil, http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}}, 0},
	} {
		r := httptest.NewRequest(fixture.method, "https://fixture.invalid"+fixture.path, bytes.NewReader(fixture.request))
		r.Header.Set("Content-Type", fixture.ct)
		r.Header.Set("Cookie", "fixture-session=one")
		h := fixture.headers
		if h == nil {
			h = make(http.Header)
		}
		h.Set("Content-Type", fixture.ct)
		resp := &http.Response{StatusCode: fixture.status, Status: http.StatusText(fixture.status), Proto: "HTTP/1.1", Header: h}
		w.Record(r, fixture.request, resp, fixture.response, 10*time.Millisecond, ResponseBodyInfo{EncodedBytes: fixture.encoded})
	}
	r := httptest.NewRequest("GET", "https://fixture.invalid/partial", nil)
	w.RecordFetchFailure(r, 503, http.Header{"Content-Type": {"text/plain"}}, []byte("partial diagnostic"), "read", 10*time.Millisecond)
	r = httptest.NewRequest("GET", "https://fixture.invalid/transport", nil)
	w.RecordFetchFailure(r, 0, nil, nil, "transport", 10*time.Millisecond)
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var parsed HARFile
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Log.Entries) != 7 {
		t.Fatalf("entries=%d", len(parsed.Log.Entries))
	}
	// Required HAR containers must be emitted even when empty. Decode raw JSON
	// so absent fields cannot be hidden by the Go model's default values.
	var raw struct {
		Log struct {
			Entries []map[string]json.RawMessage `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	for i, entry := range raw.Log.Entries {
		if string(entry["cache"]) != "{}" {
			t.Fatalf("entry %d lacks empty cache object: %s", i, entry["cache"])
		}
		for _, side := range []string{"request", "response"} {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(entry[side], &fields); err != nil {
				t.Fatal(err)
			}
			if data := fields["cookies"]; len(data) == 0 || data[0] != '[' {
				t.Fatalf("entry %d %s lacks cookie array: %s", i, side, data)
			}
			if side == "response" && fields["redirectURL"] == nil {
				t.Fatalf("entry %d lacks redirectURL", i)
			}
		}
	}
	if got := parsed.Log.Entries[3].Response; got.RedirectURL != "https://fixture.invalid/destination" || len(got.Cookies) != 1 || !got.Cookies[0].Secure || !got.Cookies[0].HTTPOnly {
		t.Fatalf("redirect/cookie evidence lost: %+v", got)
	}
	// Export only after checking a fresh capture. Re-running the test must not
	// merge previous fixture entries from an operator-selected output path.
	if configured := os.Getenv("BLINDER_HAR_COMPAT_OUTPUT"); configured != "" {
		if err := os.WriteFile(configured, body, 0600); err != nil {
			t.Fatal(err)
		}
		path = configured
	}
	t.Logf("independent HAR fixture: %s", path)
}
