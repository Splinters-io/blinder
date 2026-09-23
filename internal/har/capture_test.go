package har

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCaptureLimitsApplyToRequestsAndEveryResponseType(t *testing.T) {
	for _, tc := range []struct {
		name, mime string
		body, want []byte
		base64     bool
	}{
		{"json", "application/json", []byte(`{"a":12345}`), []byte(`{"a":`), false},
		{"utf8", "text/plain", []byte("abc€def"), []byte("abc"), false},
		{"form charset", "application/x-www-form-urlencoded; charset=utf-8", []byte("a=123456"), []byte("a=123"), false},
		{"binary", "application/octet-stream", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4}, true},
		{"invalid text", "text/plain", []byte{0xff, 1, 2, 3, 4, 5}, []byte{0xff, 1, 2, 3, 4}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := NewWriter(5)
			req, _ := http.NewRequest("POST", "https://example.test/", nil)
			req.Header.Set("Content-Type", tc.mime)
			resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {tc.mime}}}
			before := time.Now().Add(-time.Second)
			w.Record(req, tc.body, resp, tc.body, time.Second)
			entry := w.entries[0]
			start, err := time.Parse(time.RFC3339Nano, entry.StartedDateTime)
			if err != nil || start.Before(before) || start.After(time.Now().Add(-900*time.Millisecond)) {
				t.Fatalf("HAR start is not the request start: %s", entry.StartedDateTime)
			}
			for _, captured := range []struct{ text, encoding, comment string }{
				{entry.Request.PostData.Text, entry.Request.PostData.Encoding, entry.Request.PostData.Comment},
				{entry.Response.Content.Text, entry.Response.Content.Encoding, entry.Response.Content.Comment},
			} {
				data := []byte(captured.text)
				if tc.base64 {
					if captured.encoding != "base64" {
						t.Fatal("binary bytes must retain their encoding")
					}
					data, err = base64.StdEncoding.DecodeString(captured.text)
					if err != nil {
						t.Fatal(err)
					}
				}
				if string(data) != string(tc.want) || !strings.Contains(captured.comment, "truncated") {
					t.Fatalf("capture not correctly bounded/reported: %q (%s)", data, captured.comment)
				}
			}
			if entry.Request.BodySize != len(tc.body) || entry.Response.Content.Size != len(tc.body) {
				t.Fatal("capture truncation lost original body sizes")
			}
		})
	}
}
