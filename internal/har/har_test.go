package har

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewWriter(t *testing.T) {
	w := NewWriter(10 * 1024 * 1024)

	if w == nil {
		t.Fatal("expected non-nil writer")
	}
}

func TestRecord_BasicEntry(t *testing.T) {
	w := NewWriter(10 * 1024 * 1024)

	req, _ := http.NewRequest("GET", "https://example.com/api/users", nil)
	req.Header.Set("Accept", "application/json")

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     http.Header{"Content-Type": {"application/json"}},
	}

	reqBody := []byte("")
	respBody := []byte(`{"users":[]}`)
	elapsed := 150 * time.Millisecond

	w.Record(req, reqBody, resp, respBody, elapsed)

	if w.Len() != 1 {
		t.Fatalf("expected 1 entry, got %d", w.Len())
	}
}

func TestFlush_ValidHAR(t *testing.T) {
	w := NewWriter(10 * 1024 * 1024)

	req, _ := http.NewRequest("POST", "https://example.com/login", strings.NewReader("user=admin&pass=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp := &http.Response{
		StatusCode: 302,
		Status:     "302 Found",
		Proto:      "HTTP/1.1",
		Header: http.Header{
			"Location":     {"https://example.com/dashboard"},
			"Content-Type": {"text/html"},
		},
	}

	w.Record(req, []byte("user=admin&pass=secret"), resp, []byte("<html>redirect</html>"), 200*time.Millisecond)

	dir := t.TempDir()
	path := filepath.Join(dir, "test.har")

	err := w.Flush(path)
	if err != nil {
		t.Fatalf("flush: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var harFile HARFile
	if err := json.Unmarshal(data, &harFile); err != nil {
		t.Fatalf("parse HAR JSON: %v", err)
	}

	if harFile.Log.Creator.Name != "blinder" {
		t.Errorf("expected creator name 'blinder', got %q", harFile.Log.Creator.Name)
	}

	if len(harFile.Log.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(harFile.Log.Entries))
	}

	entry := harFile.Log.Entries[0]
	if entry.Request.Method != "POST" {
		t.Errorf("expected method POST, got %q", entry.Request.Method)
	}
	if entry.Request.URL != "https://example.com/login" {
		t.Errorf("expected URL https://example.com/login, got %q", entry.Request.URL)
	}
	if entry.Response.Status != 302 {
		t.Errorf("expected status 302, got %d", entry.Response.Status)
	}
	if entry.Response.Content.MimeType != "text/html" {
		t.Errorf("expected mime type text/html, got %q", entry.Response.Content.MimeType)
	}
	if entry.Response.Content.Text != "<html>redirect</html>" {
		t.Errorf("unexpected response body: %q", entry.Response.Content.Text)
	}
}

func TestFlush_BinaryBodyBase64(t *testing.T) {
	w := NewWriter(10 * 1024 * 1024)

	req, _ := http.NewRequest("GET", "https://example.com/image.png", nil)
	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     http.Header{"Content-Type": {"image/png"}},
	}

	binaryBody := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00}
	w.Record(req, nil, resp, binaryBody, 50*time.Millisecond)

	dir := t.TempDir()
	path := filepath.Join(dir, "binary.har")
	w.Flush(path)

	data, _ := os.ReadFile(path)
	var harFile HARFile
	json.Unmarshal(data, &harFile)

	entry := harFile.Log.Entries[0]
	if entry.Response.Content.Encoding != "base64" {
		t.Errorf("expected encoding 'base64', got %q", entry.Response.Content.Encoding)
	}
}

func TestFlush_TruncatedBody(t *testing.T) {
	maxBody := int64(32)
	w := NewWriter(maxBody)

	req, _ := http.NewRequest("GET", "https://example.com/big", nil)
	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     http.Header{"Content-Type": {"image/jpeg"}},
	}

	bigBody := make([]byte, 64)
	for i := range bigBody {
		bigBody[i] = byte(i)
	}
	w.Record(req, nil, resp, bigBody, 100*time.Millisecond)

	dir := t.TempDir()
	path := filepath.Join(dir, "truncated.har")
	w.Flush(path)

	data, _ := os.ReadFile(path)
	var harFile HARFile
	json.Unmarshal(data, &harFile)

	entry := harFile.Log.Entries[0]
	if entry.Response.Content.Comment == "" {
		t.Error("expected truncation comment")
	}
	if !strings.Contains(entry.Response.Content.Comment, "truncated") {
		t.Errorf("expected truncation comment, got %q", entry.Response.Content.Comment)
	}
}

func TestFlush_AtomicWrite(t *testing.T) {
	w := NewWriter(10 * 1024 * 1024)

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     http.Header{"Content-Type": {"text/html"}},
	}
	w.Record(req, nil, resp, []byte("<html></html>"), 10*time.Millisecond)

	dir := t.TempDir()
	path := filepath.Join(dir, "atomic.har")

	w.Flush(path)

	// Verify file exists at final path
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected file at final path: %v", err)
	}

	// Verify no temp files left
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".blinder-har-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestFlush_MultipleEntries(t *testing.T) {
	w := NewWriter(10 * 1024 * 1024)

	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", "https://example.com/page", nil)
		resp := &http.Response{
			StatusCode: 200,
			Status:     "200 OK",
			Proto:      "HTTP/1.1",
			Header:     http.Header{"Content-Type": {"text/html"}},
		}
		w.Record(req, nil, resp, []byte("<html></html>"), 10*time.Millisecond)
	}

	if w.Len() != 5 {
		t.Errorf("expected 5 entries, got %d", w.Len())
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "multi.har")
	w.Flush(path)

	data, _ := os.ReadFile(path)
	var harFile HARFile
	json.Unmarshal(data, &harFile)

	if len(harFile.Log.Entries) != 5 {
		t.Errorf("expected 5 entries in HAR, got %d", len(harFile.Log.Entries))
	}
}

func TestRecord_StartedDateTime(t *testing.T) {
	w := NewWriter(10 * 1024 * 1024)

	before := time.Now().Add(-10 * time.Millisecond)
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     http.Header{},
	}
	w.Record(req, nil, resp, nil, 10*time.Millisecond)
	after := time.Now().Add(-10 * time.Millisecond)

	dir := t.TempDir()
	path := filepath.Join(dir, "time.har")
	w.Flush(path)

	data, _ := os.ReadFile(path)
	var harFile HARFile
	json.Unmarshal(data, &harFile)

	entry := harFile.Log.Entries[0]
	ts, err := time.Parse(time.RFC3339Nano, entry.StartedDateTime)
	if err != nil {
		t.Fatalf("parse timestamp: %v", err)
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("timestamp %v outside range [%v, %v]", ts, before, after)
	}
}

func TestRecord_QueryString(t *testing.T) {
	w := NewWriter(10 * 1024 * 1024)

	req, _ := http.NewRequest("GET", "https://example.com/search?q=test&page=2", nil)
	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     http.Header{},
	}
	w.Record(req, nil, resp, nil, 10*time.Millisecond)

	dir := t.TempDir()
	path := filepath.Join(dir, "qs.har")
	w.Flush(path)

	data, _ := os.ReadFile(path)
	var harFile HARFile
	json.Unmarshal(data, &harFile)

	qs := harFile.Log.Entries[0].Request.QueryString
	if len(qs) != 2 {
		t.Fatalf("expected 2 query params, got %d", len(qs))
	}

	found := map[string]string{}
	for _, p := range qs {
		found[p.Name] = p.Value
	}
	if found["q"] != "test" {
		t.Errorf("expected q=test, got q=%s", found["q"])
	}
	if found["page"] != "2" {
		t.Errorf("expected page=2, got page=%s", found["page"])
	}
}

func TestRecord_Headers(t *testing.T) {
	w := NewWriter(10 * 1024 * 1024)

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Authorization", "Bearer token123")

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header: http.Header{
			"Content-Type": {"text/html"},
			"X-Custom":     {"value1", "value2"},
		},
	}
	w.Record(req, nil, resp, []byte("ok"), 10*time.Millisecond)

	dir := t.TempDir()
	path := filepath.Join(dir, "headers.har")
	w.Flush(path)

	data, _ := os.ReadFile(path)
	var harFile HARFile
	json.Unmarshal(data, &harFile)

	entry := harFile.Log.Entries[0]

	reqHeaders := map[string]string{}
	for _, h := range entry.Request.Headers {
		reqHeaders[h.Name] = h.Value
	}
	if reqHeaders["Accept"] != "text/html" {
		t.Error("expected Accept header in request")
	}

	respHeaders := map[string]string{}
	for _, h := range entry.Response.Headers {
		respHeaders[h.Name] = h.Value
	}
	if respHeaders["Content-Type"] != "text/html" {
		t.Error("expected Content-Type header in response")
	}
}

func TestFlush_EmptyWriter(t *testing.T) {
	w := NewWriter(10 * 1024 * 1024)

	dir := t.TempDir()
	path := filepath.Join(dir, "empty.har")

	err := w.Flush(path)
	if err != nil {
		t.Fatalf("flush empty writer: %v", err)
	}

	data, _ := os.ReadFile(path)
	var harFile HARFile
	json.Unmarshal(data, &harFile)

	if len(harFile.Log.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(harFile.Log.Entries))
	}
}
