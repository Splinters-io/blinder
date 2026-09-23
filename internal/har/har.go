package har

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type HARFile struct {
	Log Log `json:"log"`
}

type Log struct {
	Version string  `json:"version"`
	Creator Creator `json:"creator"`
	Entries []Entry `json:"entries"`
}

type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Entry struct {
	StartedDateTime string   `json:"startedDateTime"`
	Time            float64  `json:"time"`
	Request         Request  `json:"request"`
	Response        Response `json:"response"`
	Timings         Timings  `json:"timings"`
}

type Request struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []NameValue `json:"headers"`
	QueryString []NameValue `json:"queryString"`
	PostData    *PostData   `json:"postData,omitempty"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type Response struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []NameValue `json:"headers"`
	Content     Content     `json:"content"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type Content struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

type PostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Comment  string `json:"comment,omitempty"`
	Encoding string `json:"_encoding,omitempty"` // Extension for original binary request bytes.
}

type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Timings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

type Writer struct {
	entries     []Entry
	mu          sync.Mutex
	maxBodySize int64
}

func NewWriter(maxBodySize int64) *Writer {
	if maxBodySize <= 0 {
		maxBodySize = 10 * 1024 * 1024
	}
	return &Writer{
		maxBodySize: maxBodySize,
	}
}

func (w *Writer) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.entries)
}

func (w *Writer) Record(req *http.Request, reqBody []byte, resp *http.Response, respBody []byte, elapsed time.Duration) {
	now := time.Now()

	entry := Entry{
		StartedDateTime: now.Add(-elapsed).Format(time.RFC3339Nano),
		Time:            float64(elapsed.Milliseconds()),
		Request:         w.buildRequest(req, reqBody),
		Response:        w.buildResponse(resp, respBody),
		Timings:         buildTimings(elapsed),
	}

	w.mu.Lock()
	w.entries = append(w.entries, entry)
	w.mu.Unlock()
}

func (w *Writer) RecordError(req *http.Request, reqBody []byte, statusCode int, errorText string, elapsed time.Duration) {
	now := time.Now()

	resp := Response{
		Status:      statusCode,
		StatusText:  http.StatusText(statusCode),
		HTTPVersion: "HTTP/1.1",
		Headers:     []NameValue{},
		Content:     Content{Size: len(errorText), MimeType: "text/plain", Text: errorText},
		HeadersSize: -1,
		BodySize:    len(errorText),
	}

	entry := Entry{
		StartedDateTime: now.Add(-elapsed).Format(time.RFC3339Nano),
		Time:            float64(elapsed.Milliseconds()),
		Request:         w.buildRequest(req, reqBody),
		Response:        resp,
		Timings:         buildTimings(elapsed),
	}

	w.mu.Lock()
	w.entries = append(w.entries, entry)
	w.mu.Unlock()
}

func (w *Writer) RecordUpgrade(req *http.Request, elapsed time.Duration) {
	now := time.Now()

	resp := Response{
		Status:      http.StatusSwitchingProtocols,
		StatusText:  "Switching Protocols",
		HTTPVersion: "HTTP/1.1",
		Headers: []NameValue{
			{Name: "Upgrade", Value: "websocket"},
			{Name: "Connection", Value: "Upgrade"},
		},
		Content:     Content{Size: 0, MimeType: "application/octet-stream"},
		HeadersSize: -1,
		BodySize:    0,
	}

	entry := Entry{
		StartedDateTime: now.Add(-elapsed).Format(time.RFC3339Nano),
		Time:            float64(elapsed.Milliseconds()),
		Request:         w.buildRequest(req, nil),
		Response:        resp,
		Timings:         buildTimings(elapsed),
	}

	w.mu.Lock()
	w.entries = append(w.entries, entry)
	w.mu.Unlock()
}

func (w *Writer) Flush(path string) error {
	w.mu.Lock()
	entries := make([]Entry, len(w.entries))
	copy(entries, w.entries)
	w.mu.Unlock()

	harFile := HARFile{
		Log: Log{
			Version: "1.2",
			Creator: Creator{
				Name:    "blinder",
				Version: "2.0.0",
			},
			Entries: entries,
		},
	}

	data, err := json.MarshalIndent(harFile, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal HAR: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".blinder-har-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp: %w", err)
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename: %w", err)
	}

	return nil
}

func (w *Writer) buildRequest(req *http.Request, body []byte) Request {
	r := Request{
		Method:      req.Method,
		URL:         req.URL.String(),
		HTTPVersion: req.Proto,
		Headers:     headersToList(req.Header),
		QueryString: queryToList(req.URL),
		HeadersSize: -1,
		BodySize:    len(body),
	}

	if len(body) > 0 {
		ct := req.Header.Get("Content-Type")
		if ct == "" {
			ct = "application/octet-stream"
		}
		text, encoding, comment := w.captureBody(body, isTextContent(ct))
		r.PostData = &PostData{MimeType: ct, Text: text, Encoding: encoding, Comment: comment}
	}

	return r
}

func (w *Writer) buildResponse(resp *http.Response, body []byte) Response {
	r := Response{
		Status:      resp.StatusCode,
		StatusText:  extractStatusText(resp.Status),
		HTTPVersion: resp.Proto,
		Headers:     headersToList(resp.Header),
		HeadersSize: -1,
		BodySize:    len(body),
	}

	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}

	r.Content = Content{
		Size:     len(body),
		MimeType: ct,
	}

	if len(body) == 0 {
		return r
	}

	r.Content.Text, r.Content.Encoding, r.Content.Comment = w.captureBody(body, isTextContent(ct))

	return r
}

func (w *Writer) captureBody(body []byte, textContent bool) (text, encoding, comment string) {
	captured := body
	textContent = textContent && utf8.Valid(body)
	if int64(len(captured)) > w.maxBodySize {
		captured = captured[:w.maxBodySize]
		if textContent {
			// Do not introduce replacement runes by cutting a UTF-8 character.
			for !utf8.Valid(captured) {
				captured = captured[:len(captured)-1]
			}
		}
		comment = fmt.Sprintf("truncated: captured %d of %d bytes (limit %d)", len(captured), len(body), w.maxBodySize)
	}
	if textContent {
		return string(captured), "", comment
	}
	return base64.StdEncoding.EncodeToString(captured), "base64", comment
}

func buildTimings(elapsed time.Duration) Timings {
	ms := float64(elapsed.Milliseconds())
	return Timings{
		Send:    0,
		Wait:    ms,
		Receive: 0,
	}
}

func headersToList(h http.Header) []NameValue {
	var result []NameValue
	for name, values := range h {
		for _, v := range values {
			result = append(result, NameValue{Name: name, Value: v})
		}
	}
	if result == nil {
		result = []NameValue{}
	}
	return result
}

func queryToList(u *url.URL) []NameValue {
	var result []NameValue
	for name, values := range u.Query() {
		for _, v := range values {
			result = append(result, NameValue{Name: name, Value: v})
		}
	}
	if result == nil {
		result = []NameValue{}
	}
	return result
}

func extractStatusText(status string) string {
	parts := strings.SplitN(status, " ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func isTextContent(ct string) bool {
	ct = strings.ToLower(ct)
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = ct[:idx]
	}
	ct = strings.TrimSpace(ct)

	if strings.HasPrefix(ct, "text/") {
		return true
	}

	textTypes := []string{
		"application/x-www-form-urlencoded",
		"application/json",
		"application/javascript",
		"application/xml",
		"application/xhtml+xml",
	}
	for _, tt := range textTypes {
		if ct == tt {
			return true
		}
	}

	if strings.HasSuffix(ct, "+json") || strings.HasSuffix(ct, "+xml") {
		return true
	}

	if !utf8.Valid([]byte(ct)) {
		return false
	}

	return false
}
