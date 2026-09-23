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
		StartedDateTime: now.Format(time.RFC3339Nano),
		Time:            float64(elapsed.Milliseconds()),
		Request:         buildRequest(req, reqBody),
		Response:        w.buildResponse(resp, respBody),
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

func buildRequest(req *http.Request, body []byte) Request {
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
		r.PostData = &PostData{
			MimeType: ct,
			Text:     string(body),
		}
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

	if isTextContent(ct) {
		r.Content.Text = string(body)
	} else if int64(len(body)) > w.maxBodySize {
		truncated := body[:w.maxBodySize]
		r.Content.Text = base64.StdEncoding.EncodeToString(truncated)
		r.Content.Encoding = "base64"
		r.Content.Comment = fmt.Sprintf("truncated at %d bytes (max %d)", len(body), w.maxBodySize)
	} else {
		r.Content.Text = base64.StdEncoding.EncodeToString(body)
		r.Content.Encoding = "base64"
	}

	return r
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
