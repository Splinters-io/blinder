package har

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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
	Cache           struct{} `json:"cache"` // Required HAR object; no cache-event claims are inferred.
	Timings         Timings  `json:"timings"`
}

type Request struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []NameValue `json:"headers"`
	Cookies     []Cookie    `json:"cookies"`
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
	Cookies     []Cookie    `json:"cookies"`
	RedirectURL string      `json:"redirectURL"`
	Content     Content     `json:"content"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Expires  string `json:"expires,omitempty"`
	HTTPOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
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
	entries       []Entry
	mu            sync.Mutex
	flushMu       sync.Mutex
	maxBodySize   int64
	maxEntries    int
	captureBudget int
	path          string
	// Protected by flushMu. Once the HAR is committed, retire its journal before
	// any retry can append new evidence or materialize those records again.
	pendingJournal *journalRetirement
	retireJournal  func(path, backup string) error
}

func NewWriter(path string, maxBodySize int64, maxEntries int) *Writer {
	if maxBodySize <= 0 {
		maxBodySize = 10 * 1024 * 1024
	}
	if maxEntries <= 0 {
		maxEntries = 50000
	}
	return &Writer{
		path:        path,
		maxBodySize: maxBodySize,
		maxEntries:  maxEntries,
	}
}

func (w *Writer) SetCaptureBudget(n int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.captureBudget = n
}

func (w *Writer) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.entries)
}

type ResponseBodyInfo struct {
	EncodedBytes int64
	DecodedBytes *int64 // Optional observed count; -1 means unavailable.
}
type FetchFailureDetails struct {
	RequestBody  []byte
	EncodedBytes *int64
	DecodedBytes *int64
	// Preserve the actual status line when a response was received. Empty
	// protocol denotes unavailable evidence, including transport failures.
	HTTPVersion string
	StatusLine  string
}

func (w *Writer) Record(req *http.Request, reqBody []byte, resp *http.Response, respBody []byte, elapsed time.Duration, info ...ResponseBodyInfo) {
	now := time.Now()

	entry := Entry{
		StartedDateTime: now.Add(-elapsed).Format(time.RFC3339Nano),
		Time:            float64(elapsed.Milliseconds()),
		Request:         w.buildRequest(req, reqBody),
		Response:        w.buildResponse(resp, respBody),
		Timings:         buildTimings(elapsed),
	}

	if len(info) > 0 {
		entry.Response.BodySize = int(info[0].EncodedBytes)
		if info[0].DecodedBytes != nil {
			entry.Response.Content.Size = int(*info[0].DecodedBytes)
		}
	}
	w.mu.Lock()
	w.entries = append(w.entries, entry)
	overCap := len(w.entries) > w.maxEntries
	w.mu.Unlock()

	if overCap {
		w.FlushJournal()
	}
}

func (w *Writer) RecordError(req *http.Request, reqBody []byte, statusCode int, errorText string, elapsed time.Duration) {
	now := time.Now()

	resp := Response{
		Status:      statusCode,
		StatusText:  http.StatusText(statusCode),
		HTTPVersion: "HTTP/1.1",
		Headers:     []NameValue{},
		Cookies:     []Cookie{},
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
	overCap := len(w.entries) > w.maxEntries
	w.mu.Unlock()

	if overCap {
		w.FlushJournal()
	}
}

func (w *Writer) RecordUpgrade(req *http.Request, elapsed time.Duration) {
	now := time.Now()

	resp := Response{
		Status:      http.StatusSwitchingProtocols,
		Cookies:     []Cookie{},
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
	overCap := len(w.entries) > w.maxEntries
	w.mu.Unlock()

	if overCap {
		w.FlushJournal()
	}
}

func (w *Writer) RecordFetchFailure(req *http.Request, status int, headers http.Header, body []byte, errorText string, elapsed time.Duration, details ...FetchFailureDetails) {
	now := time.Now()

	statusText := ""
	if status > 0 {
		statusText = http.StatusText(status)
	}

	var headerList []NameValue
	if headers != nil {
		headerList = headersToList(headers)
	} else {
		headerList = []NameValue{}
	}

	ct := "application/octet-stream"
	if headers != nil {
		if h := headers.Get("Content-Type"); h != "" {
			ct = h
		}
	}

	content := Content{
		Size:     len(body),
		MimeType: ct,
		Comment:  errorText,
	}
	if len(body) > 0 {
		var truncation string
		content.Text, content.Encoding, truncation = w.captureBody(body, isTextContent(ct))
		if truncation != "" {
			content.Comment += "; " + truncation
		}
	}

	resp := Response{
		Status:      status,
		StatusText:  statusText,
		HTTPVersion: "",
		Headers:     headerList,
		Cookies:     cookiesToList((&http.Response{Header: headers}).Cookies()),
		RedirectURL: headers.Get("Location"),
		Content:     content,
		HeadersSize: -1,
		BodySize:    len(body),
	}

	entry := Entry{
		StartedDateTime: now.Add(-elapsed).Format(time.RFC3339Nano),
		Time:            float64(elapsed.Milliseconds()),
		Request:         w.buildRequest(req, nil),
		Response:        resp,
		Timings:         buildTimings(elapsed),
	}
	if len(details) > 0 {
		entry.Request = w.buildRequest(req, details[0].RequestBody)
		entry.Response.HTTPVersion = details[0].HTTPVersion
		if details[0].StatusLine != "" {
			entry.Response.StatusText = extractStatusText(details[0].StatusLine)
		}
		if details[0].EncodedBytes != nil {
			entry.Response.BodySize = int(*details[0].EncodedBytes)
		}
		if details[0].DecodedBytes != nil {
			entry.Response.Content.Size = int(*details[0].DecodedBytes)
		}
	}

	w.mu.Lock()
	w.entries = append(w.entries, entry)
	overCap := len(w.entries) > w.maxEntries
	w.mu.Unlock()

	if overCap {
		w.FlushJournal()
	}
}

func (w *Writer) FlushJournal() error {
	if w.path == "" {
		return nil
	}
	return w.flushMerge(w.path)
}

func (w *Writer) Flush() error {
	if w.path == "" {
		return nil
	}
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
	if err := w.flushMergeLocked(w.path); err != nil {
		return err
	}
	err := w.materialize(w.path)
	if err != nil && !errors.Is(err, ErrRecoveryIncomplete) {
		err = w.materialize(w.path)
	}
	return err
}

func (w *Writer) journalPath() string {
	return w.path + ".journal"
}

func (w *Writer) flushMerge(path string) error {
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
	return w.flushMergeLocked(path)
}

// flushMergeLocked and materialize share flushMu for the entire export. Record
// can still add in-memory entries while an export runs; journal appenders wait
// until that export has committed and retired its input journal.
func (w *Writer) flushMergeLocked(path string) (err error) {
	retirementErr := w.retireJournalLocked()
	if retirementErr != nil && !errors.Is(retirementErr, ErrRecoveryIncomplete) {
		return retirementErr
	}
	// A recovery warning means retirement succeeded. Persist newer evidence to
	// a fresh journal before surfacing the warning, including on shutdown.
	defer func() { err = errors.Join(err, retirementErr) }()
	w.mu.Lock()
	if len(w.entries) == 0 {
		w.mu.Unlock()
		return nil
	}
	snapshot := make([]Entry, len(w.entries))
	copy(snapshot, w.entries)
	snapshotLen := len(snapshot)
	w.mu.Unlock()

	jpath := w.journalPath()
	f, err := os.OpenFile(jpath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open journal: %w", err)
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return fmt.Errorf("restrict journal permissions: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("stat journal: %w", err)
	}
	initialSize := info.Size()

	enc := json.NewEncoder(f)
	var writeErr error
	if initialSize > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], initialSize-1); err != nil {
			writeErr = fmt.Errorf("read journal boundary: %w", err)
		} else if last[0] != '\n' {
			// A crash may leave a partial final record. Isolate it so the next
			// valid snapshot is recoverable rather than joined to corrupt JSON.
			if _, err := f.Write([]byte{'\n'}); err != nil {
				writeErr = fmt.Errorf("write journal boundary: %w", err)
			}
		}
	}
	if writeErr == nil {
		for _, e := range snapshot {
			if err := enc.Encode(e); err != nil {
				writeErr = fmt.Errorf("write journal: %w", err)
				break
			}
		}
	}
	if err := f.Close(); err != nil && writeErr == nil {
		writeErr = fmt.Errorf("close journal: %w", err)
	}
	if writeErr != nil {
		// The entire snapshot remains in memory on failure. Remove any prefix
		// appended to disk so retrying does not duplicate those entries.
		if err := os.Truncate(jpath, initialSize); err != nil {
			return fmt.Errorf("%w; journal rollback failed: %v", writeErr, err)
		}
		return writeErr
	}

	w.mu.Lock()
	remaining := make([]Entry, len(w.entries)-snapshotLen)
	copy(remaining, w.entries[snapshotLen:])
	w.entries = remaining
	w.mu.Unlock()

	return nil
}

func (w *Writer) FlushTo(path string) error {
	w.flushMu.Lock()
	defer w.flushMu.Unlock()

	w.mu.Lock()
	entries := make([]Entry, len(w.entries))
	copy(entries, w.entries)
	w.mu.Unlock()

	return writeHARFile(path, entries)
}

func writeHARFile(path string, entries []Entry) error {
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
		Cookies:     cookiesToList(req.Cookies()),
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
		Cookies:     cookiesToList(resp.Cookies()),
		RedirectURL: resp.Header.Get("Location"),
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

func cookiesToList(cookies []*http.Cookie) []Cookie {
	result := make([]Cookie, 0, len(cookies))
	for _, c := range cookies {
		cookie := Cookie{Name: c.Name, Value: c.Value, Path: c.Path, Domain: c.Domain, HTTPOnly: c.HttpOnly, Secure: c.Secure}
		if !c.Expires.IsZero() {
			cookie.Expires = c.Expires.Format(time.RFC3339)
		}
		result = append(result, cookie)
	}
	return result
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
