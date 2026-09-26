package sri

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxFetchSize = 16 * 1024 * 1024

type ScrubFunc func(body []byte, contentType, path string) []byte

type FetchRecord struct {
	HTTPVersion string
	StatusLine  string
	// Counts describe bytes observed while reading, not invented full sizes.
	// EncodedBytes is -1 if the transport already decompressed the body;
	// DecodedBytes is -1 if decoding could not begin.
	EncodedBytes int64
	DecodedBytes int64
	BodyComplete bool
	Request      *http.Request
	Status       int
	Headers      http.Header
	Body         []byte
	Elapsed      time.Duration
	Error        string
}

type Finding struct {
	URL               string
	UpstreamValid     bool
	UpstreamError     string
	OriginalIntegrity string
	ReplacementHash   string
	Transformed       bool
}

type ProcessResult struct {
	UpstreamValid      bool
	UpstreamError      string
	ReplacementHash    string
	BytesModified      bool
	VerificationFailed bool
	BodyVersion        string
}

type PipelineConfig struct {
	Transport       http.RoundTripper
	ScrubFn         ScrubFunc
	Cache           *Cache
	IsAllowedOrigin func(u *url.URL) bool
	OnFetch         func(FetchRecord)
	CookieRestoreFn func(cookieHeader, origin string) string
	FetchTimeout    time.Duration
}

type Pipeline struct {
	transport       http.RoundTripper
	scrubFn         ScrubFunc
	cache           *Cache
	isAllowedOrigin func(u *url.URL) bool
	onFetch         func(FetchRecord)
	cookieRestoreFn func(cookieHeader, origin string) string
	fetchTimeout    time.Duration

	mu       sync.Mutex
	findings []Finding
}

func NewPipeline(cfg PipelineConfig) *Pipeline {
	if cfg.FetchTimeout <= 0 {
		cfg.FetchTimeout = 30 * time.Second
	}
	return &Pipeline{
		transport:       cfg.Transport,
		scrubFn:         cfg.ScrubFn,
		cache:           cfg.Cache,
		isAllowedOrigin: cfg.IsAllowedOrigin,
		onFetch:         cfg.OnFetch,
		cookieRestoreFn: cfg.CookieRestoreFn,
		fetchTimeout:    cfg.FetchTimeout,
	}
}

func (p *Pipeline) Findings() []Finding {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Finding, len(p.findings))
	copy(out, p.findings)
	return out
}

func (p *Pipeline) Process(resourceURL, integrityAttr, contentType, crossorigin string, pageOrigin *url.URL, baseReq *http.Request) *ProcessResult {
	entries := ParseIntegrity(integrityAttr)
	if len(entries) == 0 {
		return nil
	}

	parsedURL, err := url.Parse(resourceURL)
	if err != nil {
		return &ProcessResult{UpstreamError: "invalid resource URL"}
	}
	if p.isAllowedOrigin != nil && parsedURL.Host != "" && !p.isAllowedOrigin(parsedURL) {
		return &ProcessResult{UpstreamError: "resource outside configured origins"}
	}

	canonicalURL := resourceURL
	if idx := strings.IndexByte(canonicalURL, '#'); idx >= 0 {
		canonicalURL = canonicalURL[:idx]
	}
	sameOrig := isSameOrigin(parsedURL, pageOrigin)
	sendCreds := sameOrig

	cacheKeyReq := baseReq
	if !sendCreds {
		cacheKeyReq = nil
	}
	cacheKey := CacheKey(canonicalURL, cacheKeyReq)

	if cached, ok := p.cache.Get(cacheKey); ok {
		if cached.FetchError != "" {
			return &ProcessResult{UpstreamError: cached.FetchError}
		}
		noStoreCached := cached.ResponseHeaders != nil &&
			strings.Contains(strings.ToLower(cached.ResponseHeaders.Get("Cache-Control")), "no-store")
		if !noStoreCached {
			return p.verifyAgainstCached(cached, entries, integrityAttr, resourceURL)
		}
	}

	cookieOrigin := ""
	if sendCreds {
		// A same-origin absolute URL may spell the host or default port
		// differently. Use the configured page route's cookie namespace, just
		// as the normal request path does, rather than the resource spelling.
		cookieOrigin = pageOrigin.Host
	}
	body, respCT, respHeaders, fetchErr := p.fetch(resourceURL, sendCreds, baseReq, cookieOrigin)
	if fetchErr != nil {
		cached := &CacheEntry{FetchError: fetchErr.Error()}
		p.cache.Put(cacheKey, cached)
		p.recordFinding(resourceURL, false, fetchErr.Error(), integrityAttr, "", false)
		return &ProcessResult{UpstreamError: fetchErr.Error()}
	}

	h := sha256.Sum256(body)
	bodyVersion := "bl" + hex.EncodeToString(h[:8])
	p.cache.IndexDigest(cacheKey+"\x01"+bodyVersion, body)

	digests := computeAllDigests(body)

	if respCT == "" {
		respCT = contentType
	}

	scrubbed := p.scrubFn(body, respCT, resourceURL)
	modified := !bytes.Equal(body, scrubbed)

	strongest := StrongestAlgorithm(entries)
	replacementHash := ComputeIntegrity(scrubbed, strongest)

	cached := &CacheEntry{
		ScrubbedBody:      scrubbed,
		ReplacementHash:   replacementHash,
		ContentType:       respCT,
		BytesModified:     modified,
		ResponseHeaders:   respHeaders,
		OriginalDigests:   digests,
		BodyVersion:       bodyVersion,
		OriginalBodyBytes: int64(len(body)),
		OriginalBodyKnown: true,
	}
	p.cache.Put(cacheKey, cached)

	result := p.verifyAgainstCached(cached, entries, integrityAttr, resourceURL)
	if result != nil {
		result.BodyVersion = bodyVersion
	}
	return result
}

func (p *Pipeline) verifyAgainstCached(cached *CacheEntry, entries []HashEntry, integrityAttr, resourceURL string) *ProcessResult {
	if !verifyDigests(cached.OriginalDigests, entries) {
		p.recordFinding(resourceURL, false, "upstream integrity verification failed", integrityAttr, "", false)
		return &ProcessResult{
			VerificationFailed: true,
		}
	}

	p.recordFinding(resourceURL, true, "", integrityAttr, cached.ReplacementHash, cached.BytesModified)
	return &ProcessResult{
		UpstreamValid:   true,
		ReplacementHash: cached.ReplacementHash,
		BytesModified:   cached.BytesModified,
		BodyVersion:     cached.BodyVersion,
	}
}

func verifyDigests(stored map[string][]byte, entries []HashEntry) bool {
	if len(entries) == 0 || len(stored) == 0 {
		return false
	}
	strongest := StrongestAlgorithm(entries)
	storedDigest, ok := stored[strongest]
	if !ok {
		return false
	}
	for _, e := range entries {
		if e.Algorithm != strongest {
			continue
		}
		if bytes.Equal(e.Digest, storedDigest) {
			return true
		}
	}
	return false
}

func (p *Pipeline) fetch(resourceURL string, sendCreds bool, baseReq *http.Request, cookieOrigin string) ([]byte, string, http.Header, error) {
	ctx, cancel := context.WithTimeout(baseReq.Context(), p.fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", resourceURL, nil)
	if err != nil {
		p.recordFetchEvent(req, nil, nil, fetchBodyRead{decodedBytes: -1}, 0, fmt.Sprintf("build request: %v", err))
		return nil, "", nil, fmt.Errorf("build request: %w", err)
	}

	if sendCreds {
		if cookie := baseReq.Header.Get("Cookie"); cookie != "" {
			restored := cookie
			if p.cookieRestoreFn != nil {
				restored = p.cookieRestoreFn(cookie, cookieOrigin)
			}
			req.Header.Set("Cookie", restored)
		}
		if auth := baseReq.Header.Get("Authorization"); auth != "" {
			req.Header.Set("Authorization", auth)
		}
	}
	req.Header.Set("Accept-Encoding", "gzip, identity")

	start := time.Now()
	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		elapsed := time.Since(start)
		p.recordFetchEvent(req, nil, nil, fetchBodyRead{decodedBytes: -1}, elapsed, fmt.Sprintf("fetch: %v", err))
		return nil, "", nil, fmt.Errorf("fetch: %w", err)
	}
	defer func() {
		cancel()
		resp.Body.Close()
	}()
	body, measured, err := readFetchBody(resp)
	if err != nil {
		elapsed := time.Since(start)
		p.recordFetchEvent(req, resp, body, measured, elapsed, err.Error())
		return nil, "", nil, err
	}
	if resp.StatusCode != http.StatusOK {
		elapsed := time.Since(start)
		p.recordFetchEvent(req, resp, body, measured, elapsed, fmt.Sprintf("fetch status %d", resp.StatusCode))
		return nil, "", nil, fmt.Errorf("fetch status %d", resp.StatusCode)
	}

	elapsed := time.Since(start)
	p.recordFetchEvent(req, resp, body, measured, elapsed, "")

	ct := resp.Header.Get("Content-Type")
	headers := resp.Header.Clone()
	headers.Del("Content-Encoding")
	headers.Del("Transfer-Encoding")

	return body, ct, headers, nil
}

type fetchBodyRead struct {
	encodedBytes, decodedBytes int64
	complete                   bool
}

type fetchCountingReader struct {
	io.Reader
	n int64
}

func (r *fetchCountingReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	r.n += int64(n)
	return n, err
}

func readFetchBody(resp *http.Response) (body []byte, measured fetchBodyRead, err error) {
	measured.decodedBytes = -1
	if resp.StatusCode < 200 || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		measured.decodedBytes, measured.complete = 0, true
		return nil, measured, nil
	}
	raw := &fetchCountingReader{Reader: resp.Body}
	defer func() {
		measured.encodedBytes = raw.n
		if resp.Uncompressed {
			measured.encodedBytes = -1
		}
	}()
	var reader io.Reader = raw
	encoding := strings.ToLower(strings.TrimSpace(strings.Join(resp.Header.Values("Content-Encoding"), ",")))
	switch encoding {
	case "", "identity":
	case "gzip":
		gz, decodeErr := gzip.NewReader(raw)
		if decodeErr != nil {
			return nil, measured, fmt.Errorf("gzip decode: %w", decodeErr)
		}
		defer gz.Close()
		reader = gz
	default:
		return nil, measured, fmt.Errorf("unsupported response encoding")
	}
	body, err = io.ReadAll(io.LimitReader(reader, maxFetchSize+1))
	measured.decodedBytes = int64(len(body))
	if len(body) > maxFetchSize {
		return body[:maxFetchSize], measured, fmt.Errorf("resource too large (>%d bytes)", maxFetchSize)
	}
	if err != nil {
		return body, measured, fmt.Errorf("read body: %w", err)
	}
	measured.complete = true
	return body, measured, nil
}

func (p *Pipeline) recordFetchEvent(req *http.Request, response *http.Response, body []byte, measured fetchBodyRead, elapsed time.Duration, errText string) {
	if p.onFetch == nil {
		return
	}
	rec := FetchRecord{
		Request:      req,
		Body:         body,
		Elapsed:      elapsed,
		Error:        errText,
		EncodedBytes: measured.encodedBytes,
		DecodedBytes: measured.decodedBytes,
		BodyComplete: measured.complete,
	}
	if response != nil {
		rec.HTTPVersion, rec.StatusLine = response.Proto, response.Status
		rec.Status, rec.Headers = response.StatusCode, response.Header.Clone()
	}
	p.onFetch(rec)
}

func computeAllDigests(data []byte) map[string][]byte {
	return map[string][]byte{
		"sha256": computeDigest(data, "sha256"),
		"sha384": computeDigest(data, "sha384"),
		"sha512": computeDigest(data, "sha512"),
	}
}

func (p *Pipeline) recordFinding(url string, valid bool, upstreamErr, original, replacement string, transformed bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.findings = append(p.findings, Finding{
		URL:               url,
		UpstreamValid:     valid,
		UpstreamError:     upstreamErr,
		OriginalIntegrity: original,
		ReplacementHash:   replacement,
		Transformed:       transformed,
	})
}

func isSameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}
