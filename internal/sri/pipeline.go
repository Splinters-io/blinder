package sri

import (
	"bytes"
	"compress/gzip"
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
	Request *http.Request
	Status  int
	Headers http.Header
	Body    []byte
	Elapsed time.Duration
	Error   string
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
}

type PipelineConfig struct {
	Transport       http.RoundTripper
	ScrubFn         ScrubFunc
	Cache           *Cache
	IsAllowedOrigin func(u *url.URL) bool
	OnFetch         func(FetchRecord)
	CookieRestoreFn func(cookieHeader string) string
}

type Pipeline struct {
	transport       http.RoundTripper
	scrubFn         ScrubFunc
	cache           *Cache
	isAllowedOrigin func(u *url.URL) bool
	onFetch         func(FetchRecord)
	cookieRestoreFn func(cookieHeader string) string

	mu       sync.Mutex
	findings []Finding
}

func NewPipeline(cfg PipelineConfig) *Pipeline {
	return &Pipeline{
		transport:       cfg.Transport,
		scrubFn:         cfg.ScrubFn,
		cache:           cfg.Cache,
		isAllowedOrigin: cfg.IsAllowedOrigin,
		onFetch:         cfg.OnFetch,
		cookieRestoreFn: cfg.CookieRestoreFn,
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

	cacheKey := CacheKey(resourceURL, baseReq)

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

	sameOrig := isSameOrigin(parsedURL, pageOrigin)
	sendCreds := sameOrig

	body, respCT, respHeaders, fetchErr := p.fetch(resourceURL, sendCreds, baseReq)
	if fetchErr != nil {
		cached := &CacheEntry{FetchError: fetchErr.Error()}
		p.cache.Put(cacheKey, cached)
		p.recordFinding(resourceURL, false, fetchErr.Error(), integrityAttr, "", false)
		return &ProcessResult{UpstreamError: fetchErr.Error()}
	}

	p.cache.IndexDigest(cacheKey, body)
	digests := computeAllDigests(body)

	if respCT == "" {
		respCT = contentType
	}

	scrubbed := p.scrubFn(body, respCT, resourceURL)
	modified := !bytes.Equal(body, scrubbed)

	strongest := StrongestAlgorithm(entries)
	replacementHash := ComputeIntegrity(scrubbed, strongest)

	cached := &CacheEntry{
		ScrubbedBody:    scrubbed,
		ReplacementHash: replacementHash,
		ContentType:     respCT,
		BytesModified:   modified,
		ResponseHeaders: respHeaders,
		OriginalDigests: digests,
	}
	p.cache.Put(cacheKey, cached)

	return p.verifyAgainstCached(cached, entries, integrityAttr, resourceURL)
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

func (p *Pipeline) fetch(resourceURL string, sendCreds bool, baseReq *http.Request) ([]byte, string, http.Header, error) {
	req, err := http.NewRequestWithContext(baseReq.Context(), "GET", resourceURL, nil)
	if err != nil {
		p.recordFetchEvent(req, 0, nil, nil, 0, fmt.Sprintf("build request: %v", err))
		return nil, "", nil, fmt.Errorf("build request: %w", err)
	}

	if sendCreds {
		if cookie := baseReq.Header.Get("Cookie"); cookie != "" {
			restored := cookie
			if p.cookieRestoreFn != nil {
				restored = p.cookieRestoreFn(cookie)
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
		p.recordFetchEvent(req, 0, nil, nil, elapsed, fmt.Sprintf("fetch: %v", err))
		return nil, "", nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		elapsed := time.Since(start)
		p.recordFetchEvent(req, resp.StatusCode, resp.Header.Clone(), nil, elapsed, fmt.Sprintf("fetch status %d", resp.StatusCode))
		return nil, "", nil, fmt.Errorf("fetch status %d", resp.StatusCode)
	}

	var reader io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			elapsed := time.Since(start)
			p.recordFetchEvent(req, resp.StatusCode, resp.Header.Clone(), nil, elapsed, fmt.Sprintf("gzip decode: %v", err))
			return nil, "", nil, fmt.Errorf("gzip decode: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	body, err := io.ReadAll(io.LimitReader(reader, maxFetchSize+1))
	if err != nil {
		elapsed := time.Since(start)
		p.recordFetchEvent(req, resp.StatusCode, resp.Header.Clone(), body, elapsed, fmt.Sprintf("read body: %v", err))
		return nil, "", nil, fmt.Errorf("read body: %w", err)
	}
	if len(body) > maxFetchSize {
		elapsed := time.Since(start)
		p.recordFetchEvent(req, resp.StatusCode, resp.Header.Clone(), nil, elapsed, fmt.Sprintf("resource too large (>%d bytes)", maxFetchSize))
		return nil, "", nil, fmt.Errorf("resource too large (>%d bytes)", maxFetchSize)
	}

	elapsed := time.Since(start)
	p.recordFetchEvent(req, resp.StatusCode, resp.Header.Clone(), body, elapsed, "")

	ct := resp.Header.Get("Content-Type")
	headers := resp.Header.Clone()
	headers.Del("Content-Encoding")
	headers.Del("Transfer-Encoding")

	return body, ct, headers, nil
}

func (p *Pipeline) recordFetchEvent(req *http.Request, status int, headers http.Header, body []byte, elapsed time.Duration, errText string) {
	if p.onFetch == nil {
		return
	}
	p.onFetch(FetchRecord{
		Request: req,
		Status:  status,
		Headers: headers,
		Body:    body,
		Elapsed: elapsed,
		Error:   errText,
	})
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
