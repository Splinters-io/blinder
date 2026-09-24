package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Splinters-io/blinder/internal/cache"
	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/har"
	"github.com/Splinters-io/blinder/internal/manifest"
	"github.com/Splinters-io/blinder/internal/rewriter"
	"github.com/Splinters-io/blinder/internal/scrub"
	"github.com/Splinters-io/blinder/internal/sri"
	blindertls "github.com/Splinters-io/blinder/internal/tls"
	"github.com/Splinters-io/blinder/internal/ws"
)

const maxRequestBody = 50 * 1024 * 1024
const maxResponseBody = 50 * 1024 * 1024

type Stats struct {
	Requests atomic.Int64
	Bytes    atomic.Int64
	Errors   atomic.Int64
	Scrubbed atomic.Int64
}

type Server struct {
	cfg         *config.Config
	gate        *scrub.Gate
	origins     *rewriter.OriginMapper
	transport   http.RoundTripper
	server      *http.Server
	wsProxy     *ws.Proxy
	harWriter   *har.Writer
	manifest    *manifest.Session
	sriCache      *sri.Cache
	sriPipeline   *sri.Pipeline
	responseCache *cache.ResponseCache
	stats         Stats
	done          chan struct{}
}

func New(cfg *config.Config) (*Server, error) {
	localTLS, err := blindertls.Prepare(cfg.CertDir, cfg.AliasDomain, cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("local TLS: %w", err)
	}
	return NewWithCertificate(cfg, localTLS.Certificate)
}

// NewWithCertificate uses the exact identity inspected during CLI preflight.
func NewWithCertificate(cfg *config.Config, cert tls.Certificate) (*Server, error) {
	targetHost := cfg.TargetURL.Hostname()
	targetDomains := append([]string{targetHost}, extractSubdomains(targetHost)...)
	for _, extra := range cfg.ExtraOrigins {
		extraHost := extra.Hostname()
		targetDomains = append(targetDomains, extraHost)
		targetDomains = append(targetDomains, extractSubdomains(extraHost)...)
	}

	gate := scrub.NewGate(targetDomains, cfg.IdentityTokens, cfg.AliasDomain)

	var extraRoutes []rewriter.OriginRoute
	seenAliases := map[string]string{cfg.AliasDomain: cfg.TargetURL.Host}
	for _, extra := range cfg.ExtraOrigins {
		alias := scrub.AliasOrigin(extra.Scheme, extra.Hostname(), extra.Port(), cfg.AliasDomain)
		if prev, ok := seenAliases[alias]; ok {
			return nil, fmt.Errorf("alias collision: %s and %s both map to %s", prev, extra.Host, alias)
		}
		seenAliases[alias] = extra.Host
		extraRoutes = append(extraRoutes, rewriter.OriginRoute{Upstream: extra, Alias: alias})
	}
	origins := rewriter.NewOriginMapper(cfg.TargetURL, cfg.ListenAddr, cfg.AliasDomain, extraRoutes...)

	upstreamTimeout := time.Duration(cfg.UpstreamTimeout) * time.Second

	var transport http.RoundTripper
	if cfg.UseTor() {
		t, err := NewTorTransport(cfg.Tor.SOCKSAddr, cfg.VerifyTargetTLS, upstreamTimeout)
		if err != nil {
			return nil, fmt.Errorf("tor transport: %w", err)
		}
		transport = t
	} else {
		transport = NewDirectTransport(cfg.VerifyTargetTLS, upstreamTimeout)
	}

	var socksAddr string
	if cfg.UseTor() {
		socksAddr = cfg.Tor.SOCKSAddr
	}

	wsProxy := ws.NewProxy(
		gate,
		cfg.AliasDomain,
		cfg.TargetURL.Host,
		cfg.TargetURL.Host,
		cfg.TargetURL.Scheme == "https",
		cfg.VerifyTargetTLS,
		socksAddr,
		5*time.Minute,
		origins,
	)

	var harWriter *har.Writer
	if cfg.HAR != nil {
		harWriter = har.NewWriter(cfg.HAR.FilePath, cfg.HAR.MaxBodySize, 0)
	}

	session := manifest.NewSession(cfg.AliasDomain, cfg.TargetURL.String())

	sriCache := sri.NewCache(256)

	scrubFn := func(body []byte, contentType, path string) []byte {
		result := rewriter.RewriteBody(body, contentType, path, gate, cfg.Paranoid)
		return result.Body
	}

	sriCfg := sri.PipelineConfig{
		Transport: transport,
		ScrubFn:   scrubFn,
		Cache:     sriCache,
		IsAllowedOrigin: func(u *url.URL) bool {
			return origins.IsKnownFullOrigin(u)
		},
		CookieRestoreFn: func(cookieHeader string) string {
			return gate.RestoreCookieHeader(cookieHeader)
		},
	}

	if harWriter != nil {
		sriCfg.OnFetch = func(rec sri.FetchRecord) {
			if rec.Request == nil {
				return
			}
			if rec.Error != "" {
				harWriter.RecordFetchFailure(rec.Request, rec.Status, rec.Headers, rec.Body, rec.Error, rec.Elapsed)
				return
			}
			resp := &http.Response{
				StatusCode: rec.Status,
				Status:     fmt.Sprintf("%d %s", rec.Status, http.StatusText(rec.Status)),
				Header:     rec.Headers,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
			}
			harWriter.Record(rec.Request, nil, resp, rec.Body, rec.Elapsed)
		}
	}

	sriPipeline := sri.NewPipeline(sriCfg)

	s := &Server{
		cfg:           cfg,
		gate:          gate,
		origins:       origins,
		transport:     transport,
		wsProxy:       wsProxy,
		harWriter:     harWriter,
		manifest:      session,
		sriCache:      sriCache,
		sriPipeline:   sriPipeline,
		responseCache: cache.New(4096),
		done:          make(chan struct{}),
	}

	if harWriter != nil && cfg.HAR != nil {
		go s.periodicHARFlush()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	clientTimeout := time.Duration(cfg.ClientTimeout) * time.Second

	s.server = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  clientTimeout,
		WriteTimeout: clientTimeout,
		IdleTimeout:  120 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	return s, nil
}

func (s *Server) ListenAndServe() error {
	return s.server.ListenAndServeTLS("", "")
}

func (s *Server) Addr() string {
	return s.server.Addr
}

func (s *Server) ListenAndServeOnListener(ln net.Listener) error {
	tlsLn := tls.NewListener(ln, s.server.TLSConfig)
	return s.server.Serve(tlsLn)
}

func (s *Server) Shutdown(ctx context.Context) error {
	close(s.done)
	s.wsProxy.Close()
	return s.server.Shutdown(ctx)
}

func (s *Server) Gate() *scrub.Gate {
	return s.gate
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handleRequest(w, r)
}

func (s *Server) GetStats() (requests, bytes, errors, scrubbed int64) {
	return s.stats.Requests.Load(),
		s.stats.Bytes.Load(),
		s.stats.Errors.Load(),
		s.stats.Scrubbed.Load()
}

func (s *Server) FlushHAR() error {
	if s.harWriter == nil {
		return nil
	}
	return s.harWriter.Flush()
}

func (s *Server) FlushManifest() error {
	if s.cfg.OutputDir == "" {
		return nil
	}

	for alias, real := range s.gate.Aliases() {
		s.manifest.RecordDomainAlias(real, alias)
	}

	var findings []manifest.LeakEntry
	for _, leak := range s.gate.Leaks() {
		for i := 0; i < leak.Count; i++ {
			findings = append(findings, manifest.LeakEntry{Type: leak.Type, Context: leak.Context, Value: leak.Detail})
		}
	}
	s.manifest.ReplaceLeaks(findings)

	for _, f := range s.sriPipeline.Findings() {
		s.manifest.RecordSRIFinding(f.URL, f.UpstreamValid, f.UpstreamError, f.OriginalIntegrity, f.ReplacementHash, f.Transformed)
	}

	return s.manifest.Flush(s.cfg.OutputDir)
}

func (s *Server) Manifest() *manifest.Session {
	return s.manifest
}

func (s *Server) ClearSRICache() {
	s.sriCache.Clear()
}

func (s *Server) ResponseCache() *cache.ResponseCache {
	return s.responseCache
}

func (s *Server) SRIFindings() []sri.Finding {
	return s.sriPipeline.Findings()
}

func (s *Server) periodicHARFlush() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if s.harWriter != nil {
				if err := s.harWriter.FlushJournal(); err != nil {
					log.Printf("[error] periodic HAR flush: %v", err)
				}
			}
		case <-s.done:
			return
		}
	}
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	s.stats.Requests.Add(1)

	if ws.IsUpgrade(r) {
		wsStart := time.Now()
		err := s.wsProxy.Handle(w, r)
		wsElapsed := time.Since(wsStart)
		if s.harWriter != nil {
			if err != nil {
				s.harWriter.RecordError(r, nil, http.StatusBadGateway, err.Error(), wsElapsed)
			} else {
				s.harWriter.RecordUpgrade(r, wsElapsed)
			}
		}
		if err != nil {
			log.Printf("[error] websocket: %v", err)
			s.stats.Errors.Add(1)
		}
		return
	}

	gate := s.gate.ForRequest()
	status := http.StatusOK
	var leakCount int
	defer func() {
		s.manifest.RecordRequest(r.URL.Path, status, gate.ReplacementCount(), leakCount)
	}()

	if r.ContentLength > maxRequestBody {
		status = http.StatusRequestEntityTooLarge
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		s.stats.Errors.Add(1)
		return
	}

	var reqBodyBuf []byte
	if r.Body != nil {
		var readErr error
		reqBodyBuf, readErr = io.ReadAll(io.LimitReader(r.Body, maxRequestBody+1))
		if readErr != nil {
			status = http.StatusBadRequest
			http.Error(w, "request read error", http.StatusBadRequest)
			s.stats.Errors.Add(1)
			return
		}
		if int64(len(reqBodyBuf)) > maxRequestBody {
			status = http.StatusRequestEntityTooLarge
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			s.stats.Errors.Add(1)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(reqBodyBuf))
	}

	upstream := s.origins.Resolve(r.Host)
	if upstream == nil {
		upstream = s.cfg.TargetURL
	}

	upstreamURL := upstream.Scheme + "://" + upstream.Host + r.URL.RequestURI()
	cacheable := r.Method == http.MethodGet || r.Method == http.MethodHead

	// --- SRI cache (GET only, pre-fetched resources) ---
	if r.Method == http.MethodGet {
		if served := s.tryServeSRICache(w, r, upstreamURL, gate); served {
			return
		}
	}

	// --- Response cache: conditional and fresh-hit paths ---
	var staleCacheKey string
	var staleEntry *cache.Entry
	if cacheable {
		hasCreds := cache.HasCredentials(r)
		cacheKey := cache.Key(upstreamURL, hasCreds, r, nil)
		if cached, ok := s.responseCache.Lookup(cacheKey); ok {
			if len(cached.VaryFields) > 0 {
				cacheKey = cache.Key(upstreamURL, hasCreds, r, cached.VaryFields)
				cached, ok = s.responseCache.Lookup(cacheKey)
			}
			if ok {
				inm := r.Header.Get("If-None-Match")
				if cached.IsFresh() {
					if cache.MatchesETag(inm, cached.ETag) {
						w.Header().Set("ETag", cached.ETag)
						status = http.StatusNotModified
						w.WriteHeader(http.StatusNotModified)
						return
					}
					s.writeCachedResponse(w, &cached, r.Method == http.MethodHead)
					status = cached.StatusCode
					return
				}
				staleCacheKey = cacheKey
				staleEntry = &cached
			}
		}
	}

	// --- Forward to upstream ---
	upstreamReq := rewriter.RewriteRequestHeaders(r, upstream.Host, gate, s.origins)
	upstreamReq.URL.Scheme = upstream.Scheme
	upstreamReq.URL.Host = upstream.Host
	upstreamReq.RequestURI = ""

	if cacheable && staleEntry != nil {
		if staleEntry.UpstreamETag != "" {
			upstreamReq.Header.Set("If-None-Match", staleEntry.UpstreamETag)
		}
		if staleEntry.UpstreamLastModified != "" {
			upstreamReq.Header.Set("If-Modified-Since", staleEntry.UpstreamLastModified)
		}
	}

	requestStart := time.Now()
	upstreamCtx, cancel := context.WithTimeout(upstreamReq.Context(), time.Duration(s.cfg.UpstreamTimeout)*time.Second)
	defer cancel()
	upstreamReq = upstreamReq.WithContext(upstreamCtx)

	resp, err := s.transport.RoundTrip(upstreamReq)
	if err != nil {
		status = http.StatusBadGateway
		elapsed := time.Since(requestStart)
		log.Printf("[error] upstream: %v", err)
		if s.harWriter != nil {
			s.harWriter.RecordError(upstreamReq, reqBodyBuf, http.StatusBadGateway, err.Error(), elapsed)
		}
		http.Error(w, "upstream error", http.StatusBadGateway)
		s.stats.Errors.Add(1)
		return
	}
	defer resp.Body.Close()

	elapsed := time.Since(requestStart)

	// --- Upstream 304: revalidation confirmed cached content is current ---
	if resp.StatusCode == http.StatusNotModified && staleEntry != nil {
		if s.harWriter != nil {
			s.harWriter.Record(upstreamReq, reqBodyBuf, resp, nil, elapsed)
		}
		s.responseCache.Touch(staleCacheKey)
		inm := r.Header.Get("If-None-Match")
		if cache.MatchesETag(inm, staleEntry.ETag) {
			w.Header().Set("ETag", staleEntry.ETag)
			status = http.StatusNotModified
			w.WriteHeader(http.StatusNotModified)
			return
		}
		s.writeCachedResponse(w, staleEntry, r.Method == http.MethodHead)
		status = staleEntry.StatusCode
		return
	}

	body, err := s.readResponseBody(resp)
	if err != nil {
		status = http.StatusBadGateway
		log.Printf("[error] reading body: %v", err)
		if s.harWriter != nil {
			s.harWriter.RecordError(upstreamReq, reqBodyBuf, http.StatusBadGateway, err.Error(), elapsed)
		}
		http.Error(w, "upstream error", http.StatusBadGateway)
		s.stats.Errors.Add(1)
		return
	}

	if s.harWriter != nil {
		s.harWriter.Record(upstreamReq, reqBodyBuf, resp, body, elapsed)
	}

	s.stats.Bytes.Add(int64(len(body)))

	contentType := resp.Header.Get("Content-Type")
	path := r.URL.Path

	docURL := &url.URL{
		Scheme: upstream.Scheme,
		Host:   upstream.Host,
		Path:   r.URL.Path,
	}
	result := rewriter.RewriteBody(body, contentType, path, gate, s.cfg.Paranoid, rewriter.RewriteOpts{
		Origins:      s.origins,
		SRIPipeline:  s.sriPipeline,
		UpstreamBase: docURL,
		BaseRequest:  r,
	})
	s.stats.Scrubbed.Add(1)
	leakCount = gate.ResidualLeakCount(string(result.Body))

	outHeaders := rewriter.RewriteResponseHeaders(
		resp.Header,
		gate,
		s.cfg.AliasDomain,
		s.cfg.TargetURL.Host,
		rewriter.ResponseHeaderOpts{
			OriginMapper:  s.origins,
			RequestOrigin: r.Header.Get("Origin"),
		},
	)

	etag := cache.ComputeETag(result.Body)

	// Store in response cache for cacheable 200 responses.
	if cacheable && resp.StatusCode == http.StatusOK {
		varyFields := cache.ParseVary(resp.Header.Get("Vary"))
		if len(varyFields) == 0 || varyFields[0] != "*" {
			dirs := cache.ParseDirectives(resp.Header.Get("Cache-Control"))
			hasCreds := cache.HasCredentials(r)
			cacheKey := cache.Key(upstreamURL, hasCreds, r, varyFields)
			s.responseCache.Store(cacheKey, cache.Entry{
				Body:                 append([]byte(nil), result.Body...),
				StatusCode:           resp.StatusCode,
				Headers:              outHeaders.Clone(),
				ContentType:          contentType,
				ETag:                 etag,
				UpstreamETag:         resp.Header.Get("ETag"),
				UpstreamLastModified: resp.Header.Get("Last-Modified"),
				VaryFields:           varyFields,
				VaryValues:           cache.CaptureVaryValues(r, varyFields),
				HasCredentials:       hasCreds,
				Directives:           dirs,
				StoredAt:             time.Now(),
			})
		}
	}

	for name, values := range outHeaders {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}

	w.Header().Set("ETag", etag)

	if result.Metadata != nil {
		meta := *result.Metadata
		meta.Producer = gate.Scrub(meta.Producer, "metadata:producer")
		meta.PDFVersion = gate.Scrub(meta.PDFVersion, "metadata:pdf-version")
		meta.FtypBrand = gate.Scrub(meta.FtypBrand, "metadata:brand")
		meta.ChunkTypes = append([]string(nil), meta.ChunkTypes...)
		for i, chunk := range meta.ChunkTypes {
			meta.ChunkTypes[i] = gate.Scrub(chunk, "metadata:chunk")
		}
		w.Header().Set("X-Blinder-Meta", meta.TechnicalJSON())
		s.manifest.RecordIdentity(path, result.Metadata)
	}

	status = resp.StatusCode

	// Conditional match against the just-computed downstream ETag.
	if cacheable {
		inm := r.Header.Get("If-None-Match")
		if cache.MatchesETag(inm, etag) {
			status = http.StatusNotModified
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	if result.ContentType != "" {
		w.Header().Set("Content-Type", result.ContentType)
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(result.Body)))
	w.Header().Del("Content-Encoding")
	w.Header().Del("Transfer-Encoding")

	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		w.Write(result.Body)
	}
}

func (s *Server) tryServeSRICache(w http.ResponseWriter, r *http.Request, upstreamURL string, gate *scrub.Gate) bool {
	cacheKey := sri.CacheKey(upstreamURL, r)
	entry, ok := s.sriCache.Get(cacheKey)
	if !ok {
		return false
	}
	if entry.FetchError != "" {
		http.Error(w, "upstream integrity verification failed", http.StatusBadGateway)
		s.stats.Errors.Add(1)
		return true
	}

	etag := cache.ComputeETag(entry.ScrubbedBody)
	inm := r.Header.Get("If-None-Match")
	if cache.MatchesETag(inm, etag) {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return true
	}

	if entry.ResponseHeaders != nil {
		outHeaders := rewriter.RewriteResponseHeaders(
			entry.ResponseHeaders,
			gate,
			s.cfg.AliasDomain,
			s.cfg.TargetURL.Host,
			rewriter.ResponseHeaderOpts{
				OriginMapper:  s.origins,
				RequestOrigin: r.Header.Get("Origin"),
			},
		)
		for name, values := range outHeaders {
			for _, v := range values {
				w.Header().Add(name, v)
			}
		}
	}

	ct := entry.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(entry.ScrubbedBody)))
	w.Header().Del("Content-Encoding")
	w.Header().Del("Transfer-Encoding")
	w.WriteHeader(http.StatusOK)
	w.Write(entry.ScrubbedBody)
	s.stats.Scrubbed.Add(1)
	return true
}

func (s *Server) writeCachedResponse(w http.ResponseWriter, entry *cache.Entry, headOnly bool) {
	for name, values := range entry.Headers {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	w.Header().Set("ETag", entry.ETag)
	if entry.ContentType != "" {
		w.Header().Set("Content-Type", entry.ContentType)
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(entry.Body)))
	w.Header().Del("Content-Encoding")
	w.Header().Del("Transfer-Encoding")
	w.WriteHeader(entry.StatusCode)
	if !headOnly {
		w.Write(entry.Body)
	}
}

func (s *Server) readResponseBody(resp *http.Response) ([]byte, error) {
	var reader io.Reader = resp.Body

	encoding := strings.ToLower(strings.TrimSpace(strings.Join(resp.Header.Values("Content-Encoding"), ",")))
	switch encoding {
	case "", "identity":
	case "gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gzip decode: %w", err)
		}
		defer gz.Close()
		reader = gz
	default:
		return nil, fmt.Errorf("unsupported response encoding")
	}

	body, err := io.ReadAll(io.LimitReader(reader, maxResponseBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBody {
		return nil, fmt.Errorf("response body too large")
	}

	return body, nil
}

func extractSubdomains(host string) []string {
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return nil
	}
	var subs []string
	for i := 1; i < len(parts)-1; i++ {
		subs = append(subs, strings.Join(parts[i:], "."))
	}
	return subs
}
