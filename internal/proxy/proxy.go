package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
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
	"github.com/Splinters-io/blinder/internal/captcha"
	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/endpoint"
	"github.com/Splinters-io/blinder/internal/formedit"
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

var revalidationPolicyHeaders = []string{
	"Cache-Control",
	"Content-Security-Policy",
	"Content-Security-Policy-Report-Only",
	"Referrer-Policy",
	"Permissions-Policy",
	"Strict-Transport-Security",
	"Cross-Origin-Resource-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Embedder-Policy",
	"X-Frame-Options",
}

type Stats struct {
	Requests atomic.Int64
	Bytes    atomic.Int64
	Errors   atomic.Int64
	Scrubbed atomic.Int64
}

type Server struct {
	cfg                  *config.Config
	gate                 *scrub.Gate
	origins              *rewriter.OriginMapper
	transport            http.RoundTripper
	server               *http.Server
	wsProxy              *ws.Proxy
	harWriter            *har.Writer
	manifest             *manifest.Session
	sriCache             *sri.Cache
	sriPipeline          *sri.Pipeline
	responseCache        *cache.ResponseCache
	versionRefs          *versionRegistry
	captchaMatcher       *captcha.Matcher
	captchaQueue         *captcha.ChallengeQueue
	captchaOperator      *captcha.OperatorHandler
	captchaOperatorToken string
	providerRoutes       *captcha.ProviderRoutes
	providerHandler      http.Handler
	stats                Stats
	done                 chan struct{}
}

func New(cfg *config.Config) (*Server, error) {
	var extraAliases []string
	if cfg.Captcha != nil && len(cfg.Captcha.Providers) > 0 {
		extraAliases = append(extraAliases, endpoint.ChallengeWildcard)
	}
	for _, u := range cfg.ExtraOrigins {
		extraAliases = append(extraAliases, scrub.AliasOrigin(u.Scheme, u.Hostname(), u.Port(), cfg.AliasDomain))
	}
	if cfg.UseTor() && cfg.Captcha != nil {
		listen := cfg.ListenAddr
		if host, port, err := net.SplitHostPort(listen); err == nil && port == "0" {
			listen = net.JoinHostPort(host, "443")
		}
		routes, err := captcha.NewProviderRoutes(captcha.NewMatcher(cfg.Captcha), "https", listen)
		if err != nil {
			return nil, err
		}
		extraAliases = append(extraAliases, routes.AliasHosts()...)
	}
	localTLS, err := blindertls.Prepare(cfg.CertDir, cfg.AliasDomain, cfg.ListenAddr, extraAliases...)
	if err != nil {
		return nil, fmt.Errorf("local TLS: %w", err)
	}
	return NewWithCertificate(cfg, localTLS.Certificate)
}

// NewWithCertificate uses the exact identity inspected during CLI preflight.
func NewWithCertificate(cfg *config.Config, cert tls.Certificate) (*Server, error) {
	if err := cfg.HAR.Validate(); err != nil {
		return nil, err
	}
	if err := validateOperatorEndpoint(cfg); err != nil {
		return nil, err
	}
	keyDir := cfg.VersionKeyDir
	if keyDir == "" {
		keyDir = cfg.CertDir
	}
	versionRefs, err := persistentVersionRegistry(1024, keyDir)
	if err != nil {
		return nil, fmt.Errorf("version signing key: %w", err)
	}
	targetHost := cfg.TargetURL.Hostname()
	targetDomains := append([]string{targetHost}, extractSubdomains(targetHost)...)
	for _, extra := range cfg.ExtraOrigins {
		extraHost := extra.Hostname()
		targetDomains = append(targetDomains, extraHost)
		targetDomains = append(targetDomains, extractSubdomains(extraHost)...)
	}

	gate := scrub.NewGate(targetDomains, cfg.IdentityTokens, cfg.AliasDomain)

	if cfg.Captcha != nil {
		var preserveDomains []string
		for _, p := range cfg.Captcha.Providers {
			if len(p.URLRegexes) > 0 {
				continue
			}
			for _, origin := range p.ResourceOrigins {
				if u, err := url.Parse(origin); err == nil && u.Hostname() != "" {
					preserveDomains = append(preserveDomains, u.Hostname())
				}
			}
		}
		if len(preserveDomains) > 0 {
			gate.PreserveDomains(preserveDomains)
		}
		if cfg.Captcha.Matcher != nil {
			gate.SetPreserveURLCheck(func(fullURL string) bool {
				u, err := url.Parse(fullURL)
				if err != nil {
					return false
				}
				return cfg.Captcha.Matcher.IsProviderResource(u)
			})
		}
	}

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
	origins, err := rewriter.NewOriginMapper(cfg.TargetURL, cfg.ListenAddr, cfg.AliasDomain, extraRoutes...)
	if err != nil {
		return nil, fmt.Errorf("origin mapper: %w", err)
	}

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
		harWriter = har.NewWriter(cfg.HAR.FilePath, cfg.HAR.MaxBodySize, cfg.HAR.MaxEntries)
		if cfg.HAR.CaptureBudget > 0 {
			harWriter.SetCaptureBudget(cfg.HAR.CaptureBudget)
		}
	}

	session := manifest.NewSession(cfg.AliasDomain, cfg.TargetURL.String())

	sriCache := sri.NewCache(256)

	scrubFn := func(body []byte, contentType, path string) []byte {
		result := rewriter.RewriteBody(body, contentType, path, gate, cfg.Paranoid, rewriter.RewriteOpts{Origins: origins})
		return result.Body
	}

	sriCfg := sri.PipelineConfig{
		Transport:    transport,
		ScrubFn:      scrubFn,
		Cache:        sriCache,
		ContentTag:   gate.ContentTag,
		FetchTimeout: upstreamTimeout,
		IsAllowedOrigin: func(u *url.URL) bool {
			return origins.IsKnownFullOrigin(u)
		},
		CookieRestoreFn: func(cookieHeader, origin string) string {
			return gate.RestoreCookieHeader(cookieHeader, origin)
		},
	}

	if harWriter != nil {
		sriCfg.OnFetch = func(rec sri.FetchRecord) {
			if rec.Request == nil {
				return
			}
			if rec.Error != "" {
				harWriter.RecordFetchFailure(rec.Request, rec.Status, rec.Headers, rec.Body, rec.Error, rec.Elapsed, har.FetchFailureDetails{HTTPVersion: rec.HTTPVersion, StatusLine: rec.StatusLine, EncodedBytes: &rec.EncodedBytes, DecodedBytes: &rec.DecodedBytes})
				return
			}
			resp := &http.Response{
				StatusCode: rec.Status,
				Status:     rec.StatusLine,
				Header:     rec.Headers,
				Proto:      rec.HTTPVersion,
			}
			harWriter.Record(rec.Request, nil, resp, rec.Body, rec.Elapsed, har.ResponseBodyInfo{EncodedBytes: rec.EncodedBytes, DecodedBytes: &rec.DecodedBytes})
		}
	}

	sriPipeline := sri.NewPipeline(scopeSRIRepresentation(sriCfg, origins, gate, cfg.Paranoid))

	var captchaCfg *captcha.Config
	if cfg.Captcha != nil {
		captchaCfg = cfg.Captcha
	} else {
		captchaCfg = &captcha.Config{}
	}

	matcher := captcha.NewMatcher(captchaCfg)
	matcher.SetPrimaryHost(cfg.TargetURL.Hostname())
	challengeQueue := captcha.NewChallengeQueue(10 * time.Minute)
	operatorHandler, operatorToken := captcha.NewOperatorHandler(challengeQueue, matcher, transport, cfg.UseTor())
	if _, port, _ := net.SplitHostPort(cfg.ListenAddr); port != "0" {
		if err := operatorHandler.SetOperatorOrigin(operatorOrigin(cfg.ListenAddr)); err != nil {
			return nil, err
		}
	}
	operatorHandler.SetResourceTimeout(upstreamTimeout)

	s := &Server{
		cfg:                  cfg,
		gate:                 gate,
		origins:              origins,
		transport:            transport,
		wsProxy:              wsProxy,
		harWriter:            harWriter,
		manifest:             session,
		sriCache:             sriCache,
		sriPipeline:          sriPipeline,
		responseCache:        cache.New(4096),
		versionRefs:          versionRefs,
		captchaMatcher:       matcher,
		captchaQueue:         challengeQueue,
		captchaOperator:      operatorHandler,
		captchaOperatorToken: operatorToken,
		done:                 make(chan struct{}),
	}
	if err := s.configureProviderRoutes("https"); err != nil {
		return nil, err
	}

	if harWriter != nil && cfg.HAR != nil {
		go s.periodicHARFlush()
	}

	clientTimeout := time.Duration(cfg.ClientTimeout) * time.Second

	s.server = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      s,
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
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return s.ListenAndServeOnListener(ln)
}

func (s *Server) Addr() string {
	return s.server.Addr
}

func (s *Server) ListenAndServeOnListener(ln net.Listener) error {
	if _, port, _ := net.SplitHostPort(s.cfg.ListenAddr); port == "0" {
		s.cfg.ListenAddr = ln.Addr().String()
		s.server.Addr = s.cfg.ListenAddr
		if err := s.captchaOperator.SetOperatorOrigin(operatorOrigin(s.cfg.ListenAddr)); err != nil {
			return err
		}
		if err := s.configureProviderRoutes("https"); err != nil {
			return err
		}
	}
	tlsLn := tls.NewListener(ln, s.server.TLSConfig)
	return s.server.Serve(tlsLn)
}

func (s *Server) Shutdown(ctx context.Context) error {
	close(s.done)
	s.wsProxy.Close()
	s.captchaQueue.Shutdown()
	return s.server.Shutdown(ctx)
}

func (s *Server) Gate() *scrub.Gate {
	return s.gate
}

func (s *Server) CaptchaOperatorToken() string {
	return s.captchaOperatorToken
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.routeRequest(w, r)
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
		s.handleWebSocket(w, r)
		return
	}

	gate := s.gate.ForRequest()
	status := http.StatusOK
	var leakCount int
	observed := newResponseObserver(w, r.Method)
	evidence := newRequestEvidence(s.manifest, gate, r)
	observed.requestID = evidence.entry.RequestID
	w = observed
	defer func() {
		if observed.status != 0 {
			status = observed.status
		}
		if observed.metrics.Source == "proxy" {
			observed.metrics.RewrittenBodyBytes = observed.writtenBytes
		}
		observed.finish()
		observed.metrics.ShortTextFallbacks = gate.ShortTextFallbackCount()
		evidence.entry.Path = r.URL.Path
		evidence.entry.StatusCode = status
		evidence.entry.ScrubCount = gate.ReplacementCount()
		evidence.entry.LeakCount = leakCount
		evidence.entry.Response = &observed.metrics
		s.manifest.RecordExchange(evidence.entry)
	}()

	upstream := s.origins.Resolve(r.Host)
	if upstream == nil {
		status = http.StatusMisdirectedRequest
		http.Error(w, "unknown proxy origin", status)
		return
	}
	requestOrigins := s.origins.ForRequestHost(r.Host)
	evidence.observeContext(gate, r, upstream)
	restoreSubmittedValue := func(value string) string {
		return rewriter.RestoreResourceValue(value, gate, requestOrigins)
	}
	observed.beforeFinalHeader = func(headers http.Header) {
		s.localizeResponseLocations(headers, r.Host, upstream)
	}
	// Restore issued path mappings before submission scoping, version checks
	// and cache keys. Preserve escaped segment boundaries just as WS does.
	rewriter.RestoreURLPath(r.URL, gate)

	if r.ContentLength > maxRequestBody {
		status = http.StatusRequestEntityTooLarge
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		s.stats.Errors.Add(1)
		return
	}

	var reqBodyBuf []byte
	if r.Body == nil {
		evidence.observeBody(gate, nil)
	}
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
		evidence.observeBody(gate, reqBodyBuf)
		ct := r.Header.Get("Content-Type")
		normCT := strings.ToLower(strings.TrimSpace(ct))
		if i := strings.IndexByte(normCT, ';'); i >= 0 {
			normCT = strings.TrimSpace(normCT[:i])
		}
		if strings.HasPrefix(normCT, "application/x-www-form-urlencoded") {
			restored, err := formedit.Rewrite(string(reqBodyBuf), restoreSubmittedValue, func(key string) bool {
				return s.captchaMatcher.SubmissionHasOpaqueFields(r, key, upstream.Hostname())
			})
			if err == nil {
				reqBodyBuf = []byte(restored)
			} // Preserve malformed encoding for the upstream's own error handling.
		} else if normCT == "application/json" || strings.HasSuffix(normCT, "+json") {
			opaqueKeys := s.opaqueJSONKeys(r, upstream.Hostname())
			restored, restoreErr := s.restoreJSONWithOpaqueKeys(gate, reqBodyBuf, opaqueKeys, restoreSubmittedValue)
			if restoreErr != nil {
				status = http.StatusBadRequest
				http.Error(w, "ambiguous request body", http.StatusBadRequest)
				return
			}
			reqBodyBuf = restored
		} else {
			reqBodyBuf = []byte(restoreSubmittedValue(string(reqBodyBuf)))
		}
		r.Body = io.NopCloser(bytes.NewReader(reqBodyBuf))
		r.ContentLength = int64(len(reqBodyBuf))
	}

	if rawQuery := r.URL.RawQuery; rawQuery != "" {
		if restored, err := formedit.Rewrite(rawQuery, restoreSubmittedValue, func(key string) bool {
			return s.captchaMatcher.SubmissionHasOpaqueFields(r, key, upstream.Hostname())
		}); err == nil {
			r.URL.RawQuery = restored
		}
	}

	var upstreamURL string
	var sriBodyVersion string

	blvHandled := false
	for _, v := range r.URL.Query()["__blv"] {
		ref, isProxy, found := s.versionRefs.VerifyAndLookup(v)
		if !isProxy {
			continue
		}
		if !found {
			status = http.StatusBadGateway
			http.Error(w, "resource version expired", http.StatusBadGateway)
			s.stats.Errors.Add(1)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			status = http.StatusBadGateway
			http.Error(w, "resource version expired", http.StatusBadGateway)
			s.stats.Errors.Add(1)
			return
		}
		parsed, err := url.Parse(ref.UpstreamURL)
		if err != nil {
			status = http.StatusBadGateway
			http.Error(w, "resource version expired", http.StatusBadGateway)
			s.stats.Errors.Add(1)
			return
		}
		if !sameOrigin(upstream, parsed) {
			status = http.StatusBadGateway
			http.Error(w, "resource version expired", http.StatusBadGateway)
			s.stats.Errors.Add(1)
			return
		}
		appQuery := r.URL.Query()
		blvVals := appQuery["__blv"]
		var remaining []string
		for _, qv := range blvVals {
			if qv != v {
				remaining = append(remaining, qv)
			}
		}
		if len(remaining) > 0 {
			appQuery["__blv"] = remaining
		} else {
			delete(appQuery, "__blv")
		}
		appURI := r.URL.EscapedPath()
		if encoded := appQuery.Encode(); encoded != "" {
			appURI += "?" + encoded
		}
		candidateURL := s.unaliasURL(upstream.Scheme + "://" + upstream.Host + appURI)
		parsedCandidate, parseErr := url.Parse(candidateURL)
		if parseErr != nil || parsedCandidate.Path != ref.Path || parsedCandidate.Query().Encode() != ref.Query {
			status = http.StatusBadGateway
			http.Error(w, "resource version expired", http.StatusBadGateway)
			s.stats.Errors.Add(1)
			return
		}
		upstream = &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}
		stripVersionBLV(r, v)
		upstreamURL = ref.UpstreamURL
		sriBodyVersion = ref.BodyVersion
		blvHandled = true
		break
	}
	if !blvHandled {
		upstreamURL = upstream.Scheme + "://" + upstream.Host + r.URL.RequestURI()
		if orig := s.unaliasURL(upstreamURL); orig != upstreamURL {
			upstreamURL = orig
		}
	}

	// --- SRI cache (GET only, pre-fetched resources) ---
	if r.Method == http.MethodGet {
		if served := s.tryServeSRICache(w, r, upstream, upstreamURL, sriBodyVersion, gate); served {
			return
		}
	}

	// --- Response cache: GET and HEAD read; only GET writes ---
	cacheable := r.Method == http.MethodGet || r.Method == http.MethodHead
	var staleCacheKey string
	var staleEntry *cache.Entry
	if cacheable && sriBodyVersion == "" {
		reqCC := cache.ParseDirectives(r.Header.Get("Cache-Control"))
		if !reqCC.NoCache {
			credHash := responseCacheCredentialHash(r)
			cacheKey := cache.Key(upstreamURL, credHash, r, nil)
			if cached, ok := s.responseCache.Lookup(cacheKey); ok {
				if cached.VarySentinel {
					variantKey := cache.Key(upstreamURL, credHash, r, cached.VaryFields)
					cached, ok = s.responseCache.Lookup(variantKey)
					if ok {
						cacheKey = variantKey
					}
				}
				if ok && !cached.VarySentinel {
					if cached.IsFresh() {
						original := int64(-1)
						if cached.OriginalBodyKnown {
							original = cached.OriginalBodyBytes
						}
						observed.representation("cache", original, int64(len(cached.Body)), cached.OriginalBodyTag)
						inm := r.Header.Get("If-None-Match")
						if cache.MatchesETag(inm, cached.ETag) {
							for name, values := range cached.Headers {
								for _, v := range values {
									w.Header().Add(name, v)
								}
							}
							if cached.UpstreamACAO != "" && s.origins != nil {
								w.Header().Set("Access-Control-Allow-Origin",
									s.origins.RewriteResponseOrigin(cached.UpstreamACAO, r.Header.Get("Origin")))
							}
							w.Header().Set("ETag", cached.ETag)
							w.Header().Del("Content-Length")
							w.Header().Del("Content-Encoding")
							w.Header().Del("Transfer-Encoding")
							status = http.StatusNotModified
							w.WriteHeader(http.StatusNotModified)
							return
						}
						s.writeCachedResponse(w, &cached, r.Method == http.MethodHead, r.Header.Get("Origin"))
						status = cached.StatusCode
						return
					}
					staleCacheKey = cacheKey
					staleEntry = &cached
				}
			}
		}
	}

	// --- Forward to upstream ---
	upstreamReq := rewriter.RewriteRequestHeaders(r, upstream.Host, gate, s.origins)
	upstreamReq.URL.Scheme = upstream.Scheme
	upstreamReq.URL.Host = upstream.Host
	upstreamReq.RequestURI = ""
	// Negotiate only encodings we decode ourselves, keeping both byte counts
	// observable instead of letting http.Transport silently decompress gzip.
	upstreamReq.Header.Set("Accept-Encoding", "gzip, identity")
	if parsed, err := url.Parse(upstreamURL); err == nil {
		upstreamReq.URL.Path = parsed.Path
		upstreamReq.URL.RawPath = parsed.RawPath
		upstreamReq.URL.RawQuery = parsed.RawQuery
	}

	if cacheable {
		upstreamReq.Header.Del("If-None-Match")
		upstreamReq.Header.Del("If-Modified-Since")
	}

	if staleEntry != nil {
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
		observed.metrics.Upstream = append(observed.metrics.Upstream, manifest.BodyRead{Error: "transport"})
		elapsed := time.Since(requestStart)
		log.Printf("[error] upstream: %v", err)
		if s.harWriter != nil {
			s.harWriter.RecordFetchFailure(upstreamReq, 0, nil, nil, err.Error(), elapsed, har.FetchFailureDetails{RequestBody: reqBodyBuf})
		}
		http.Error(w, "upstream error", http.StatusBadGateway)
		s.stats.Errors.Add(1)
		return
	}
	defer resp.Body.Close()

	elapsed := time.Since(requestStart)

	// --- Upstream 304: revalidation confirmed cached content is current ---
	if resp.StatusCode == http.StatusNotModified && staleEntry != nil {
		observed.metrics.Upstream = append(observed.metrics.Upstream, manifest.BodyRead{StatusCode: resp.StatusCode, Complete: true})
		original := int64(-1)
		if staleEntry.OriginalBodyKnown {
			original = staleEntry.OriginalBodyBytes
		}
		observed.representation("cache", original, int64(len(staleEntry.Body)), staleEntry.OriginalBodyTag)
		if s.harWriter != nil {
			s.harWriter.Record(upstreamReq, reqBodyBuf, resp, nil, elapsed)
		}

		scrubbedRespHeaders := rewriter.RewriteResponseHeaders(
			resp.Header, gate, s.cfg.AliasDomain, upstream.Host,
			rewriter.ResponseHeaderOpts{
				OriginMapper:  requestOrigins,
				RequestOrigin: r.Header.Get("Origin"),
			},
		)

		s.responseCache.Revalidate(staleCacheKey, resp.Header)

		mergePolicyHeaders := func(dst http.Header, src http.Header) {
			for _, name := range revalidationPolicyHeaders {
				if vals := src.Values(name); len(vals) > 0 {
					dst.Del(name)
					for _, v := range vals {
						dst.Add(name, v)
					}
				}
			}
		}

		refreshed, ok := s.responseCache.Lookup(staleCacheKey)
		if !ok {
			served := *staleEntry
			served.Headers = staleEntry.Headers.Clone()
			mergePolicyHeaders(served.Headers, scrubbedRespHeaders)
			if acao := resp.Header.Get("Access-Control-Allow-Origin"); acao != "" {
				served.UpstreamACAO = acao
			}
			s.writeCachedResponse(w, &served, r.Method == http.MethodHead, r.Header.Get("Origin"))
			status = served.StatusCode
			return
		}

		refreshed.Headers = refreshed.Headers.Clone()
		mergePolicyHeaders(refreshed.Headers, scrubbedRespHeaders)
		s.responseCache.UpdatePolicyHeaders(staleCacheKey, scrubbedRespHeaders, revalidationPolicyHeaders)

		newVary := cache.ParseVary(resp.Header.Get("Vary"))
		if len(newVary) > 0 && (newVary[0] == "*" || !varyEqual(newVary, staleEntry.VaryFields)) {
			credHash := responseCacheCredentialHash(r)
			baseKey := cache.Key(upstreamURL, credHash, r, nil)
			if staleEntry.VaryFields != nil {
				oldVariantKey := cache.Key(upstreamURL, credHash, r, staleEntry.VaryFields)
				s.responseCache.Remove(oldVariantKey)
			}
			if newVary[0] == "*" {
				s.responseCache.Remove(staleCacheKey)
				s.responseCache.Remove(baseKey)
			} else {
				variantKey := cache.Key(upstreamURL, credHash, r, newVary)
				s.responseCache.Store(baseKey, cache.Entry{
					VarySentinel: true,
					VaryFields:   append([]string(nil), newVary...),
					Directives:   cache.Directives{MaxAge: refreshed.Directives.MaxAge},
					StoredAt:     time.Now(),
				})
				variantEntry := refreshed
				variantEntry.VaryFields = newVary
				variantEntry.VaryValues = cache.CaptureVaryValues(r, newVary)
				s.responseCache.Store(variantKey, variantEntry)
			}
		}

		inm := r.Header.Get("If-None-Match")
		if cache.MatchesETag(inm, refreshed.ETag) {
			for name, values := range refreshed.Headers {
				for _, v := range values {
					w.Header().Add(name, v)
				}
			}
			if refreshed.UpstreamACAO != "" && s.origins != nil {
				w.Header().Set("Access-Control-Allow-Origin",
					s.origins.RewriteResponseOrigin(refreshed.UpstreamACAO, r.Header.Get("Origin")))
			}
			w.Header().Set("ETag", refreshed.ETag)
			w.Header().Del("Content-Length")
			w.Header().Del("Content-Encoding")
			w.Header().Del("Transfer-Encoding")
			status = http.StatusNotModified
			w.WriteHeader(http.StatusNotModified)
			return
		}
		s.writeCachedResponse(w, &refreshed, r.Method == http.MethodHead, r.Header.Get("Origin"))
		status = refreshed.StatusCode
		return
	}

	body, measured, err := readMeasuredResponse(resp, r.Method)
	observed.metrics.Upstream = append(observed.metrics.Upstream, measured)
	elapsed = time.Since(requestStart)
	if err != nil {
		status = http.StatusBadGateway
		log.Printf("[error] reading body: %v", err)
		if s.harWriter != nil {
			s.harWriter.RecordFetchFailure(upstreamReq, resp.StatusCode, resp.Header, body, err.Error(), elapsed, har.FetchFailureDetails{RequestBody: reqBodyBuf, EncodedBytes: &measured.EncodedBytes, HTTPVersion: resp.Proto, StatusLine: resp.Status})
		}
		http.Error(w, "upstream error", http.StatusBadGateway)
		s.stats.Errors.Add(1)
		return
	}

	if s.harWriter != nil {
		s.harWriter.Record(upstreamReq, reqBodyBuf, resp, body, elapsed, har.ResponseBodyInfo{EncodedBytes: measured.EncodedBytes})
	}
	if r.Method == http.MethodHead {
		observed.representation("upstream", -1, -1)
		out := rewriter.RewriteResponseHeaders(resp.Header, gate, s.cfg.AliasDomain, upstream.Host, rewriter.ResponseHeaderOpts{OriginMapper: requestOrigins, RequestOrigin: r.Header.Get("Origin")})
		for name, values := range out {
			w.Header()[name] = values
		}
		// No representation bytes were received, so neither its transformed
		// length nor its downstream validator can be computed truthfully.
		w.Header()["Content-Length"] = nil
		w.Header().Del("Content-Encoding")
		w.Header().Del("Transfer-Encoding")
		w.WriteHeader(resp.StatusCode)
		return
	}

	s.stats.Bytes.Add(int64(len(body)))

	upstreamMethod := r.Method
	upstreamCredReq := r

	if detection := s.captchaMatcher.DetectChallenge(body, resp.Header.Get("Content-Type"), resp.StatusCode); detection.IsCaptcha {
		challengeID := s.captchaQueue.Submit(
			detection.ProviderName,
			upstreamURL,
			body,
			resp.Header.Get("Content-Type"),
			detection.FormAction,
			detection.FormMethod,
		)
		s.captchaQueue.SetResponseHeaders(challengeID, resp.Header)
		if len(detection.FormFields) > 0 {
			s.captchaQueue.SetFormFields(challengeID, detection.FormFields)
		}
		log.Printf("[captcha] %s challenge detected on %s (id=%s), waiting for operator",
			detection.ProviderName, r.URL.Path, challengeID)

		solution, ok := s.captchaQueue.WaitForCompletion(r.Context(), challengeID, 5*time.Minute)
		if !ok {
			log.Printf("[captcha] challenge %s timed out, cancelled or expired", challengeID)
			s.captchaQueue.Cancel(challengeID)
		} else if len(solution) > 0 {
			log.Printf("[captcha] challenge %s completed by operator (%d fields), re-submitting to target", challengeID, len(solution))
			ch, _ := s.captchaQueue.GetCompleted(challengeID)
			retryMethod, retryURL, usedForm := s.captchaRetryTarget(ch, r, upstream)
			var retryBodyBytes []byte
			if usedForm && ch != nil {
				form := url.Values{}
				if strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]), "application/x-www-form-urlencoded") {
					if original, err := url.ParseQuery(string(reqBodyBuf)); err == nil {
						form = original
					}
				}
				for k, v := range ch.FormFields {
					form.Set(k, v)
				}
				for k, v := range solution {
					form.Set(k, v)
				}
				retryBodyBytes = []byte(form.Encode())
			} else {
				retryBodyBytes = s.buildCaptchaRetryBody(reqBodyBuf, r.Header.Get("Content-Type"), solution)
			}
			if retryMethod == http.MethodGet || retryMethod == http.MethodHead {
				if target, err := url.Parse(retryURL); err == nil {
					query := target.Query()
					if fields, err := url.ParseQuery(string(retryBodyBytes)); err == nil {
						for name, values := range fields {
							query[name] = values
						}
					}
					target.RawQuery = query.Encode()
					retryURL = target.String()
				}
				retryBodyBytes = nil
			}
			retryReq, retryErr := http.NewRequestWithContext(r.Context(), retryMethod, retryURL, bytes.NewReader(retryBodyBytes))
			if retryErr != nil {
				log.Printf("[captcha] failed to build retry request: %v", retryErr)
			} else {
				for k, vv := range upstreamReq.Header {
					retryReq.Header[k] = vv
				}
				if usedForm || retryMethod != r.Method {
					retryReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else if len(retryBodyBytes) > 0 && retryReq.Header.Get("Content-Type") == "" {
					retryReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				if retryMethod == http.MethodGet || retryMethod == http.MethodHead {
					retryReq.Header.Del("Content-Type")
				}
				retryReq.ContentLength = int64(len(retryBodyBytes))
				s.mergeChallengeResponseCookies(retryReq, resp)
				retryCtx, retryCancel := context.WithTimeout(retryReq.Context(), time.Duration(s.cfg.UpstreamTimeout)*time.Second)
				defer retryCancel()
				retryReq = retryReq.WithContext(retryCtx)
				retryStart := time.Now()
				retryResp, retryRespErr := s.transport.RoundTrip(retryReq)
				retryElapsed := time.Since(retryStart)
				if retryRespErr != nil {
					observed.metrics.Upstream = append(observed.metrics.Upstream, manifest.BodyRead{Error: "transport"})
					log.Printf("[captcha] upstream re-submission failed: %v", retryRespErr)
					if s.harWriter != nil {
						s.harWriter.RecordFetchFailure(retryReq, 0, nil, nil, retryRespErr.Error(), retryElapsed, har.FetchFailureDetails{RequestBody: retryBodyBytes})
					}
				} else {
					retryRespBody, retryMeasured, readErr := readMeasuredResponse(retryResp, retryMethod)
					observed.metrics.Upstream = append(observed.metrics.Upstream, retryMeasured)
					retryElapsed = time.Since(retryStart)
					retryResp.Body.Close()
					if readErr != nil {
						log.Printf("[captcha] reading retry response: %v", readErr)
						if s.harWriter != nil {
							s.harWriter.RecordFetchFailure(retryReq, retryResp.StatusCode, retryResp.Header, retryRespBody, readErr.Error(), retryElapsed, har.FetchFailureDetails{RequestBody: retryBodyBytes, EncodedBytes: &retryMeasured.EncodedBytes, HTTPVersion: retryResp.Proto, StatusLine: retryResp.Status})
						}
					} else {
						if s.harWriter != nil {
							s.harWriter.Record(retryReq, retryBodyBytes, retryResp, retryRespBody, retryElapsed, har.ResponseBodyInfo{EncodedBytes: retryMeasured.EncodedBytes})
						}
						body = retryRespBody
						resp = retryResp
						upstreamURL = retryURL
						upstreamMethod = retryMethod
						upstreamCredReq = retryReq
					}
				}
			}
		}
	}

	if upstreamMethod == http.MethodGet && s.sriPipeline != nil {
		if sriBodyVersion != "" {
			sriKey := sri.CacheKeyForAuthority(upstreamURL, r, r.Host) + "\x01" + sriBodyVersion
			if !s.sriCache.HasDigest(sriKey) {
				status = http.StatusBadGateway
				http.Error(w, "resource version expired", http.StatusBadGateway)
				s.stats.Errors.Add(1)
				return
			}
			if !s.sriCache.CheckBodyIntegrity(sriKey, body) {
				status = http.StatusBadGateway
				http.Error(w, "resource integrity changed", http.StatusBadGateway)
				s.stats.Errors.Add(1)
				return
			}
		} else {
			sriKey := sri.CacheKeyForAuthority(upstreamURL, r, r.Host)
			integrityOK := s.sriCache.CheckBodyIntegrity(sriKey, body)
			if integrityOK {
				if orig := s.unaliasURL(upstreamURL); orig != upstreamURL {
					integrityOK = s.sriCache.CheckBodyIntegrity(sri.CacheKeyForAuthority(orig, r, r.Host), body)
				}
			}
			if !integrityOK {
				status = http.StatusBadGateway
				http.Error(w, "resource integrity changed", http.StatusBadGateway)
				s.stats.Errors.Add(1)
				return
			}
		}
	}

	// Extension methods may mutate state too. Only methods with known safe
	// semantics are exempt from invalidation (RFC 9111, section 4.4).
	unsafeMethod := upstreamMethod != http.MethodGet && upstreamMethod != http.MethodHead &&
		upstreamMethod != http.MethodOptions && upstreamMethod != http.MethodTrace
	if unsafeMethod &&
		resp.StatusCode >= 200 && resp.StatusCode < 400 {
		s.responseCache.InvalidateURL(upstreamURL)
		s.sriCache.InvalidateURL(upstreamURL)
	}
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		original, rewritten := int64(0), int64(0)
		if resp.StatusCode == http.StatusNotModified {
			original, rewritten = -1, -1
		}
		observed.representation("upstream", original, rewritten)
		out := rewriter.RewriteResponseHeaders(resp.Header, gate, s.cfg.AliasDomain, upstream.Host, rewriter.ResponseHeaderOpts{OriginMapper: requestOrigins, RequestOrigin: r.Header.Get("Origin")})
		for name, values := range out {
			w.Header()[name] = values
		}
		w.Header()["Content-Length"] = nil
		w.Header().Del("Content-Encoding")
		w.Header().Del("Transfer-Encoding")
		w.WriteHeader(resp.StatusCode)
		return
	}

	contentType := resp.Header.Get("Content-Type")
	upstreamPath := r.URL.Path
	if parsed, err := url.Parse(upstreamURL); err == nil && parsed.Path != "" {
		upstreamPath = parsed.Path
	}

	docURL := &url.URL{
		Scheme: upstream.Scheme,
		Host:   upstream.Host,
		Path:   upstreamPath,
	}
	originalBodyTag := gate.ContentTag(body)
	result := rewriter.RewriteBody(body, contentType, upstreamPath, gate, s.cfg.Paranoid, rewriter.RewriteOpts{
		CSPPolicies:     resp.Header.Values("Content-Security-Policy"),
		StatusCode:      resp.StatusCode,
		Origins:         requestOrigins,
		SRIPipeline:     s.sriPipeline,
		UpstreamBase:    docURL,
		BaseRequest:     r,
		RegisterVersion: s.versionRefs.Register,
		ResourceURL: func(raw string, base *url.URL) (string, bool) {
			if s.providerRoutes != nil {
				if mapped, ok := s.providerRoutes.RewriteURL(raw, base); ok {
					return mapped, true
				}
			}
			return s.captchaMatcher.RewriteResourceURL(raw, base, s.cfg.UseTor())
		},
	})
	// A version can pin collision-disambiguating whitespace as well as the
	// original body digest. Regenerate that representation after no-store or
	// cache eviction; the original bytes were authenticated above.
	if upstreamMethod == http.MethodGet && sriBodyVersion != "" {
		result.Body = sri.ApplyBodyVersion(body, result.Body, sriBodyVersion)
	}
	s.stats.Scrubbed.Add(1)

	leakCount = gate.ResidualLeakCount(string(result.Body))
	observed.representation("upstream", int64(len(body)), int64(len(result.Body)), originalBodyTag)

	outHeaders := rewriter.RewriteResponseHeaders(
		resp.Header,
		gate,
		s.cfg.AliasDomain,
		upstream.Host,
		rewriter.ResponseHeaderOpts{
			OriginMapper:  requestOrigins,
			RequestOrigin: r.Header.Get("Origin"),
		},
	)
	result.CSPHashes.RewriteHeaders(outHeaders)

	etag := cache.ComputeETag(result.Body)

	// Store in response cache: only GET 200 responses.
	// HEAD must not populate the cache (empty body would corrupt GETs).
	// HTML with SRI processing is excluded (integrity hashes couple HTML to SRI cache lifetime).
	if upstreamMethod == http.MethodGet && resp.StatusCode == http.StatusOK {
		dirs := cache.ParseDirectives(resp.Header.Get("Cache-Control"))
		if dirs.NoStore || dirs.Private {
			s.responseCache.InvalidateURL(upstreamURL)
		}
		isHTML := strings.HasPrefix(strings.ToLower(contentType), "text/html")
		sriActive := s.sriPipeline != nil && isHTML
		varyFields := cache.ParseVary(resp.Header.Get("Vary"))
		if !sriActive && (len(varyFields) == 0 || varyFields[0] != "*") && !dirs.NoStore && !dirs.Private {
			credHash := responseCacheCredentialHash(upstreamCredReq)

			storedHeaders := outHeaders.Clone()
			storedHeaders.Del("Access-Control-Allow-Origin")

			variantKey := cache.Key(upstreamURL, credHash, upstreamCredReq, varyFields)

			if len(varyFields) > 0 {
				baseKey := cache.Key(upstreamURL, credHash, upstreamCredReq, nil)
				s.responseCache.Store(baseKey, cache.Entry{
					VarySentinel: true,
					VaryFields:   append([]string(nil), varyFields...),
					Directives:   cache.Directives{MaxAge: dirs.MaxAge},
					StoredAt:     time.Now(),
				})
			}

			s.responseCache.Store(variantKey, cache.Entry{
				Body:                 append([]byte(nil), result.Body...),
				StatusCode:           resp.StatusCode,
				Headers:              storedHeaders,
				ContentType:          contentType,
				OriginalBodyBytes:    int64(len(body)),
				OriginalBodyKnown:    true,
				OriginalBodyTag:      originalBodyTag,
				ETag:                 etag,
				UpstreamETag:         resp.Header.Get("ETag"),
				UpstreamLastModified: resp.Header.Get("Last-Modified"),
				UpstreamACAO:         resp.Header.Get("Access-Control-Allow-Origin"),
				VaryFields:           varyFields,
				VaryValues:           cache.CaptureVaryValues(upstreamCredReq, varyFields),
				Directives:           dirs,
				InitialAge:           cache.ParseAge(resp.Header.Get("Age")),
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
		s.manifest.RecordIdentity(upstreamPath, result.Metadata)
	}

	status = resp.StatusCode

	// Conditional match: only on successful (2xx) responses.
	if cacheable && resp.StatusCode >= 200 && resp.StatusCode < 300 {
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

// Bodies can contain the validated browser entry authority. Cache those bytes
// and their validators separately even when upstream URL and credentials match.
func responseCacheCredentialHash(r *http.Request) string {
	return cache.CredentialHash(r) + "\x00view=" + r.Host
}

func (s *Server) tryServeSRICache(w http.ResponseWriter, r *http.Request, upstream *url.URL, upstreamURL, sriBodyVersion string, gate *scrub.Gate) bool {
	reqCC := cache.ParseDirectives(r.Header.Get("Cache-Control"))
	if reqCC.NoCache {
		return false
	}

	cacheKey := sri.CacheKeyForAuthority(upstreamURL, r, r.Host)
	entry, ok := s.sriCache.Get(cacheKey)
	if !ok {
		if orig := s.unaliasURL(upstreamURL); orig != upstreamURL {
			cacheKey = sri.CacheKeyForAuthority(orig, r, r.Host)
			entry, ok = s.sriCache.Get(cacheKey)
		}
		if !ok {
			return false
		}
	}

	if sriBodyVersion != "" && entry.BodyVersion != sriBodyVersion {
		return false
	}

	if entry.ResponseHeaders != nil {
		dirs := cache.ParseDirectives(entry.ResponseHeaders.Get("Cache-Control"))
		if dirs.NoStore {
			return false
		}
	}

	if entry.FetchError != "" {
		http.Error(w, "upstream integrity verification failed", http.StatusBadGateway)
		s.stats.Errors.Add(1)
		return true
	}
	original := int64(-1)
	if entry.OriginalBodyKnown {
		original = entry.OriginalBodyBytes
	}
	observeRepresentation(w, "sri-cache", original, int64(len(entry.ScrubbedBody)), entry.OriginalBodyTag)

	etag := cache.ComputeETag(entry.ScrubbedBody)

	var sriOutHeaders http.Header
	if entry.ResponseHeaders != nil {
		sriOutHeaders = rewriter.RewriteResponseHeaders(
			entry.ResponseHeaders,
			gate,
			s.cfg.AliasDomain,
			upstream.Host,
			rewriter.ResponseHeaderOpts{
				OriginMapper:  s.origins.ForRequestHost(r.Host),
				RequestOrigin: r.Header.Get("Origin"),
			},
		)
	}

	inm := r.Header.Get("If-None-Match")
	if cache.MatchesETag(inm, etag) {
		for name, values := range sriOutHeaders {
			for _, v := range values {
				w.Header().Add(name, v)
			}
		}
		w.Header().Set("ETag", etag)
		w.Header().Del("Content-Length")
		w.Header().Del("Content-Encoding")
		w.Header().Del("Transfer-Encoding")
		w.WriteHeader(http.StatusNotModified)
		return true
	}

	for name, values := range sriOutHeaders {
		for _, v := range values {
			w.Header().Add(name, v)
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

func (s *Server) writeCachedResponse(w http.ResponseWriter, entry *cache.Entry, headOnly bool, requestOrigin string) {
	original := int64(-1)
	if entry.OriginalBodyKnown {
		original = entry.OriginalBodyBytes
	}
	observeRepresentation(w, "cache", original, int64(len(entry.Body)), entry.OriginalBodyTag)
	for name, values := range entry.Headers {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	if entry.UpstreamACAO != "" && s.origins != nil {
		w.Header().Set("Access-Control-Allow-Origin",
			s.origins.RewriteResponseOrigin(entry.UpstreamACAO, requestOrigin))
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
	body, _, err := readMeasuredResponse(resp, "")
	return body, err
}

func (s *Server) unaliasURL(upstreamURL string) string {
	for alias, original := range s.gate.Aliases() {
		if strings.Contains(upstreamURL, alias) {
			upstreamURL = strings.ReplaceAll(upstreamURL, alias, original)
		}
	}
	return upstreamURL
}

func varyEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
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

func stripVersionBLV(r *http.Request, token string) {
	q := r.URL.Query()
	vals := q["__blv"]
	var remaining []string
	for _, v := range vals {
		if v != token {
			remaining = append(remaining, v)
		}
	}
	if len(remaining) > 0 {
		q["__blv"] = remaining
	} else {
		q.Del("__blv")
	}
	r.URL.RawQuery = q.Encode()
}

func sameOrigin(a, b *url.URL) bool {
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	if !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	ap, bp := a.Port(), b.Port()
	if ap == "" {
		if strings.EqualFold(a.Scheme, "https") {
			ap = "443"
		} else {
			ap = "80"
		}
	}
	if bp == "" {
		if strings.EqualFold(b.Scheme, "https") {
			bp = "443"
		} else {
			bp = "80"
		}
	}
	return ap == bp
}

func (s *Server) opaqueJSONKeys(r *http.Request, upstreamHost string) map[string]bool {
	keys := make(map[string]bool)
	for _, p := range s.captchaMatcher.Providers() {
		for _, field := range p.OpaqueFields {
			if s.captchaMatcher.SubmissionHasOpaqueFields(r, field, upstreamHost) {
				keys[field] = true
			}
		}
	}
	return keys
}

func (s *Server) captchaRetryTarget(ch *captcha.Challenge, originalReq *http.Request, upstream *url.URL) (method, targetURL string, usedForm bool) {
	fallback := upstream.Scheme + "://" + upstream.Host + originalReq.URL.RequestURI()

	if ch == nil || ch.FormAction == "" || ch.FormMethod == "" {
		return originalReq.Method, fallback, false
	}

	base := &url.URL{
		Scheme: upstream.Scheme,
		Host:   upstream.Host,
		Path:   originalReq.URL.Path,
	}
	resolved, err := base.Parse(ch.FormAction)
	if err != nil {
		return originalReq.Method, fallback, false
	}

	if resolved.Scheme != upstream.Scheme || resolved.Host != upstream.Host {
		return originalReq.Method, fallback, false
	}

	return ch.FormMethod, resolved.String(), true
}

func (s *Server) mergeChallengeResponseCookies(retryReq *http.Request, challengeResp *http.Response) {
	newCookies := challengeResp.Cookies()
	if len(newCookies) == 0 {
		return
	}
	replacements := make(map[string]*http.Cookie, len(newCookies))
	for _, c := range newCookies {
		if c.MaxAge < 0 {
			replacements[c.Name] = nil
		} else {
			replacements[c.Name] = c
		}
	}
	existing := retryReq.Cookies()
	retryReq.Header.Del("Cookie")
	for _, c := range existing {
		if replacement, found := replacements[c.Name]; found {
			if replacement != nil {
				retryReq.AddCookie(replacement)
			}
			delete(replacements, c.Name)
			continue
		}
		retryReq.AddCookie(c)
	}
	for _, c := range newCookies {
		if c, ok := replacements[c.Name]; ok && c != nil {
			retryReq.AddCookie(c)
		}
	}
}

func (s *Server) buildCaptchaRetryBody(originalBody []byte, contentType string, solution map[string]string) []byte {
	normCT := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(normCT, ';'); i >= 0 {
		normCT = strings.TrimSpace(normCT[:i])
	}
	if strings.HasPrefix(normCT, "application/x-www-form-urlencoded") {
		form, err := url.ParseQuery(string(originalBody))
		if err != nil {
			form = make(url.Values)
		}
		for k, v := range solution {
			form.Set(k, v)
		}
		return []byte(form.Encode())
	}
	if normCT == "application/json" || strings.HasSuffix(normCT, "+json") {
		dec := json.NewDecoder(bytes.NewReader(originalBody))
		dec.UseNumber()
		var obj map[string]interface{}
		if err := dec.Decode(&obj); err != nil || obj == nil {
			obj = make(map[string]interface{})
		}
		for k, v := range solution {
			obj[k] = v
		}
		out, err := json.Marshal(obj)
		if err != nil {
			return originalBody
		}
		return out
	}
	form := make(url.Values)
	for k, v := range solution {
		form.Set(k, v)
	}
	return []byte(form.Encode())
}

func (s *Server) restoreJSONWithOpaqueKeys(gate *scrub.Gate, input []byte, opaqueKeys map[string]bool, restorers ...func(string) string) ([]byte, error) {
	return gate.RestoreJSONWithOpaqueKeys(input, opaqueKeys, restorers...)
}
