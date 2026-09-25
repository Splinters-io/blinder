package proxy

import (
	"bytes"
	"compress/gzip"
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
	stats                Stats
	done                 chan struct{}
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

	if harWriter != nil && cfg.HAR != nil {
		go s.periodicHARFlush()
	}

	mux := http.NewServeMux()
	mux.Handle("/__blinder/captcha/", s.captchaOperator)
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

	upstream := s.origins.Resolve(r.Host)
	if upstream == nil {
		upstream = s.cfg.TargetURL
	}

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
		ct := r.Header.Get("Content-Type")
		normCT := strings.ToLower(strings.TrimSpace(ct))
		if i := strings.IndexByte(normCT, ';'); i >= 0 {
			normCT = strings.TrimSpace(normCT[:i])
		}
		if strings.HasPrefix(normCT, "application/x-www-form-urlencoded") {
			if formValues, err := url.ParseQuery(string(reqBodyBuf)); err == nil {
				needsRestore := false
				for key, vals := range formValues {
					if gate.ContainsAlias(key) || gate.ContainsEscape(key) {
						needsRestore = true
						break
					}
					for _, v := range vals {
						if gate.ContainsAlias(v) || gate.ContainsEscape(v) {
							needsRestore = true
							break
						}
					}
					if needsRestore {
						break
					}
				}
				if needsRestore {
					restored := make(url.Values, len(formValues))
					for key, vals := range formValues {
						rk := gate.RestoreBody(key)
						for _, v := range vals {
							if s.captchaMatcher.SubmissionHasOpaqueFields(r, rk, upstream.Hostname()) {
								restored.Add(rk, v)
							} else {
								restored.Add(rk, gate.RestoreBody(v))
							}
						}
					}
					reqBodyBuf = []byte(restored.Encode())
				}
			}
		} else if normCT == "application/json" || strings.HasSuffix(normCT, "+json") {
			opaqueKeys := s.opaqueJSONKeys(r, upstream.Hostname())
			if len(opaqueKeys) > 0 {
				restored, restoreErr := s.restoreJSONWithOpaqueKeys(gate, reqBodyBuf, opaqueKeys)
				if restoreErr != nil {
					status = http.StatusBadRequest
					http.Error(w, "ambiguous request body", http.StatusBadRequest)
					return
				}
				reqBodyBuf = restored
			} else {
				restored := gate.RestoreJSON(reqBodyBuf)
				if restored == nil {
					status = http.StatusBadRequest
					http.Error(w, "ambiguous request body", http.StatusBadRequest)
					return
				}
				reqBodyBuf = restored
			}
		} else {
			reqBodyBuf = []byte(gate.RestoreBody(string(reqBodyBuf)))
		}
		r.Body = io.NopCloser(bytes.NewReader(reqBodyBuf))
		r.ContentLength = int64(len(reqBodyBuf))
	}

	if rawQuery := r.URL.RawQuery; rawQuery != "" {
		if q, err := url.ParseQuery(rawQuery); err == nil {
			restored := make(url.Values, len(q))
			changed := false
			for key, vals := range q {
				rk := gate.RestoreBody(key)
				if rk != key {
					changed = true
				}
				for _, v := range vals {
					rv := gate.RestoreBody(v)
					if rv != v {
						changed = true
					}
					restored.Add(rk, rv)
				}
			}
			if changed {
				r.URL.RawQuery = restored.Encode()
			}
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
		appURI := r.URL.Path
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
		if served := s.tryServeSRICache(w, r, upstreamURL, sriBodyVersion, gate); served {
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
			credHash := cache.CredentialHash(r)
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

		scrubbedRespHeaders := rewriter.RewriteResponseHeaders(
			resp.Header, gate, s.cfg.AliasDomain, s.cfg.TargetURL.Host,
			rewriter.ResponseHeaderOpts{
				OriginMapper:  s.origins,
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
			credHash := cache.CredentialHash(r)
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

	if detection := s.captchaMatcher.DetectChallenge(body, resp.Header.Get("Content-Type"), resp.StatusCode); detection.IsCaptcha {
		challengeID := s.captchaQueue.Submit(
			detection.ProviderName,
			upstreamURL,
			body,
			resp.Header.Get("Content-Type"),
			detection.FormAction,
			detection.FormMethod,
		)
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
					log.Printf("[captcha] upstream re-submission failed: %v", retryRespErr)
					if s.harWriter != nil {
						s.harWriter.RecordError(retryReq, retryBodyBytes, http.StatusBadGateway, retryRespErr.Error(), retryElapsed)
					}
				} else {
					retryRespBody, readErr := s.readResponseBody(retryResp)
					retryResp.Body.Close()
					if readErr != nil {
						log.Printf("[captcha] reading retry response: %v", readErr)
					} else {
						if s.harWriter != nil {
							s.harWriter.Record(retryReq, retryBodyBytes, retryResp, retryRespBody, retryElapsed)
						}
						body = retryRespBody
						resp = retryResp
					}
				}
			}
		}
	}

	if r.Method == http.MethodGet && s.sriPipeline != nil {
		if sriBodyVersion != "" {
			sriKey := sri.CacheKey(upstreamURL, r) + "\x01" + sriBodyVersion
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
			sriKey := sri.CacheKey(upstreamURL, r)
			integrityOK := s.sriCache.CheckBodyIntegrity(sriKey, body)
			if integrityOK {
				if orig := s.unaliasURL(upstreamURL); orig != upstreamURL {
					integrityOK = s.sriCache.CheckBodyIntegrity(sri.CacheKey(orig, r), body)
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

	// Mutation invalidation: successful writes invalidate cached GET responses.
	if (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch) &&
		resp.StatusCode >= 200 && resp.StatusCode < 400 {
		s.responseCache.InvalidateURL(upstreamURL)
		s.sriCache.InvalidateURL(upstreamURL)
	}

	contentType := resp.Header.Get("Content-Type")
	path := r.URL.Path

	docURL := &url.URL{
		Scheme: upstream.Scheme,
		Host:   upstream.Host,
		Path:   r.URL.Path,
	}
	result := rewriter.RewriteBody(body, contentType, path, gate, s.cfg.Paranoid, rewriter.RewriteOpts{
		Origins:         s.origins,
		SRIPipeline:     s.sriPipeline,
		UpstreamBase:    docURL,
		BaseRequest:     r,
		RegisterVersion: s.versionRefs.Register,
		ResourceURL: func(raw string, base *url.URL) (string, bool) {
			return s.captchaMatcher.RewriteResourceURL(raw, base, s.cfg.UseTor())
		},
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

	if cspEntries := s.captchaMatcher.CSPDirectives(); len(cspEntries) > 0 {
		outHeaders = injectCaptchaCSP(outHeaders, cspEntries)
	}

	etag := cache.ComputeETag(result.Body)

	// Store in response cache: only GET 200 responses.
	// HEAD must not populate the cache (empty body would corrupt GETs).
	// HTML with SRI processing is excluded (integrity hashes couple HTML to SRI cache lifetime).
	if r.Method == http.MethodGet && resp.StatusCode == http.StatusOK {
		dirs := cache.ParseDirectives(resp.Header.Get("Cache-Control"))
		if dirs.NoStore || dirs.Private {
			s.responseCache.InvalidateURL(upstreamURL)
		}
		isHTML := strings.HasPrefix(strings.ToLower(contentType), "text/html")
		sriActive := s.sriPipeline != nil && isHTML
		varyFields := cache.ParseVary(resp.Header.Get("Vary"))
		if !sriActive && (len(varyFields) == 0 || varyFields[0] != "*") && !dirs.NoStore && !dirs.Private {
			credHash := cache.CredentialHash(r)

			storedHeaders := outHeaders.Clone()
			storedHeaders.Del("Access-Control-Allow-Origin")

			variantKey := cache.Key(upstreamURL, credHash, r, varyFields)

			if len(varyFields) > 0 {
				baseKey := cache.Key(upstreamURL, credHash, r, nil)
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
				ETag:                 etag,
				UpstreamETag:         resp.Header.Get("ETag"),
				UpstreamLastModified: resp.Header.Get("Last-Modified"),
				UpstreamACAO:         resp.Header.Get("Access-Control-Allow-Origin"),
				VaryFields:           varyFields,
				VaryValues:           cache.CaptureVaryValues(r, varyFields),
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
		s.manifest.RecordIdentity(path, result.Metadata)
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

func (s *Server) tryServeSRICache(w http.ResponseWriter, r *http.Request, upstreamURL, sriBodyVersion string, gate *scrub.Gate) bool {
	reqCC := cache.ParseDirectives(r.Header.Get("Cache-Control"))
	if reqCC.NoCache {
		return false
	}

	cacheKey := sri.CacheKey(upstreamURL, r)
	entry, ok := s.sriCache.Get(cacheKey)
	if !ok {
		if orig := s.unaliasURL(upstreamURL); orig != upstreamURL {
			cacheKey = sri.CacheKey(orig, r)
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

	etag := cache.ComputeETag(entry.ScrubbedBody)

	var sriOutHeaders http.Header
	if entry.ResponseHeaders != nil {
		sriOutHeaders = rewriter.RewriteResponseHeaders(
			entry.ResponseHeaders,
			gate,
			s.cfg.AliasDomain,
			s.cfg.TargetURL.Host,
			rewriter.ResponseHeaderOpts{
				OriginMapper:  s.origins,
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

func (s *Server) restoreJSONWithOpaqueKeys(gate *scrub.Gate, input []byte, opaqueKeys map[string]bool) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	var parsed interface{}
	if err := dec.Decode(&parsed); err != nil {
		return []byte(gate.RestoreBody(string(input))), nil
	}
	if len(bytes.TrimSpace(input[dec.InputOffset():])) > 0 {
		return input, nil
	}

	result, ok := restoreJSONExcludingOpaque(gate, parsed, opaqueKeys)
	if !ok {
		return nil, fmt.Errorf("ambiguous JSON body")
	}

	out, err := json.Marshal(result)
	if err != nil {
		return input, nil
	}
	return out, nil
}

func restoreJSONExcludingOpaque(gate *scrub.Gate, v interface{}, opaqueKeys map[string]bool) (interface{}, bool) {
	switch val := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for key, value := range val {
			restoredKey := gate.RestoreBody(key)
			if _, exists := result[restoredKey]; exists {
				return nil, false
			}
			if opaqueKeys[restoredKey] {
				result[restoredKey] = value
			} else {
				rv, ok := restoreJSONExcludingOpaque(gate, value, opaqueKeys)
				if !ok {
					return nil, false
				}
				result[restoredKey] = rv
			}
		}
		return result, true
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			rv, ok := restoreJSONExcludingOpaque(gate, item, opaqueKeys)
			if !ok {
				return nil, false
			}
			result[i] = rv
		}
		return result, true
	case json.Number:
		return val, true
	case string:
		return gate.RestoreBody(val), true
	default:
		return v, true
	}
}

func injectCaptchaCSP(headers http.Header, captchaEntries []string) http.Header {
	existing := headers.Values("Content-Security-Policy")
	if len(existing) == 0 {
		return headers
	}

	merged := make(map[string]map[string]bool)
	for _, entry := range captchaEntries {
		parts := strings.SplitN(entry, " ", 2)
		if len(parts) != 2 {
			continue
		}
		directive, source := parts[0], parts[1]
		if merged[directive] == nil {
			merged[directive] = make(map[string]bool)
		}
		merged[directive][source] = true
	}

	result := headers.Clone()
	result.Del("Content-Security-Policy")
	for _, csp := range existing {
		result.Add("Content-Security-Policy", mergeCSPPolicy(csp, merged))
	}
	return result
}

func mergeCSPPolicy(policy string, captchaSources map[string]map[string]bool) string {
	directives := strings.Split(policy, ";")
	seen := make(map[string]bool)
	var result []string

	var defaultSrcSources []string

	for _, d := range directives {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		parts := strings.Fields(d)
		if len(parts) == 0 {
			continue
		}
		directive := parts[0]
		seen[directive] = true

		if directive == "default-src" {
			defaultSrcSources = parts[1:]
		}

		if sources, ok := captchaSources[directive]; ok {
			for s := range sources {
				found := false
				for _, existing := range parts[1:] {
					if existing == s {
						found = true
						break
					}
				}
				if !found {
					parts = append(parts, s)
				}
			}
		}
		result = append(result, strings.Join(parts, " "))
	}

	for directive, sources := range captchaSources {
		if seen[directive] {
			continue
		}
		parts := []string{directive}
		if len(defaultSrcSources) > 0 {
			parts = append(parts, defaultSrcSources...)
		}
		for s := range sources {
			found := false
			for _, existing := range parts[1:] {
				if existing == s {
					found = true
					break
				}
			}
			if !found {
				parts = append(parts, s)
			}
		}
		result = append(result, strings.Join(parts, " "))
	}

	return strings.Join(result, "; ")
}
