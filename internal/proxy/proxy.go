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
	"strings"
	"sync/atomic"
	"time"

	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/har"
	"github.com/Splinters-io/blinder/internal/manifest"
	"github.com/Splinters-io/blinder/internal/rewriter"
	"github.com/Splinters-io/blinder/internal/scrub"
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
	cfg       *config.Config
	gate      *scrub.Gate
	origins   *rewriter.OriginMapper
	transport http.RoundTripper
	server    *http.Server
	wsProxy   *ws.Proxy
	harWriter *har.Writer
	manifest  *manifest.Session
	stats     Stats
	done      chan struct{}
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

	gate := scrub.NewGate(targetDomains, cfg.IdentityTokens, cfg.AliasDomain)
	origins := rewriter.NewOriginMapper(cfg.TargetURL, cfg.ListenAddr, cfg.AliasDomain)

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
		harWriter = har.NewWriter(cfg.HAR.MaxBodySize)
	}

	session := manifest.NewSession(cfg.AliasDomain, cfg.TargetURL.String())

	s := &Server{
		cfg:       cfg,
		gate:      gate,
		origins:   origins,
		transport: transport,
		wsProxy:   wsProxy,
		harWriter: harWriter,
		manifest:  session,
		done:      make(chan struct{}),
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
	if s.harWriter == nil || s.cfg.HAR == nil {
		return nil
	}
	return s.harWriter.Flush(s.cfg.HAR.FilePath)
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

	return s.manifest.Flush(s.cfg.OutputDir)
}

func (s *Server) Manifest() *manifest.Session {
	return s.manifest
}

func (s *Server) periodicHARFlush() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := s.FlushHAR(); err != nil {
				log.Printf("[error] periodic HAR flush: %v", err)
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

	upstreamReq := rewriter.RewriteRequestHeaders(r, s.cfg.TargetURL.Host, gate, s.origins)
	upstreamReq.URL.Scheme = s.cfg.TargetURL.Scheme
	upstreamReq.URL.Host = s.cfg.TargetURL.Host
	upstreamReq.RequestURI = ""

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

	body, err := s.readResponseBody(resp)
	if err != nil {
		status = http.StatusBadGateway
		elapsed := time.Since(requestStart)
		log.Printf("[error] reading body: %v", err)
		if s.harWriter != nil {
			s.harWriter.RecordError(upstreamReq, reqBodyBuf, http.StatusBadGateway, err.Error(), elapsed)
		}
		http.Error(w, "upstream error", http.StatusBadGateway)
		s.stats.Errors.Add(1)
		return
	}

	elapsed := time.Since(requestStart)

	if s.harWriter != nil {
		s.harWriter.Record(upstreamReq, reqBodyBuf, resp, body, elapsed)
	}

	s.stats.Bytes.Add(int64(len(body)))

	contentType := resp.Header.Get("Content-Type")
	path := r.URL.Path

	result := rewriter.RewriteBody(body, contentType, path, gate, s.cfg.Paranoid)
	s.stats.Scrubbed.Add(1)
	leakCount = gate.ResidualLeakCount(string(result.Body))

	outHeaders := rewriter.RewriteResponseHeaders(
		resp.Header,
		gate,
		s.cfg.AliasDomain,
		s.cfg.TargetURL.Host,
	)

	for name, values := range outHeaders {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}

	if result.Metadata != nil {
		// Scrub decoded values before JSON escaping, while retaining the schema.
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

	if result.ContentType != "" {
		w.Header().Set("Content-Type", result.ContentType)
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(result.Body)))
	w.Header().Del("Content-Encoding")
	w.Header().Del("Transfer-Encoding")

	w.WriteHeader(resp.StatusCode)
	w.Write(result.Body)
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
