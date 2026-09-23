package proxy

import (
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
	"github.com/Splinters-io/blinder/internal/rewriter"
	"github.com/Splinters-io/blinder/internal/scrub"
	blindertls "github.com/Splinters-io/blinder/internal/tls"
	"github.com/Splinters-io/blinder/internal/ws"
)

const maxRequestBody = 50 * 1024 * 1024
const maxResponseBody = 50 * 1024 * 1024

type Stats struct {
	Requests  atomic.Int64
	Bytes     atomic.Int64
	Errors    atomic.Int64
	Scrubbed  atomic.Int64
}

type Server struct {
	cfg       *config.Config
	gate      *scrub.Gate
	transport http.RoundTripper
	server    *http.Server
	wsProxy   *ws.Proxy
	harWriter *har.Writer
	stats     Stats
}

func New(cfg *config.Config) (*Server, error) {
	targetHost := cfg.TargetURL.Hostname()
	targetDomains := append([]string{targetHost}, extractSubdomains(targetHost)...)

	gate := scrub.NewGate(targetDomains, cfg.IdentityTokens, cfg.AliasDomain)

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
	)

	var harWriter *har.Writer
	if cfg.HAR != nil {
		harWriter = har.NewWriter(cfg.HAR.MaxBodySize)
	}

	s := &Server{
		cfg:       cfg,
		gate:      gate,
		transport: transport,
		wsProxy:   wsProxy,
		harWriter: harWriter,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	cert, err := blindertls.GenerateSelfSigned(cfg.AliasDomain)
	if err != nil {
		return nil, fmt.Errorf("tls cert: %w", err)
	}

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

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	s.stats.Requests.Add(1)

	if ws.IsUpgrade(r) {
		if err := s.wsProxy.Handle(w, r); err != nil {
			log.Printf("[error] websocket: %v", err)
			s.stats.Errors.Add(1)
		}
		return
	}

	if r.ContentLength > maxRequestBody {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		s.stats.Errors.Add(1)
		return
	}

	upstreamReq := rewriter.RewriteRequestHeaders(r, s.cfg.TargetURL.Host, s.cfg.AliasDomain)
	upstreamReq.URL.Scheme = s.cfg.TargetURL.Scheme
	upstreamReq.URL.Host = s.cfg.TargetURL.Host
	upstreamReq.RequestURI = ""

	requestStart := time.Now()

	resp, err := s.transport.RoundTrip(upstreamReq)
	if err != nil {
		log.Printf("[error] upstream: %v", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		s.stats.Errors.Add(1)
		return
	}
	defer resp.Body.Close()

	body, err := s.readResponseBody(resp)
	if err != nil {
		log.Printf("[error] reading body: %v", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		s.stats.Errors.Add(1)
		return
	}

	elapsed := time.Since(requestStart)

	if s.harWriter != nil {
		var reqBody []byte
		if r.Body != nil {
			reqBody, _ = io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
		}
		s.harWriter.Record(r, reqBody, resp, body, elapsed)
	}

	s.stats.Bytes.Add(int64(len(body)))

	contentType := resp.Header.Get("Content-Type")
	path := r.URL.Path

	result := rewriter.RewriteBody(body, contentType, path, s.gate, s.cfg.Paranoid)
	s.stats.Scrubbed.Add(1)

	outHeaders := rewriter.RewriteResponseHeaders(
		resp.Header,
		s.gate,
		s.cfg.AliasDomain,
		s.cfg.TargetURL.Host,
	)

	for name, values := range outHeaders {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}

	if result.Metadata != nil {
		w.Header().Set("X-Blinder-Meta", result.Metadata.TechnicalJSON())
	}

	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(result.Body)))
	w.Header().Del("Content-Encoding")
	w.Header().Del("Transfer-Encoding")

	w.WriteHeader(resp.StatusCode)
	w.Write(result.Body)
}

func (s *Server) readResponseBody(resp *http.Response) ([]byte, error) {
	var reader io.Reader = resp.Body

	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gzip decode: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	body, err := io.ReadAll(io.LimitReader(reader, maxResponseBody))
	if err != nil {
		return nil, err
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
