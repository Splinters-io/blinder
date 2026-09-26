package ws

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Splinters-io/blinder/internal/formedit"
	"github.com/Splinters-io/blinder/internal/rewriter"
	"github.com/Splinters-io/blinder/internal/scrub"
	socks "golang.org/x/net/proxy"
)

const (
	opcodeText  = 0x1
	opcodeBin   = 0x2
	opcodeClose = 0x8
	opcodePing  = 0x9
	opcodePong  = 0xA

	finBit  = 0x80
	maskBit = 0x80

	maxFrameSize          = 16 * 1024 * 1024
	closeHandshakeTimeout = 5 * time.Second
)

var (
	ErrNotWebSocket   = errors.New("not a websocket upgrade request")
	ErrUpstreamDial   = errors.New("failed to dial upstream for websocket")
	ErrUpgradeRefused = errors.New("upstream refused websocket upgrade")
)

type Proxy struct {
	gate        *scrub.Gate
	origins     *rewriter.OriginMapper
	aliasDomain string
	targetHost  string
	targetAddr  string
	useTLS      bool
	verifyTLS   bool
	socksAddr   string
	idleTimeout time.Duration
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	active      map[net.Conn]struct{}
	closed      bool
}

// HandleOptions connects handshake responses to the owning HTTP proxy without
// coupling frame transport to its capture or representation policy.
type HandleOptions struct {
	Gate                  *scrub.Gate
	HandshakeTimeout      time.Duration
	RefusedResponse       func(http.ResponseWriter, *http.Request, *http.Response, time.Duration) error
	RewriteUpgradeHeaders func(*http.Request, *http.Response) http.Header
	ObserveHandshake      func(HandshakeEvent)
}

type HandshakeEvent struct {
	Request           *http.Request
	Response          *http.Response
	Elapsed           time.Duration
	Error             error
	UpstreamAttempted bool
}

func NewProxy(gate *scrub.Gate, aliasDomain, targetHost, targetAddr string, useTLS, verifyTLS bool, socksAddr string, idleTimeout time.Duration, origins *rewriter.OriginMapper) *Proxy {
	if idleTimeout <= 0 {
		idleTimeout = 5 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	if origins == nil {
		scheme := "http"
		if useTLS {
			scheme = "https"
		}
		origins, _ = rewriter.NewOriginMapper(&url.URL{Scheme: scheme, Host: targetHost}, "", aliasDomain)
	}
	return &Proxy{
		gate:        gate,
		origins:     origins,
		aliasDomain: aliasDomain,
		targetHost:  targetHost,
		targetAddr:  targetAddr,
		useTLS:      useTLS,
		verifyTLS:   verifyTLS,
		socksAddr:   socksAddr,
		idleTimeout: idleTimeout,
		ctx:         ctx,
		cancel:      cancel,
		active:      make(map[net.Conn]struct{}),
	}
}

func IsUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		hasHeaderToken(r.Header, "Connection", "upgrade")
}

func (p *Proxy) Handle(w http.ResponseWriter, r *http.Request, options ...HandleOptions) (resultErr error) {
	var opt HandleOptions
	if len(options) > 0 {
		opt = options[0]
	}
	gate := p.gate
	if opt.Gate != nil {
		gate = opt.Gate
	}
	timeout := opt.HandshakeTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	start := time.Now()
	var upgradeReq *http.Request
	var upstreamResp *http.Response
	var attempted, reported bool
	observe := func(err error) {
		if reported {
			return
		}
		reported = true
		if opt.ObserveHandshake != nil {
			opt.ObserveHandshake(HandshakeEvent{Request: upgradeReq, Response: upstreamResp, Elapsed: time.Since(start), Error: err, UpstreamAttempted: attempted})
		}
	}
	defer func() { observe(resultErr) }()
	if !IsUpgrade(r) {
		return ErrNotWebSocket
	}

	key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
	if r.Method != http.MethodGet || r.ContentLength > 0 || len(r.TransferEncoding) != 0 ||
		r.Header.Get("Sec-WebSocket-Version") != "13" || err != nil || len(key) != 16 {
		http.Error(w, "invalid websocket handshake", http.StatusBadRequest)
		return ErrNotWebSocket
	}
	// Resolve before dialing: each alias selects its registered complete origin,
	// including scheme and port. An unknown Host must not reach the primary.
	upstream := p.origins.Resolve(r.Host)
	if upstream == nil || !p.origins.IsKnownFullOrigin(upstream) {
		http.Error(w, "unknown websocket origin", http.StatusMisdirectedRequest)
		return errors.New("unknown websocket origin")
	}
	upgradeReq = buildUpgradeRequest(rewriter.RewriteRequestHeaders(r, upstream.Host, gate, p.origins), upstream.Host, p.aliasDomain)
	upgradeReq.URL.Scheme = upstream.Scheme
	restoreRequestURI(upgradeReq, gate)
	upgradeReq.Header.Set("Accept-Encoding", "gzip, identity")
	dialCtx, cancel := context.WithTimeout(r.Context(), timeout)
	stop := context.AfterFunc(p.ctx, cancel)
	defer stop()
	defer cancel()
	attempted = true
	upstreamConn, err := p.dialRoute(dialCtx, upstream)
	if err != nil {
		http.Error(w, "websocket upstream error", http.StatusBadGateway)
		return fmt.Errorf("%w: %v", ErrUpstreamDial, err)
	}

	if !p.track(upstreamConn) {
		upstreamConn.Close()
		http.Error(w, "websocket shutting down", http.StatusServiceUnavailable)
		return errors.New("websocket proxy closed")
	}
	defer p.release(upstreamConn)
	deadline, _ := dialCtx.Deadline()
	upstreamConn.SetDeadline(deadline)
	if err := upgradeReq.Write(upstreamConn); err != nil {
		upstreamConn.Close()
		http.Error(w, "websocket upstream error", http.StatusBadGateway)
		return fmt.Errorf("write upgrade: %w", err)
	}

	upstreamBuf := bufio.NewReader(upstreamConn)
	for {
		upstreamResp, err = http.ReadResponse(upstreamBuf, upgradeReq)
		if err != nil {
			upstreamConn.Close()
			http.Error(w, "websocket upstream error", http.StatusBadGateway)
			return fmt.Errorf("read upgrade response: %w", err)
		}
		if upstreamResp.StatusCode == http.StatusSwitchingProtocols || upstreamResp.StatusCode >= 200 {
			break
		}
		// Informational responses are not a refusal. Continue to the final
		// response under the same handshake deadline.
		upstreamResp.Body.Close()
	}

	if upstreamResp.StatusCode != http.StatusSwitchingProtocols {
		defer func() {
			// This connection is never reused. Close it before Body.Close so an
			// unread/oversized refusal cannot trigger an implicit body drain.
			upstreamConn.Close()
			upstreamResp.Body.Close()
		}()
		if opt.RefusedResponse != nil {
			// The callback consumes and records the actual HTTP response while
			// the connection remains open. It owns this event's capture.
			reported = true
			return opt.RefusedResponse(w, upgradeReq, upstreamResp, time.Since(start))
		}
		http.Error(w, "websocket upgrade refused", http.StatusBadGateway)
		return fmt.Errorf("%w: got %d", ErrUpgradeRefused, upstreamResp.StatusCode)
	}

	if !validUpgradeResponse(upstreamResp, upgradeReq) {
		http.Error(w, "invalid websocket upstream handshake", http.StatusBadGateway)
		return errors.New("invalid upstream websocket handshake")
	}
	protocol := upstreamResp.Header.Get("Sec-WebSocket-Protocol")
	if gate.Scrub(protocol, "ws:protocol") != protocol {
		http.Error(w, "unsupported websocket subprotocol", http.StatusBadGateway)
		return errors.New("identity-bearing websocket subprotocol")
	}
	responseHeaders := make(http.Header)
	if opt.RewriteUpgradeHeaders != nil {
		responseHeaders = opt.RewriteUpgradeHeaders(upgradeReq, upstreamResp)
		if responseHeaders == nil {
			responseHeaders = make(http.Header)
		}
	}
	// These are protocol fields, not arbitrary metadata. Reconstruct them only
	// from the already validated upstream handshake, never from scrubbed text.
	for _, name := range []string{"Content-Length", "Content-Encoding", "Transfer-Encoding", "Trailer", "Sec-WebSocket-Extensions", "Sec-WebSocket-Protocol"} {
		responseHeaders.Del(name)
	}
	responseHeaders.Set("Upgrade", "websocket")
	responseHeaders.Set("Connection", "Upgrade")
	responseHeaders.Set("Sec-WebSocket-Accept", upstreamResp.Header.Get("Sec-WebSocket-Accept"))
	if protocol != "" {
		responseHeaders.Set("Sec-WebSocket-Protocol", protocol)
	}

	clientConn, clientBuf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		upstreamConn.Close()
		if errors.Is(err, http.ErrNotSupported) {
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
		}
		return fmt.Errorf("hijack: %w", err)
	}

	if !p.track(clientConn) {
		clientConn.Close()
		return errors.New("websocket proxy closed")
	}
	defer p.release(clientConn)
	clientConn.SetWriteDeadline(time.Now().Add(p.idleTimeout))
	_, err = clientBuf.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	if err == nil {
		err = responseHeaders.Write(clientBuf)
	}
	if err == nil {
		_, err = clientBuf.WriteString("\r\n")
	}
	if err == nil {
		err = clientBuf.Flush()
	}
	if err != nil {
		clientConn.Close()
		upstreamConn.Close()
		return fmt.Errorf("write 101: %w", err)
	}

	log.Printf("[ws] upgrade complete, relaying frames")
	observe(nil)

	p.relay(clientConn, clientBuf, upstreamConn, upstreamBuf)
	return nil
}

func (p *Proxy) relay(clientConn net.Conn, clientBuf *bufio.ReadWriter, upstreamConn net.Conn, upstreamBuf *bufio.Reader) {
	clientConn.SetDeadline(time.Time{})
	upstreamConn.SetDeadline(time.Time{})
	activity := &relayActivity{conns: []net.Conn{clientConn, upstreamConn}, timeout: p.idleTimeout}
	activity.touch()
	var wg sync.WaitGroup
	wg.Add(2)
	closing := &relayClose{begun: make(chan struct{})}
	results := make(chan bool, 2)
	run := func(src io.Reader, dst net.Conn, serverToClient bool) {
		defer wg.Done()
		reader := bufio.NewReader(&idleReader{src, activity})
		results <- p.relayFrames(reader, dst, serverToClient, closing)
	}
	go run(upstreamBuf, clientConn, true)
	go run(clientBuf.Reader, upstreamConn, false)
	defer func() {
		clientConn.Close()
		upstreamConn.Close()
		wg.Wait()
	}()
	started := closing.begun
	var deadline <-chan time.Time
	for completed := 0; completed < 2; {
		select {
		case <-started:
			// Activity cannot extend the Close handshake. Bound even a blocked
			// Close write, and never wait longer than the configured idle limit.
			timeout := closeHandshakeTimeout
			if p.idleTimeout < timeout {
				timeout = p.idleTimeout
			}
			timer := time.NewTimer(timeout)
			defer timer.Stop()
			deadline = timer.C
			started = nil
		case clean := <-results:
			if !clean {
				return
			}
			completed++
		case <-deadline:
			return
		}
	}
}

type relayClose struct {
	once  sync.Once
	begun chan struct{}
}

func (c *relayClose) begin() {
	if c != nil {
		c.once.Do(func() { close(c.begun) })
	}
}

func (c *relayClose) started() bool {
	if c != nil {
		select {
		case <-c.begun:
			return true
		default:
		}
	}
	return false
}

type idleReader struct {
	reader   io.Reader
	activity *relayActivity
}

func (r *idleReader) Read(b []byte) (int, error) {
	n, err := r.reader.Read(b)
	if n > 0 {
		r.activity.touch()
	}
	return n, err
}

type relayActivity struct {
	mu      sync.Mutex
	conns   []net.Conn
	timeout time.Duration
}

// Activity in either direction keeps a one-way stream alive.
func (a *relayActivity) touch() {
	a.mu.Lock()
	defer a.mu.Unlock()
	deadline := time.Now().Add(a.timeout)
	for _, conn := range a.conns {
		conn.SetReadDeadline(deadline)
	}
}

func (p *Proxy) track(conn net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.active[conn] = struct{}{}
	return true
}
func (p *Proxy) release(conn net.Conn) {
	conn.Close()
	p.mu.Lock()
	delete(p.active, conn)
	p.mu.Unlock()
}

// Close also cancels pending dials. net/http's Shutdown does not close hijacked connections.
func (p *Proxy) Close() {
	p.mu.Lock()
	p.closed = true
	p.cancel()
	for conn := range p.active {
		conn.Close()
	}
	p.mu.Unlock()
}
func (p *Proxy) dealiasText(text string) string {
	return p.gate.RestoreBody(text)
}

func (p *Proxy) dialUpstream() (net.Conn, error) {
	scheme := "http"
	if p.useTLS {
		scheme = "https"
	}
	return p.dialRoute(p.ctx, &url.URL{Scheme: scheme, Host: p.targetAddr})
}

func (p *Proxy) dialRoute(parent context.Context, upstream *url.URL) (net.Conn, error) {
	useTLS := upstream.Scheme == "https"
	if upstream.Scheme != "http" && !useTLS || upstream.Hostname() == "" {
		return nil, errors.New("invalid websocket upstream origin")
	}
	addr := upstream.Host
	if upstream.Port() == "" {
		port := "80"
		if useTLS {
			port = "443"
		}
		addr = net.JoinHostPort(upstream.Hostname(), port)
	}
	timeout := 30 * time.Second
	if deadline, ok := parent.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if p.socksAddr != "" {
		var d socks.Dialer
		d, err = socks.SOCKS5("tcp", p.socksAddr, nil, dialer)
		if err == nil {
			cd, ok := d.(socks.ContextDialer)
			if !ok {
				return nil, errors.New("SOCKS5 dialer lacks context support")
			}
			conn, err = cd.DialContext(ctx, "tcp", addr)
		}
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	if useTLS {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: upstream.Hostname(), InsecureSkipVerify: !p.verifyTLS, MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		return tlsConn, nil
	}
	return conn, nil
}

func hasHeaderToken(h http.Header, name, want string) bool {
	for _, value := range h.Values(name) {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}

func validUpgradeResponse(resp *http.Response, req *http.Request) bool {
	if resp.StatusCode != http.StatusSwitchingProtocols || !hasHeaderToken(resp.Header, "Upgrade", "websocket") || !hasHeaderToken(resp.Header, "Connection", "upgrade") || len(resp.Header.Values("Sec-WebSocket-Extensions")) != 0 {
		return false
	}
	hash := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(hash[:]) {
		return false
	}
	selected := resp.Header.Get("Sec-WebSocket-Protocol")
	if selected == "" {
		return true
	}
	for _, value := range req.Header.Values("Sec-WebSocket-Protocol") {
		for _, token := range strings.Split(value, ",") {
			if strings.TrimSpace(token) == selected {
				return true
			}
		}
	}
	return false
}

func buildUpgradeRequest(r *http.Request, targetHost, aliasDomain string) *http.Request {
	outReq := r.Clone(r.Context())
	outReq.Host = targetHost
	outReq.URL.Host = targetHost
	outReq.URL.Scheme = "http"
	outReq.RequestURI = r.URL.RequestURI()

	outReq.Header.Del("Accept-Encoding")
	outReq.Header.Del("Sec-WebSocket-Extensions")

	return outReq
}

// Restore issued mappings in URL components without changing the route chosen
// from the incoming Host. Work on escaped path segments so an encoded slash
// remains segment data rather than becoming a new path separator.
func restoreRequestURI(req *http.Request, gate *scrub.Gate) {
	rewriter.RestoreURLPath(req.URL, gate)
	if rawQuery := req.URL.RawQuery; rawQuery != "" {
		if restored, err := formedit.Rewrite(rawQuery, gate.RestoreBody, nil); err == nil {
			req.URL.RawQuery = restored
		} // Leave malformed parameters for the upstream's own error handling.
	}
	req.RequestURI = req.URL.RequestURI()
}
