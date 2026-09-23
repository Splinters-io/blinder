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
	"strings"
	"sync"
	"time"

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

	maxFrameSize = 16 * 1024 * 1024
)

var (
	ErrNotWebSocket   = errors.New("not a websocket upgrade request")
	ErrUpstreamDial   = errors.New("failed to dial upstream for websocket")
	ErrUpgradeRefused = errors.New("upstream refused websocket upgrade")
)

type Proxy struct {
	gate        *scrub.Gate
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

func NewProxy(gate *scrub.Gate, aliasDomain, targetHost, targetAddr string, useTLS, verifyTLS bool, socksAddr string, idleTimeout time.Duration) *Proxy {
	if idleTimeout <= 0 {
		idleTimeout = 5 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Proxy{
		gate:        gate,
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

func (p *Proxy) Handle(w http.ResponseWriter, r *http.Request) error {
	if !IsUpgrade(r) {
		return ErrNotWebSocket
	}

	key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
	if r.Method != http.MethodGet || r.ContentLength > 0 || len(r.TransferEncoding) != 0 ||
		r.Header.Get("Sec-WebSocket-Version") != "13" || err != nil || len(key) != 16 {
		http.Error(w, "invalid websocket handshake", http.StatusBadRequest)
		return ErrNotWebSocket
	}
	upstreamConn, err := p.dialUpstream()
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
	upstreamConn.SetDeadline(time.Now().Add(30 * time.Second))
	upgradeReq := buildUpgradeRequest(rewriter.RewriteRequestHeaders(r, p.targetHost, p.aliasDomain, p.gate), p.targetHost, p.aliasDomain)
	if err := upgradeReq.Write(upstreamConn); err != nil {
		upstreamConn.Close()
		http.Error(w, "websocket upstream error", http.StatusBadGateway)
		return fmt.Errorf("write upgrade: %w", err)
	}

	upstreamBuf := bufio.NewReader(upstreamConn)
	upstreamResp, err := http.ReadResponse(upstreamBuf, upgradeReq)
	if err != nil {
		upstreamConn.Close()
		http.Error(w, "websocket upstream error", http.StatusBadGateway)
		return fmt.Errorf("read upgrade response: %w", err)
	}

	if upstreamResp.StatusCode != http.StatusSwitchingProtocols {
		upstreamConn.Close()
		http.Error(w, "websocket upgrade refused", http.StatusBadGateway)
		return fmt.Errorf("%w: got %d", ErrUpgradeRefused, upstreamResp.StatusCode)
	}

	if !validUpgradeResponse(upstreamResp, upgradeReq) {
		http.Error(w, "invalid websocket upstream handshake", http.StatusBadGateway)
		return errors.New("invalid upstream websocket handshake")
	}
	protocol := upstreamResp.Header.Get("Sec-WebSocket-Protocol")
	if p.gate.Scrub(protocol, "ws:protocol") != protocol {
		http.Error(w, "unsupported websocket subprotocol", http.StatusBadGateway)
		return errors.New("identity-bearing websocket subprotocol")
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstreamConn.Close()
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return errors.New("ResponseWriter does not support Hijack")
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		upstreamConn.Close()
		return fmt.Errorf("hijack: %w", err)
	}

	if !p.track(clientConn) {
		clientConn.Close()
		return errors.New("websocket proxy closed")
	}
	defer p.release(clientConn)
	clientConn.SetWriteDeadline(time.Now().Add(p.idleTimeout))
	switchResp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n")
	if secAccept := upstreamResp.Header.Get("Sec-WebSocket-Accept"); secAccept != "" {
		switchResp += fmt.Sprintf("Sec-WebSocket-Accept: %s\r\n", secAccept)
	}
	if proto := upstreamResp.Header.Get("Sec-WebSocket-Protocol"); proto != "" {
		switchResp += fmt.Sprintf("Sec-WebSocket-Protocol: %s\r\n", proto)
	}
	switchResp += "\r\n"

	if _, err := clientConn.Write([]byte(switchResp)); err != nil {
		clientConn.Close()
		upstreamConn.Close()
		return fmt.Errorf("write 101: %w", err)
	}

	log.Printf("[ws] upgrade complete, relaying frames")

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
	run := func(src io.Reader, dst net.Conn, serverToClient bool) {
		defer wg.Done()
		defer clientConn.Close()
		defer upstreamConn.Close()
		reader := bufio.NewReader(&idleReader{src, activity})
		p.relayFrames(reader, dst, serverToClient)
	}
	go run(upstreamBuf, clientConn, true)
	go run(clientBuf.Reader, upstreamConn, false)
	wg.Wait()
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
	return strings.ReplaceAll(text, p.aliasDomain, p.targetHost)
}

func (p *Proxy) dialUpstream() (net.Conn, error) {
	addr := p.targetAddr
	if _, _, err := net.SplitHostPort(addr); err != nil {
		port := "80"
		if p.useTLS {
			port = "443"
		}
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), port)
	}
	ctx, cancel := context.WithTimeout(p.ctx, 30*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 30 * time.Second}
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
	if p.useTLS {
		host, _, _ := net.SplitHostPort(addr)
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: !p.verifyTLS, MinVersion: tls.VersionTLS12})
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

	if ref := outReq.Header.Get("Origin"); ref != "" {
		outReq.Header.Set("Origin", strings.ReplaceAll(ref, aliasDomain, targetHost))
	}

	outReq.Header.Del("Accept-Encoding")
	outReq.Header.Del("Sec-WebSocket-Extensions")

	return outReq
}
