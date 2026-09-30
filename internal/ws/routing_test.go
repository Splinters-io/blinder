package ws

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/rewriter"
	"github.com/Splinters-io/blinder/internal/scrub"
)

func mustMapper(t *testing.T, target *url.URL, listen, alias string, extras ...rewriter.OriginRoute) *rewriter.OriginMapper {
	t.Helper()
	m, err := rewriter.NewOriginMapper(target, listen, alias, extras...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func routeURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func startRouteProxy(t *testing.T, p *Proxy) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = p.Handle(w, r) }))
	t.Cleanup(srv.Close)
	t.Cleanup(p.Close)
	return srv
}

func routeHandshake(t *testing.T, front, host, origin string, requestURIs ...string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", routeURL(t, front).Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	requestURI := "/socket/stream?mode=one"
	if len(requestURIs) > 0 {
		requestURI = requestURIs[0]
	}
	req, err := http.NewRequest("GET", front+requestURI, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	if origin != "" {
		req.Header.Set("Origin", origin)
		req.Header.Set("Referer", origin+"/page?x=1")
	}
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		t.Fatal(err)
	}
	return conn, reader, resp
}

func TestWebSocketRestoresIssuedRequestURIComponents(t *testing.T) {
	requests := make(chan *http.Request, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		conn, _, err := routeUpgrade(w, r)
		if err == nil {
			conn.Close()
		}
	}))
	defer target.Close()
	upstream := routeURL(t, target.URL)
	gate := scrub.NewGate(nil, []string{"AcmeCorp", "segment/name"}, "alias.local")
	token := gate.Scrub("AcmeCorp", "test:seed")
	slashToken := gate.Scrub("segment/name", "test:seed")
	fileAlias := gate.Scrub("asset.js", "test:seed")
	if token == "AcmeCorp" || slashToken == "segment/name" || fileAlias == "asset.js" {
		t.Fatal("fixture did not issue its mappings")
	}
	mapper := mustMapper(t, upstream, "127.0.0.1:9443", "alias.local")
	p := NewProxy(gate, "alias.local", upstream.Host, upstream.Host, false, true, "", time.Second, func() *rewriter.OriginMapper { return mapper })
	front := startRouteProxy(t, p)
	pathToken, queryToken := url.PathEscape(token), url.QueryEscape(token)
	cases := []struct{ name, input, want string }{
		{"issued-path-and-query", "/socket/" + pathToken + "?first=one%20two&tenant=" + queryToken + "&first=second", "/socket/AcmeCorp?first=one%20two&tenant=AcmeCorp&first=second"},
		{"escaped-slash-and-unknown-alias", "/a%2fb/" + pathToken + "/%5BREDACTED%3Affffff%5D?keep=%2f&&bare&semi=x;y&tenant=" + queryToken, "/a%2fb/AcmeCorp/%5BREDACTED%3Affffff%5D?keep=%2f&&bare&semi=x;y&tenant=AcmeCorp"},
		{"escaped-slash-and-neutral-unknown-alias", "/a%2fb/" + pathToken + "/%5Bv%3Affffff%5D?keep=%2f&&bare&semi=x;y&tenant=" + queryToken, "/a%2fb/AcmeCorp/%5Bv%3Affffff%5D?keep=%2f&&bare&semi=x;y&tenant=AcmeCorp"},
		{"restored-slash-is-segment-data", "/socket/" + url.PathEscape(slashToken), "/socket/segment%2Fname"},
		{"colliding-query-keys", "/socket?" + queryToken + "=one&AcmeCorp=two&" + queryToken + "=three", "/socket?AcmeCorp=one&AcmeCorp=two&AcmeCorp=three"},
		{"malformed-query-retained", "/" + pathToken + "?issued=" + queryToken + "&bad=%zz", "/AcmeCorp?issued=" + queryToken + "&bad=%zz"},
		{"empty-query-marker", "/" + pathToken + "?", "/AcmeCorp?"},
		{"issued-domain-filename", "/assets/" + fileAlias + "?literal=unissued.alias.local", "/assets/asset.js?literal=unissued.alias.local"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, _, resp := routeHandshake(t, front.URL, "alias.local:9443", "", tc.input)
			defer conn.Close()
			if resp.StatusCode != 101 {
				t.Fatalf("upgrade status=%d", resp.StatusCode)
			}
			select {
			case req := <-requests:
				if req.Host != upstream.Host || req.RequestURI != tc.want {
					t.Fatalf("restoration changed route or URL spelling: host=%s URI=%q want=%q", req.Host, req.RequestURI, tc.want)
				}
			case <-time.After(time.Second):
				t.Fatal("upstream did not receive request")
			}
		})
	}
}

func TestRestoreRequestURILeavesIncomingRequestUntouched(t *testing.T) {
	gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	alias := gate.Scrub("AcmeCorp", "test:seed")
	input := "https://alias.local/a%2fb/" + url.PathEscape(alias) + "?value=" + url.QueryEscape(alias)
	r, err := http.NewRequest("GET", input, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := r.URL.String()
	clone := buildUpgradeRequest(r, "upstream.example:9443", "alias.local")
	restoreRequestURI(clone, gate)
	if r.URL.String() != before || r.Host != "alias.local" || r.RequestURI != "" {
		t.Fatalf("restoration mutated incoming request: %+v", r)
	}
	if !strings.Contains(clone.URL.EscapedPath(), "/a%2fb/AcmeCorp") || clone.URL.Host != "upstream.example:9443" {
		t.Fatalf("incorrect restored clone: %+v", clone.URL)
	}
}

func routeUpgrade(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsAcceptKey(r.Header.Get("Sec-WebSocket-Key")))
	if err == nil {
		err = rw.Flush()
	}
	return conn, rw, err
}

func TestWebSocketRoutesPrimaryAndExtraOrigins(t *testing.T) {
	requests := make(chan *http.Request, 3)
	upstreamMessages := make(chan string, 2)
	const original = `{"identity":"AcmeCorp","url":"https://service.example/path","literal":"unissued.alias.local"}`
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		conn, rw, err := routeUpgrade(w, r)
		if err != nil {
			return
		}
		defer conn.Close()
		if err := writeFrame(conn, finBit|opcodeText, []byte(original), false); err != nil {
			return
		}
		_, body, ok := readFrame(rw.Reader, false)
		if ok {
			upstreamMessages <- string(body)
		}
	})
	primary := httptest.NewServer(handler)
	defer primary.Close()
	extra := httptest.NewTLSServer(handler)
	defer extra.Close()
	primaryURL, extraURL := routeURL(t, primary.URL), routeURL(t, extra.URL)
	mapper := mustMapper(t, primaryURL, "127.0.0.1:9443", "alias.local", rewriter.OriginRoute{Upstream: extraURL, Alias: "extra.alias.local"})
	gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	p := NewProxy(gate, "alias.local", primaryURL.Host, primaryURL.Host, false, false, "", time.Second, func() *rewriter.OriginMapper { return mapper })
	front := startRouteProxy(t, p)
	for _, tc := range []struct{ alias, upstream string }{{"alias.local", primary.URL}, {"extra.alias.local", extra.URL}} {
		t.Run(tc.alias, func(t *testing.T) {
			conn, reader, resp := routeHandshake(t, front.URL, tc.alias+":9443", "https://"+tc.alias+":9443")
			defer conn.Close()
			if resp.StatusCode != 101 {
				t.Fatalf("upgrade: %d", resp.StatusCode)
			}
			select {
			case req := <-requests:
				if req.Host != routeURL(t, tc.upstream).Host || req.URL.RequestURI() != "/socket/stream?mode=one" ||
					req.Header.Get("Origin") != tc.upstream || req.Header.Get("Referer") != tc.upstream+"/page?x=1" {
					t.Fatalf("incorrect upstream request: host=%s uri=%s origin=%s referer=%s", req.Host, req.URL.RequestURI(), req.Header.Get("Origin"), req.Header.Get("Referer"))
				}
			case <-time.After(time.Second):
				t.Fatal("upstream did not receive upgrade")
			}
			_, body, ok := readFrame(reader, true)
			if !ok || bytes.Contains(body, []byte("AcmeCorp")) || !bytes.Contains(body, []byte(scrub.ValueAliasPrefix)) {
				t.Fatalf("incorrect downstream text: %q", body)
			}
			// Split a generated alias across frames. Restoration must operate on
			// the assembled message and must not rewrite an unissued suffix.
			cut := bytes.Index(body, []byte(scrub.ValueAliasPrefix)) + 4
			if err := writeFrame(conn, opcodeText, body[:cut], true); err != nil {
				t.Fatal(err)
			}
			if err := writeFrame(conn, finBit, body[cut:], true); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-upstreamMessages:
				if got != original {
					t.Fatalf("upstream text changed: %s", got)
				}
			case <-time.After(time.Second):
				t.Fatal("upstream did not receive restored fragmented message")
			}
		})
	}
	conn, _, resp := routeHandshake(t, front.URL, "unknown.alias.local:9443", "")
	defer conn.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("unknown route status=%d", resp.StatusCode)
	}
	select {
	case r := <-requests:
		t.Fatalf("unknown route reached upstream %s", r.Host)
	default:
	}
}

func TestWebSocketExtraOriginTLSVerification(t *testing.T) {
	var hits atomic.Int32
	sni := make(chan string, 1)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	upstream.TLS = &tls.Config{GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) { sni <- info.ServerName; return nil, nil }}
	upstream.StartTLS()
	defer upstream.Close()
	extra := routeURL(t, upstream.URL)
	extra.Host = net.JoinHostPort("localhost", extra.Port())
	primary := routeURL(t, "http://127.0.0.1:1")
	mapper := mustMapper(t, primary, "127.0.0.1:9443", "alias.local", rewriter.OriginRoute{Upstream: extra, Alias: "extra.alias.local"})
	p := NewProxy(scrub.NewGate(nil, nil, "alias.local"), "alias.local", primary.Host, primary.Host, false, true, "", time.Second, func() *rewriter.OriginMapper { return mapper })
	front := startRouteProxy(t, p)
	conn, _, resp := routeHandshake(t, front.URL, "extra.alias.local:9443", "")
	defer conn.Close()
	if resp.StatusCode != 502 || hits.Load() != 0 {
		t.Fatalf("untrusted extra-origin certificate accepted: status=%d hits=%d", resp.StatusCode, hits.Load())
	}
	select {
	case name := <-sni:
		if name != "localhost" {
			t.Fatalf("SNI=%q; expected selected extra origin", name)
		}
	case <-time.After(time.Second):
		t.Fatal("TLS hello not observed")
	}
}

type routeSOCKSDestination struct {
	host        string
	port        uint16
	addressType byte
}

func startRouteSOCKS(t *testing.T, upstream string, reject bool) (string, <-chan routeSOCKSDestination) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan routeSOCKSDestination, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var greeting [2]byte
		if _, err := io.ReadFull(conn, greeting[:]); err != nil {
			return
		}
		methods := make([]byte, int(greeting[1]))
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		if _, err := conn.Write([]byte{5, 0}); err != nil {
			return
		}
		var request [4]byte
		if _, err := io.ReadFull(conn, request[:]); err != nil {
			return
		}
		var host string
		switch request[3] {
		case 3:
			var n [1]byte
			if _, err := io.ReadFull(conn, n[:]); err != nil {
				return
			}
			name := make([]byte, int(n[0]))
			if _, err := io.ReadFull(conn, name); err != nil {
				return
			}
			host = string(name)
		case 1:
			var ip [4]byte
			if _, err := io.ReadFull(conn, ip[:]); err != nil {
				return
			}
			host = net.IP(ip[:]).String()
		default:
			return
		}
		var port [2]byte
		if _, err := io.ReadFull(conn, port[:]); err != nil {
			return
		}
		seen <- routeSOCKSDestination{host, binary.BigEndian.Uint16(port[:]), request[3]}
		if reject {
			_, _ = conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		target, err := net.DialTimeout("tcp", upstream, time.Second)
		if err != nil {
			return
		}
		defer target.Close()
		if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
			return
		}
		copied := make(chan struct{}, 1)
		go func() { _, _ = io.Copy(target, conn); close(copied) }()
		_, _ = io.Copy(conn, target)
		conn.Close()
		target.Close()
		<-copied
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	return listener.Addr().String(), seen
}

func TestWebSocketExtraOriginSOCKSRoute(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject=%t", reject), func(t *testing.T) {
			var hits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				conn, _, err := routeUpgrade(w, r)
				if err == nil {
					conn.Close()
				}
			}))
			defer upstream.Close()
			upURL := routeURL(t, upstream.URL)
			socksAddr, seen := startRouteSOCKS(t, upURL.Host, reject)
			extra := routeURL(t, "http://synthetic-provider.onion:8123")
			if reject {
				// This target is directly reachable; rejecting SOCKS must never
				// fall back to it and accidentally produce a successful upgrade.
				extra = upURL
			}
			primary := routeURL(t, "http://unused.invalid:8000")
			mapper := mustMapper(t, primary, "127.0.0.1:9443", "alias.local", rewriter.OriginRoute{Upstream: extra, Alias: "extra.alias.local"})
			p := NewProxy(scrub.NewGate(nil, nil, "alias.local"), "alias.local", primary.Host, primary.Host, false, true, socksAddr, time.Second, func() *rewriter.OriginMapper { return mapper })
			front := startRouteProxy(t, p)
			conn, _, resp := routeHandshake(t, front.URL, "extra.alias.local:9443", "")
			defer conn.Close()
			want := 101
			if reject {
				want = 502
			}
			if resp.StatusCode != want {
				t.Fatalf("upgrade status=%d want=%d", resp.StatusCode, want)
			}
			select {
			case destination := <-seen:
				if !reject && (destination.host != "synthetic-provider.onion" || destination.port != 8123 || destination.addressType != 3) {
					t.Fatalf("SOCKS lost remote hostname/port: %+v", destination)
				}
			case <-time.After(time.Second):
				t.Fatal("no SOCKS request")
			}
			if reject && hits.Load() != 0 {
				t.Fatal("SOCKS rejection fell back to a direct dial")
			}
		})
	}
}
