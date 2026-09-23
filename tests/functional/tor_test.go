//go:build functional

package functional_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/tests/fixture"
)

func TestTorSOCKSRouting(t *testing.T) {
	// These names cannot be resolved locally. Successful forwarding requires the
	// CLI to hand the original hostname to SOCKS5; the fixture maps it to loopback.
	onion := strings.Repeat("a", 56) + ".onion"
	for _, tc := range []struct {
		name, target, port string
		tls, allowTLS      bool
	}{
		{"http_onion_default_port", "http://" + onion, "80", false, false},
		{"https_onion_default_port", "https://" + onion, "443", true, true},
		{"custom_port", "http://" + onion + ":8443", "8443", false, false},
		{"clearnet_remote_dns", "http://fixture.invalid", "80", false, false},
		{"https_certificate_rejected", "https://" + onion, "443", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstream *httptest.Server
			if tc.tls {
				upstream = httptest.NewTLSServer(fixture.Handler())
			} else {
				upstream = httptest.NewServer(fixture.Handler())
			}
			t.Cleanup(upstream.Close)
			upstreamURL, _ := url.Parse(upstream.URL)
			socks := startSOCKSFixture(t, upstreamURL.Host, "relay")
			args := []string{"--tor", "--tor-addr", socks.listener.Addr().String()}
			if tc.allowTLS {
				args = append(args, "--no-verify-tls")
			}
			p := start(t, tc.target, args...)
			resp, body := request(t, client(t), "GET", p.baseURL+"/api", "", nil)
			conn, rd, wsResp := websocketRequest(t, p.baseURL)
			defer conn.Close()
			if tc.tls && !tc.allowTLS {
				if resp.StatusCode != 502 || strings.TrimSpace(body) != "upstream error" || wsResp.StatusCode != 502 {
					t.Fatalf("Tor bypassed certificate verification: HTTP=%d WS=%d body=%q", resp.StatusCode, wsResp.StatusCode, body)
				}
				wsBody, err := io.ReadAll(wsResp.Body)
				wsResp.Body.Close()
				if err != nil || strings.TrimSpace(string(wsBody)) != "websocket upstream error" {
					t.Fatalf("WS certificate error leaked details: %q (%v)", wsBody, err)
				}
			} else {
				if resp.StatusCode != 200 || !strings.Contains(body, "9007199254740993") || wsResp.StatusCode != 101 {
					t.Fatalf("SOCKS routing failed: HTTP=%d WS=%d body=%s", resp.StatusCode, wsResp.StatusCode, body)
				}
				message := readTextMessage(t, rd)
				if !strings.HasSuffix(message, " live") {
					t.Fatalf("WebSocket message lost: %q", message)
				}
				noIdentity(t, message)
			}
			noIdentity(t, body)
			if err := p.stop(); err != nil {
				t.Fatalf("Tor-mode shutdown: %v", err)
			}
			targetURL, _ := url.Parse(tc.target)
			want := net.JoinHostPort(targetURL.Hostname(), tc.port)
			seen := socks.destinations()
			if len(seen) < 2 {
				t.Fatalf("HTTP and WS did not establish separate SOCKS connections: %v", seen)
			}
			for _, dst := range seen {
				if dst.addressType != 3 || dst.address != want {
					t.Errorf("want unresolved hostname %s (ATYP=3); got %+v", want, dst)
				}
			}
		})
	}
}

func TestTorFailureDoesNotDialDirect(t *testing.T) {
	for _, failure := range []string{"reject", "disconnect", "unavailable"} {
		t.Run(failure, func(t *testing.T) {
			var hits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				fixture.Handler().ServeHTTP(w, r)
			}))
			t.Cleanup(upstream.Close)
			socks := startSOCKSFixture(t, "", failure)
			if failure == "unavailable" {
				socks.listener.Close()
			}
			// The target is directly reachable. A fallback would increment hits.
			p := start(t, upstream.URL, "--tor", "--tor-addr", socks.listener.Addr().String())
			resp, body := request(t, client(t), "GET", p.baseURL+"/api", "", nil)
			conn, _, wsResp := websocketRequest(t, p.baseURL)
			defer conn.Close()
			if resp.StatusCode != 502 || strings.TrimSpace(body) != "upstream error" || wsResp.StatusCode != 502 {
				t.Errorf("expected generic failures: HTTP=%d WS=%d body=%q", resp.StatusCode, wsResp.StatusCode, body)
			}
			wsBody, err := io.ReadAll(wsResp.Body)
			wsResp.Body.Close()
			if err != nil || strings.TrimSpace(string(wsBody)) != "websocket upstream error" {
				t.Errorf("unexpected WS error response: %q (%v)", wsBody, err)
			}
			if err := p.stop(); err != nil {
				t.Fatal(err)
			}
			if got := hits.Load(); got != 0 {
				t.Fatalf("Tor failure caused %d direct requests to the target", got)
			}
		})
	}
}

type socksDestination struct {
	addressType byte
	address     string
}

type socksFixture struct {
	listener net.Listener
	mu       sync.Mutex
	seen     []socksDestination
	active   map[net.Conn]bool
	closed   bool
	wg       sync.WaitGroup
}

func (s *socksFixture) destinations() []socksDestination {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]socksDestination(nil), s.seen...)
}

// This is a deterministic SOCKS5 transport fixture, not a Tor emulator. It
// records the destination without resolving it and relays only to the local
// test server supplied by the test. No public DNS/network traffic is needed.
func startSOCKSFixture(t *testing.T, route, behavior string) *socksFixture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socksFixture{listener: ln, active: make(map[net.Conn]bool)}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				conn.Close()
				return
			}
			s.active[conn] = true
			s.wg.Add(1)
			s.mu.Unlock()
			go func() {
				defer s.wg.Done()
				defer func() {
					conn.Close()
					s.mu.Lock()
					delete(s.active, conn)
					s.mu.Unlock()
				}()
				if behavior == "disconnect" {
					return
				}
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				if err := s.serve(conn, route, behavior); err != nil {
					t.Errorf("SOCKS fixture: %v", err)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		s.mu.Lock()
		s.closed = true
		ln.Close()
		for conn := range s.active {
			conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

func (s *socksFixture) serve(conn net.Conn, route, behavior string) error {
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return err
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	if greeting[0] != 5 || !strings.ContainsRune(string(methods), 0) {
		return fmt.Errorf("expected SOCKS5 no-auth negotiation")
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return err
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != 5 || header[1] != 1 || header[2] != 0 {
		return fmt.Errorf("invalid SOCKS CONNECT header %x", header)
	}
	var host string
	switch header[3] {
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return err
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return err
		}
		host = string(name)
	case 1, 4:
		size := 4
		if header[3] == 4 {
			size = 16
		}
		ip := make(net.IP, size)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return err
		}
		host = ip.String()
	default:
		return fmt.Errorf("invalid SOCKS address type %d", header[3])
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return err
	}
	s.mu.Lock()
	s.seen = append(s.seen, socksDestination{header[3], net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(port[:])))})
	s.mu.Unlock()
	if behavior == "reject" {
		_, err := conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return err
	}
	upstream, err := net.DialTimeout("tcp", route, time.Second)
	if err != nil {
		return err
	}
	defer upstream.Close()
	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return err
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
	conn.Close()
	upstream.Close()
	<-done
	return nil
}
