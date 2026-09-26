package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestProxyWebSocketExtraOriginAcceptance(t *testing.T) {
	requests := make(chan *http.Request, 3)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		// The request below uses RFC 6455's sample handshake key.
		_, _ = fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		_ = rw.Flush()
	})
	primary := httptest.NewServer(handler)
	defer primary.Close()
	extra := httptest.NewTLSServer(handler)
	defer extra.Close()
	primaryURL, _ := url.Parse(primary.URL)
	extraURL, _ := url.Parse(extra.URL)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg := newTestConfig(t, primary.URL)
	cfg.ListenAddr = listener.Addr().String()
	cfg.ExtraOrigins = []*url.URL{extraURL}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServeOnListener(listener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	_, port, _ := net.SplitHostPort(cfg.ListenAddr)
	extraAlias := scrub.AliasOrigin(extraURL.Scheme, extraURL.Hostname(), extraURL.Port(), cfg.AliasDomain)
	for _, tc := range []struct {
		alias    string
		upstream *url.URL
		want     int
	}{
		{cfg.AliasDomain, primaryURL, 101},
		{extraAlias, extraURL, 101},
		{"unregistered.local", nil, http.StatusMisdirectedRequest},
	} {
		t.Run(tc.alias, func(t *testing.T) {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", cfg.ListenAddr, &tls.Config{InsecureSkipVerify: true})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			req, _ := http.NewRequest("GET", "https://"+net.JoinHostPort(tc.alias, port)+"/events?channel=one", nil)
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			req.Header.Set("Origin", "https://"+req.Host)
			req.Header.Set("Referer", "https://"+req.Host+"/page")
			if err := req.Write(conn); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.want {
				t.Fatalf("upgrade status=%d want=%d", resp.StatusCode, tc.want)
			}
			if tc.upstream == nil {
				select {
				case got := <-requests:
					t.Fatalf("unknown alias reached upstream %s", got.Host)
				default:
				}
				return
			}
			select {
			case got := <-requests:
				if got.Host != tc.upstream.Host || got.URL.RequestURI() != "/events?channel=one" || got.Header.Get("Origin") != tc.upstream.String() || got.Header.Get("Referer") != tc.upstream.String()+"/page" {
					t.Fatalf("incorrect routed upgrade: host=%s uri=%s origin=%s referer=%s", got.Host, got.URL.RequestURI(), got.Header.Get("Origin"), got.Header.Get("Referer"))
				}
			case <-time.After(time.Second):
				t.Fatal("upstream did not receive upgrade")
			}
		})
	}
}
