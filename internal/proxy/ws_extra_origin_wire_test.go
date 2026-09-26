package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/scrub"
)

// Exercise the complete handshake and frame path for each registered origin,
// rather than accepting a 101 as evidence that a working session was routed.
func TestWebSocketExtraOriginWireSession(t *testing.T) {
	type observation struct {
		route, host, uri, origin, referer, cookie string
		secure                                    bool
		text                                      string
		err                                       error
	}
	observed := make(chan observation, 4)
	newUpstream := func(name string, secure bool) *httptest.Server {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/session" {
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Content-Type", "text/plain")
				http.SetCookie(w, &http.Cookie{Name: "session", Value: name + "-AcmeCorp-secret", Path: "/", Secure: true, HttpOnly: true})
				fmt.Fprint(w, "session ready")
				return
			}
			got := observation{route: name, host: r.Host, uri: r.URL.RequestURI(), origin: r.Header.Get("Origin"), referer: r.Header.Get("Referer"), cookie: r.Header.Get("Cookie"), secure: r.TLS != nil}
			defer func() { observed <- got }()
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				got.err = err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
			// Split the identity across frames so the relay must reassemble it.
			if err = writeExtraOriginFrame(rw, 0x01, []byte("Acme"), false); err == nil {
				err = writeExtraOriginFrame(rw, 0x80, []byte("Corp "+name), false)
			}
			if err == nil {
				err = rw.Flush()
			}
			if err != nil {
				got.err = err
				return
			}
			first, payload, err := readExtraOriginFrame(rw.Reader, true)
			if err != nil || first != 0x81 {
				got.err = fmt.Errorf("restored text frame: opcode=%x err=%v", first, err)
				return
			}
			got.text = string(payload)
			first, payload, err = readExtraOriginFrame(rw.Reader, true)
			if err != nil || first != 0x88 || !bytes.Equal(payload, []byte{3, 232}) {
				got.err = fmt.Errorf("client Close: opcode=%x payload=%x err=%v", first, payload, err)
				return
			}
			got.err = writeExtraOriginFrame(conn, 0x88, payload, false)
		})
		if secure {
			return httptest.NewTLSServer(handler)
		}
		return httptest.NewServer(handler)
	}
	type route struct {
		name, alias string
		upstream    *httptest.Server
		url         *url.URL
		cookie      *http.Cookie
	}
	routes := []route{{name: "primary-http"}, {name: "extra-https"}, {name: "extra-http"}}
	for i := range routes {
		routes[i].upstream = newUpstream(routes[i].name, i == 1)
		t.Cleanup(routes[i].upstream.Close)
		routes[i].url, _ = url.Parse(routes[i].upstream.URL)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := newTestConfig(t, routes[0].upstream.URL)
	cfg.ListenAddr = listener.Addr().String()
	cfg.ExtraOrigins = []*url.URL{routes[1].url, routes[2].url}
	server, err := New(cfg)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	go func() { _ = server.ListenAndServeOnListener(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	_, port, _ := net.SplitHostPort(cfg.ListenAddr)
	client := testClient() // Synthetic TLS servers; platform/browser trust is separate acceptance.
	t.Cleanup(client.CloseIdleConnections)
	for i := range routes {
		r := &routes[i]
		r.alias = cfg.AliasDomain
		if i != 0 {
			r.alias = scrub.AliasOrigin(r.url.Scheme, r.url.Hostname(), r.url.Port(), cfg.AliasDomain)
		}
		req, _ := http.NewRequest(http.MethodGet, "https://"+cfg.ListenAddr+"/session", nil)
		req.Host = net.JoinHostPort(r.alias, port)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || len(resp.Cookies()) != 1 {
			t.Fatalf("%s session setup: status=%d cookies=%v", r.name, resp.StatusCode, resp.Cookies())
		}
		r.cookie = resp.Cookies()[0]
		if strings.Contains(r.cookie.Value, "AcmeCorp") {
			t.Fatal("session cookie disclosed identity")
		}
	}
	roundTrip := func(t *testing.T, r route, cookie *http.Cookie, wantCookie string) {
		t.Helper()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", cfg.ListenAddr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		host := net.JoinHostPort(r.alias, port)
		req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/events?channel=one%20two&channel=three", nil)
		req.AddCookie(cookie)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Origin", "https://"+host)
		req.Header.Set("Referer", "https://"+host+"/page")
		if err := req.Write(conn); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade returned %d", resp.StatusCode)
		}
		first, payload, err := readExtraOriginFrame(reader, false)
		if err != nil || first != 0x81 || strings.Contains(string(payload), "AcmeCorp") || !strings.HasSuffix(string(payload), " "+r.name) {
			t.Fatalf("masked server message: opcode=%x text=%q err=%v", first, payload, err)
		}
		// Return the delivered value, including an alias split between frames.
		cut := len(payload) / 2
		if err := writeExtraOriginFrame(conn, 0x01, payload[:cut], true); err != nil {
			t.Fatal(err)
		}
		if err := writeExtraOriginFrame(conn, 0x80, payload[cut:], true); err != nil {
			t.Fatal(err)
		}
		if err := writeExtraOriginFrame(conn, 0x88, []byte{3, 232}, true); err != nil {
			t.Fatal(err)
		}
		first, payload, err = readExtraOriginFrame(reader, false)
		if err != nil || first != 0x88 || !bytes.Equal(payload, []byte{3, 232}) {
			t.Fatalf("Close acknowledgment: opcode=%x payload=%x err=%v", first, payload, err)
		}
		select {
		case got := <-observed:
			if got.err != nil || got.route != r.name || got.host != r.url.Host || got.secure != (r.url.Scheme == "https") || got.uri != "/events?channel=one%20two&channel=three" || got.origin != r.upstream.URL || got.referer != r.upstream.URL+"/page" || got.cookie != wantCookie || got.text != "AcmeCorp "+r.name {
				t.Fatalf("incorrect routed session: %+v; want cookie=%q", got, wantCookie)
			}
		case <-time.After(time.Second):
			t.Fatal("upstream session observation missing")
		}
	}
	for _, r := range routes {
		t.Run(r.name, func(t *testing.T) { roundTrip(t, r, r.cookie, "session="+r.name+"-AcmeCorp-secret") })
	}
	t.Run("foreign-cookie-is-not-restored", func(t *testing.T) {
		roundTrip(t, routes[1], routes[0].cookie, "session="+routes[0].cookie.Value)
	})
}

// These small independent wire helpers deliberately support only the bounded
// frames used by this fixture; they do not share the relay implementation.
func writeExtraOriginFrame(w io.Writer, first byte, payload []byte, masked bool) error {
	if len(payload) > 125 {
		return fmt.Errorf("fixture payload too large: %d", len(payload))
	}
	frame := []byte{first, byte(len(payload))}
	if masked {
		frame[1] |= 0x80
		key := []byte{19, 73, 29, 61}
		frame = append(frame, key...)
		for i, b := range payload {
			frame = append(frame, b^key[i%4])
		}
	} else {
		frame = append(frame, payload...)
	}
	_, err := w.Write(frame)
	return err
}

func readExtraOriginFrame(r io.Reader, wantMasked bool) (byte, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	if (header[1]&0x80 != 0) != wantMasked || header[1]&0x7f > 125 {
		return 0, nil, fmt.Errorf("unexpected frame flags/length: %x", header)
	}
	var key [4]byte
	if wantMasked {
		if _, err := io.ReadFull(r, key[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, int(header[1]&0x7f))
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if wantMasked {
		for i := range payload {
			payload[i] ^= key[i%4]
		}
	}
	return header[0], payload, nil
}
