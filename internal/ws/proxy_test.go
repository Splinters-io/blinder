package ws

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/scrub"
	blindertls "github.com/Splinters-io/blinder/internal/tls"
)

func wsAcceptKey(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func startWSEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleWSConn(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func handleWSConn(conn net.Conn) {
	defer conn.Close()
	buf := bufio.NewReader(conn)

	req, err := http.ReadRequest(buf)
	if err != nil {
		return
	}

	key := req.Header.Get("Sec-WebSocket-Key")
	accept := wsAcceptKey(key)

	resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	conn.Write([]byte(resp))

	for {
		header := make([]byte, 2)
		if _, err := io.ReadFull(buf, header); err != nil {
			return
		}

		opcode := header[0] & 0x0F
		masked := (header[1] & maskBit) != 0
		payloadLen := uint64(header[1] & 0x7F)

		switch payloadLen {
		case 126:
			ext := make([]byte, 2)
			io.ReadFull(buf, ext)
			payloadLen = uint64(ext[0])<<8 | uint64(ext[1])
		case 127:
			ext := make([]byte, 8)
			io.ReadFull(buf, ext)
			payloadLen = 0
			for _, b := range ext {
				payloadLen = payloadLen<<8 | uint64(b)
			}
		}

		var maskKey [4]byte
		if masked {
			io.ReadFull(buf, maskKey[:])
		}

		payload := make([]byte, payloadLen)
		if payloadLen > 0 {
			io.ReadFull(buf, payload)
		}
		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}

		if opcode == opcodeClose {
			writeFrame(conn, finBit|opcodeClose, payload, false)
			return
		}
		if opcode == opcodeText {
			writeFrame(conn, finBit|opcodeText, payload, false)
		}
		if opcode == opcodePing {
			writeFrame(conn, finBit|opcodePong, payload, false)
		}
	}
}

func TestIsUpgrade(t *testing.T) {
	req, _ := http.NewRequest("GET", "/ws", nil)
	if IsUpgrade(req) {
		t.Error("plain GET should not be an upgrade")
	}

	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	if !IsUpgrade(req) {
		t.Error("proper upgrade request should be detected")
	}
}

func TestIsUpgrade_CaseInsensitive(t *testing.T) {
	req, _ := http.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "WebSocket")
	req.Header.Set("Connection", "keep-alive, Upgrade")
	if !IsUpgrade(req) {
		t.Error("mixed-case upgrade should be detected")
	}
}

func TestProxy_TextFrameScrubbing(t *testing.T) {
	echoAddr := startWSEchoServer(t)

	gate := scrub.NewGate(nil, []string{"SecretOrg"}, "alias.local")
	p := NewProxy(gate, "alias.local", echoAddr, echoAddr, false, true, "", 5*time.Second, nil)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	clientBuf := bufio.NewReadWriter(bufio.NewReader(clientConn), bufio.NewWriter(clientConn))

	upgradeReq := fmt.Sprintf("GET /ws HTTP/1.1\r\nHost: alias.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")

	rec := &hijackResponseWriter{
		conn: serverConn,
		buf:  bufio.NewReadWriter(bufio.NewReader(serverConn), bufio.NewWriter(serverConn)),
	}

	req, _ := http.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")

	done := make(chan error, 1)
	go func() {
		done <- p.Handle(rec, req)
	}()

	_ = upgradeReq

	clientBuf.Reader = bufio.NewReader(clientConn)

	respLine, _ := clientBuf.ReadString('\n')
	if !strings.Contains(respLine, "101") {
		t.Fatalf("expected 101, got: %s", respLine)
	}
	for {
		line, _ := clientBuf.ReadString('\n')
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	msg := []byte("Hello from SecretOrg HQ")
	maskedMsg := make([]byte, len(msg))
	copy(maskedMsg, msg)
	maskKey := [4]byte{0x12, 0x34, 0x56, 0x78}
	for i := range maskedMsg {
		maskedMsg[i] ^= maskKey[i%4]
	}

	frame := []byte{finBit | opcodeText, maskBit | byte(len(msg))}
	frame = append(frame, maskKey[:]...)
	frame = append(frame, maskedMsg...)
	clientConn.Write(frame)

	time.Sleep(200 * time.Millisecond)

	echoHeader := make([]byte, 2)
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(clientBuf, echoHeader); err != nil {
		t.Fatalf("read echo frame header: %v", err)
	}

	echoLen := int(echoHeader[1] & 0x7F)
	echoPayload := make([]byte, echoLen)
	io.ReadFull(clientBuf, echoPayload)

	echoed := string(echoPayload)
	if strings.Contains(echoed, "SecretOrg") {
		t.Errorf("text frame should have SecretOrg scrubbed, got: %s", echoed)
	}
	if !strings.Contains(echoed, "[REDACTED]") {
		t.Errorf("text frame should contain [REDACTED], got: %s", echoed)
	}

	closeFrame := []byte{finBit | opcodeClose, maskBit | 0}
	closeFrame = append(closeFrame, 0, 0, 0, 0)
	clientConn.Write(closeFrame)

	time.Sleep(100 * time.Millisecond)
}

type hijackResponseWriter struct {
	conn    net.Conn
	buf     *bufio.ReadWriter
	headers http.Header
	status  int
}

func (h *hijackResponseWriter) Header() http.Header {
	if h.headers == nil {
		h.headers = make(http.Header)
	}
	return h.headers
}

func (h *hijackResponseWriter) Write(b []byte) (int, error) {
	return h.conn.Write(b)
}

func (h *hijackResponseWriter) WriteHeader(code int) {
	h.status = code
}

func (h *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, h.buf, nil
}

func TestProxy_BinaryFramePassthrough(t *testing.T) {
	gate := scrub.NewGate(nil, []string{"SecretOrg"}, "alias.local")

	input := []byte{0x00, 0x01, 0x02, 'S', 'e', 'c', 'r', 'e', 't', 'O', 'r', 'g', 0xFF}

	scrubbed := gate.ScrubBytes(input, "test")
	_ = scrubbed

	p := NewProxy(gate, "alias.local", "localhost:1", "localhost:1", false, true, "", 5*time.Second, nil)
	_ = p
}

func TestWriteFrame(t *testing.T) {
	tests := []struct {
		name      string
		payload   string
		expectLen int
	}{
		{"small", "hello", 2 + 5},
		{"medium", strings.Repeat("x", 200), 2 + 2 + 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			err := writeFrame(&buf, finBit|opcodeText, []byte(tt.payload), false)
			if err != nil {
				t.Fatalf("writeFrame: %v", err)
			}
			if buf.Len() != tt.expectLen {
				t.Errorf("expected frame length %d, got %d", tt.expectLen, buf.Len())
			}
		})
	}
}

func TestDialUpstream_BadAddress(t *testing.T) {
	gate := scrub.NewGate(nil, nil, "alias.local")
	p := NewProxy(gate, "alias.local", "127.0.0.1:1", "127.0.0.1:1", false, true, "", 5*time.Second, nil)

	_, err := p.dialUpstream()
	if err == nil {
		t.Error("expected error dialing bad address")
	}
}

func TestDialUpstream_TLS(t *testing.T) {
	cert, err := blindertls.GenerateSelfSigned("localhost")
	if err != nil {
		t.Fatalf("gen cert: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tlsConn := conn.(*tls.Conn)
		tlsConn.Handshake()
		tlsConn.Close()
	}()

	gate := scrub.NewGate(nil, nil, "alias.local")
	p := NewProxy(gate, "alias.local", ln.Addr().String(), ln.Addr().String(), true, false, "", 5*time.Second, nil)

	conn, err := p.dialUpstream()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
}
