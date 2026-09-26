package fixture

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func openControlFixture(t *testing.T, interval time.Duration) (net.Conn, *bufio.Reader, <-chan struct{}) {
	t.Helper()
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		websocketWithHeartbeat(w, r, interval)
	}))
	t.Cleanup(server.Close)
	u, _ := url.Parse(server.URL)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", u.Host)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: response=%v error=%v", response, err)
	}
	want := []byte{0x01, 4, 'A', 'c', 'm', 'e', 0x80, 9, 'C', 'o', 'r', 'p', ' ', 'l', 'i', 'v', 'e'}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("initial fragmented message=%x error=%v", got, err)
	}
	return conn, reader, done
}

func sendFixtureControl(t *testing.T, conn net.Conn, opcode byte, payload []byte) {
	t.Helper()
	mask := [4]byte{0x31, 0x72, 0x25, 0x44}
	frame := append([]byte{0x80 | opcode, 0x80 | byte(len(payload))}, mask[:]...)
	for i, value := range payload {
		frame = append(frame, value^mask[i%4])
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
}

func readFixtureControl(t *testing.T, reader *bufio.Reader) (byte, []byte) {
	t.Helper()
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		t.Fatal(err)
	}
	if header[0]&0xf0 != 0x80 || header[1] > 125 {
		t.Fatalf("malformed server control frame header=%x", header)
	}
	payload := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatal(err)
	}
	return header[0] & 15, payload
}

func TestWebSocketFixtureAcknowledgesCloseAndStops(t *testing.T) {
	conn, reader, done := openControlFixture(t, time.Hour)
	closePayload := append([]byte{0x03, 0xe8}, []byte("page hidden")...)
	sendFixtureControl(t, conn, 8, closePayload)
	opcode, payload := readFixtureControl(t, reader)
	if opcode != 8 || !bytes.Equal(payload, closePayload) {
		t.Fatalf("close acknowledgement opcode=%d payload=%x, want 1000 with original reason", opcode, payload)
	}
	if extra, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("bytes after close acknowledgement: %x error=%v", extra, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fixture handler remained alive after closing handshake")
	}
}

func TestWebSocketFixtureRepliesToPingWhileHeartbeating(t *testing.T) {
	conn, reader, done := openControlFixture(t, 5*time.Millisecond)
	want := []byte{0, 0xff, 'p', 'i', 'n', 'g'}
	sendFixtureControl(t, conn, 9, want)
	heartbeats, gotPong := 0, false
	for heartbeats < 2 || !gotPong {
		opcode, payload := readFixtureControl(t, reader)
		switch opcode {
		case 9:
			if len(payload) != 0 {
				t.Fatalf("heartbeat payload=%x", payload)
			}
			heartbeats++
			sendFixtureControl(t, conn, 10, payload)
		case 10:
			if gotPong || !bytes.Equal(payload, want) {
				t.Fatalf("pong payload=%x duplicate=%v", payload, gotPong)
			}
			gotPong = true
		default:
			t.Fatalf("unexpected opcode=%d", opcode)
		}
	}
	closePayload := []byte{0x03, 0xe8}
	sendFixtureControl(t, conn, 8, closePayload)
	for {
		opcode, payload := readFixtureControl(t, reader)
		if opcode == 8 {
			if !bytes.Equal(payload, closePayload) {
				t.Fatalf("close payload=%x", payload)
			}
			break
		}
		if opcode != 9 || len(payload) != 0 {
			t.Fatalf("unexpected frame while closing opcode=%d payload=%x", opcode, payload)
		}
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("stream did not end after close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat worker remained alive after close")
	}
}

func TestWebSocketFixtureRejectsOversizedFrameWithoutReadingPayload(t *testing.T) {
	conn, reader, done := openControlFixture(t, time.Hour)
	// An eight-byte payload length already exceeds this synthetic fixture's
	// frame budget. Do not send the rest: rejection must not wait for the body.
	if _, err := conn.Write([]byte{0x82, 0xff}); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("oversized frame was not rejected: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fixture kept reading an oversized frame")
	}
}
