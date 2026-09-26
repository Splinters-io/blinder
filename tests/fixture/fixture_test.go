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
	"os/exec"
	"testing"
	"time"
)

func TestWebSocketFixtureNavigationLifecycle(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for fixture browser-lifecycle checks")
	}
	if output, err := exec.Command(node, "websocket_test.js").CombinedOutput(); err != nil {
		t.Fatalf("browser lifecycle: %v\n%s", err, output)
	}
}

func TestWebSocketFixtureKeepsManualSessionActive(t *testing.T) {
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		websocketWithHeartbeat(w, r, 10*time.Millisecond)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", u.Host)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: response=%v err=%v", response, err)
	}
	want := []byte{0x01, 4, 'A', 'c', 'm', 'e', 0x80, 9, 'C', 'o', 'r', 'p', ' ', 'l', 'i', 'v', 'e'}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("fragmented message %q, error %v", got, err)
	}
	for i := 0; i < 2; i++ {
		ping := make([]byte, 2)
		if _, err := io.ReadFull(reader, ping); err != nil || !bytes.Equal(ping, []byte{0x89, 0}) {
			t.Fatalf("heartbeat %d: %x, error %v", i, ping, err)
		}
		if _, err := conn.Write([]byte{0x8a, 0x80, 1, 2, 3, 4}); err != nil {
			t.Fatal(err)
		}
	}
	conn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fixture heartbeat survived client disconnect")
	}
}
