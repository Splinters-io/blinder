package ws

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestRelayRejectsInvalidFrames(t *testing.T) {
	for _, tc := range []struct {
		name           string
		frame          []byte
		serverToClient bool
	}{
		{"unsolicited continuation", append([]byte{0x80, 8}, []byte("AcmeCorp")...), true},
		{"unnegotiated compression", []byte{0xc1, 2, 'h', 'i'}, true},
		{"reserved opcode", []byte{0x83, 2, 'h', 'i'}, true},
		{"fragmented control", []byte{0x09, 0}, true},
		{"oversized control", append([]byte{0x89, 126, 0, 126}, make([]byte, 126)...), true},
		{"nonminimal length", []byte{0x81, 126, 0, 2, 'h', 'i'}, true},
		{"unmasked client", []byte{0x81, 2, 'h', 'i'}, false},
		{"masked server", []byte{0x81, 0x80, 0, 0, 0, 0}, true},
		{"invalid UTF8", []byte{0x81, 1, 0xff}, true},
		{"invalid close length", []byte{0x88, 1, 0}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := reviewRelay(t, tc.frame, tc.serverToClient); len(got) != 0 {
				t.Fatalf("forwarded invalid frame: %x", got)
			}
		})
	}
}

func TestRelayKeepsControlBetweenFragments(t *testing.T) {
	var input bytes.Buffer
	writeFrame(&input, opcodeText, []byte("Acme"), false)
	writeFrame(&input, finBit|opcodePing, []byte("ping"), false)
	writeFrame(&input, finBit, []byte("Corp"), false)
	var want bytes.Buffer
	writeFrame(&want, finBit|opcodePing, []byte("ping"), false)
	writeFrame(&want, finBit|opcodeText, []byte("[REDACTED]"), false)
	if got := reviewRelay(t, input.Bytes(), true); !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("got %x, want %x", got, want.Bytes())
	}
}

func TestRelayIdleTimeoutClosesBothDirections(t *testing.T) {
	client, relayClient := net.Pipe()
	defer client.Close()
	defer relayClient.Close()
	upstream, relayUpstream := net.Pipe()
	defer upstream.Close()
	defer relayUpstream.Close()
	p := NewProxy(scrub.NewGate(nil, nil, "alias.local"), "alias.local", "unused", "unused", false, true, "", 20*time.Millisecond, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.relay(relayClient, bufio.NewReadWriter(bufio.NewReader(relayClient), bufio.NewWriter(relayClient)), relayUpstream, bufio.NewReader(relayUpstream))
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle relay did not terminate")
	}
}

func TestUpgradeHeaderToken(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "not-an-upgrade")
	if IsUpgrade(r) {
		t.Fatal("substring of a header token accepted as an upgrade")
	}
}

func TestUpgradeResponseValidation(t *testing.T) {
	request, _ := http.NewRequest("GET", "http://alias.local/ws", nil)
	request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	request.Header.Set("Sec-WebSocket-Protocol", "chat, superchat")
	response := &http.Response{StatusCode: 101, Header: http.Header{}}
	response.Header.Set("Upgrade", "websocket")
	response.Header.Set("Connection", "Upgrade")
	// RFC 6455's independently specified handshake example.
	response.Header.Set("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
	response.Header.Set("Sec-WebSocket-Protocol", "chat")
	if !validUpgradeResponse(response, request) {
		t.Fatal("rejected RFC handshake")
	}
	for _, tc := range []struct{ key, value string }{
		{"Sec-WebSocket-Accept", "wrong"},
		{"Sec-WebSocket-Extensions", "permessage-deflate"},
		{"Sec-WebSocket-Protocol", "unoffered"},
		{"Connection", "not-an-upgrade"},
	} {
		clone := *response
		clone.Header = response.Header.Clone()
		clone.Header.Set(tc.key, tc.value)
		if validUpgradeResponse(&clone, request) {
			t.Errorf("accepted invalid %s", tc.key)
		}
	}
}

func TestUpgradeDoesNotOfferUnsupportedCompression(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://alias.local/ws", nil)
	r.Header.Set("Sec-WebSocket-Extensions", "permessage-deflate")
	got := buildUpgradeRequest(r, "target.test", "alias.local")
	if got.Header.Get("Sec-WebSocket-Extensions") != "" {
		t.Fatal("offered unsupported compression upstream")
	}
	if r.Header.Get("Sec-WebSocket-Extensions") == "" {
		t.Fatal("mutated incoming request")
	}
}

func TestCloseCancelsRelayConnections(t *testing.T) {
	p := NewProxy(scrub.NewGate(nil, nil, "alias.local"), "alias.local", "unused", "unused", false, true, "", time.Second, nil)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if !p.track(server) {
		t.Fatal("could not track open connection")
	}
	p.Close()
	if _, err := client.Write([]byte("x")); err == nil {
		t.Fatal("shutdown left connection open")
	}
	if p.track(server) {
		t.Fatal("allowed connection after shutdown")
	}
	if p.ctx.Err() == nil {
		t.Fatal("shutdown did not cancel pending dials")
	}
	p.Close()
}

func FuzzFrameValidation(f *testing.F) {
	f.Add([]byte{0x81, 2, 'h', 'i'})
	f.Add([]byte{0x80, 0})
	f.Add([]byte{0x81, 127, 0x80, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, frame []byte) {
		if len(frame) > 1024 {
			t.Skip()
		}
		// The reader is bounded and EOF-terminated; no network or unbounded input.
		readFrame(bufio.NewReader(bytes.NewReader(frame)), true)
	})
}

func TestRelayOneWayActivityKeepsConnectionAlive(t *testing.T) {
	client, relayClient := net.Pipe()
	defer client.Close()
	defer relayClient.Close()
	upstream, relayUpstream := net.Pipe()
	defer upstream.Close()
	defer relayUpstream.Close()
	p := NewProxy(scrub.NewGate(nil, nil, "alias.local"), "alias.local", "unused", "unused", false, true, "", 100*time.Millisecond, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.relay(relayClient, bufio.NewReadWriter(bufio.NewReader(relayClient), bufio.NewWriter(relayClient)), relayUpstream, bufio.NewReader(relayUpstream))
	}()
	readDone := make(chan struct{})
	go func() { defer close(readDone); io.Copy(io.Discard, client) }()
	defer func() { client.Close(); upstream.Close(); <-done; <-readDone }()
	for i := 0; i < 12; i++ {
		upstream.SetWriteDeadline(time.Now().Add(time.Second))
		if err := writeFrame(upstream, finBit|opcodeText, []byte("hello"), false); err != nil {
			t.Fatalf("active one-way relay closed: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("closed while upstream was active")
	default:
	}
}
