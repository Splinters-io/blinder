package ws

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func closeHandshakeRelay(t *testing.T, idle time.Duration) (*Proxy, net.Conn, net.Conn, <-chan struct{}) {
	t.Helper()
	client, relayClient := net.Pipe()
	upstream, relayUpstream := net.Pipe()
	p := NewProxy(scrub.NewGate(nil, nil, "alias.local"), "alias.local", "unused", "unused", false, true, "", idle, nil)
	p.track(relayClient)
	p.track(relayUpstream)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer p.release(relayClient)
		defer p.release(relayUpstream)
		p.relay(relayClient, bufio.NewReadWriter(bufio.NewReader(relayClient), bufio.NewWriter(relayClient)), relayUpstream, bufio.NewReader(relayUpstream))
	}()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	upstream.SetDeadline(time.Now().Add(2 * time.Second))
	t.Cleanup(func() {
		client.Close()
		upstream.Close()
		p.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("relay did not stop after cleanup")
		}
	})
	return p, client, upstream, done
}

func TestRelayCloseHandshakeBothDirections(t *testing.T) {
	for _, clientInitiates := range []bool{true, false} {
		name := "upstream"
		if clientInitiates {
			name = "client"
		}
		t.Run(name, func(t *testing.T) {
			_, client, upstream, done := closeHandshakeRelay(t, time.Second)
			initiator, peer := upstream, client
			if clientInitiates {
				initiator, peer = client, upstream
			}
			payload := []byte{3, 232} // Normal closure, 1000.
			if err := writeFrame(initiator, finBit|opcodeClose, payload, clientInitiates); err != nil {
				t.Fatal(err)
			}
			first, body, ok := readFrame(bufio.NewReader(peer), !clientInitiates)
			if !ok || first != finBit|opcodeClose || !bytes.Equal(body, payload) {
				t.Fatalf("peer did not receive initial Close: %x %x %v", first, body, ok)
			}
			// A real peer is not required to acknowledge in the same scheduler turn.
			select {
			case <-done:
				t.Fatal("relay closed the transport before the peer could acknowledge Close")
			case <-time.After(20 * time.Millisecond):
			}
			if err := writeFrame(peer, finBit|opcodeClose, payload, !clientInitiates); err != nil {
				t.Fatalf("peer Close acknowledgment: %v", err)
			}
			first, body, ok = readFrame(bufio.NewReader(initiator), clientInitiates)
			if !ok || first != finBit|opcodeClose || !bytes.Equal(body, payload) {
				t.Fatalf("initiator lost Close acknowledgment: %x %x %v", first, body, ok)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("completed close handshake left relay running")
			}
		})
	}
}

func TestRelayDropsDataWhileAwaitingClose(t *testing.T) {
	_, client, upstream, _ := closeHandshakeRelay(t, time.Second)
	if err := writeFrame(client, finBit|opcodeClose, nil, true); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := readFrame(bufio.NewReader(upstream), false); !ok {
		t.Fatal("upstream did not receive Close")
	}
	if err := writeFrame(upstream, finBit|opcodeText, []byte("late message"), false); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() { writeDone <- writeFrame(upstream, finBit|opcodeClose, nil, false) }()
	first, _, ok := readFrame(bufio.NewReader(client), true)
	if !ok || first != finBit|opcodeClose {
		t.Fatalf("expected Close acknowledgment, received data or EOF: %x %v", first, ok)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestRelayCloseWaitIsBoundedDespitePeerActivity(t *testing.T) {
	_, client, upstream, done := closeHandshakeRelay(t, 80*time.Millisecond)
	if err := writeFrame(client, finBit|opcodeClose, nil, true); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := readFrame(bufio.NewReader(upstream), false); !ok {
		t.Fatal("upstream did not receive Close")
	}
	readDone := make(chan struct{})
	go func() { defer close(readDone); io.Copy(io.Discard, client) }()
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		for {
			if err := writeFrame(upstream, finBit|opcodePing, []byte("alive"), false); err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Error("peer activity indefinitely extended Close handshake")
	}
	upstream.Close()
	client.Close()
	<-writeDone
	<-readDone
}

func TestRelayCloseWaitStopsOnInvalidPeerOrShutdown(t *testing.T) {
	for _, tc := range []struct {
		name    string
		invalid []byte
	}{
		{"masked server frame", []byte{finBit | opcodeClose, maskBit}},
		{"invalid text", []byte{finBit | opcodeText, 1, 0xff}},
		{"orphan continuation", []byte{finBit, 0}},
		{"proxy shutdown", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, client, upstream, done := closeHandshakeRelay(t, time.Second)
			if err := writeFrame(client, finBit|opcodeClose, nil, true); err != nil {
				t.Fatal(err)
			}
			if _, _, ok := readFrame(bufio.NewReader(upstream), false); !ok {
				t.Fatal("upstream did not receive Close")
			}
			if tc.invalid == nil {
				p.Close()
			} else {
				if _, err := upstream.Write(tc.invalid); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-done:
			case <-time.After(250 * time.Millisecond):
				t.Fatal("fatal termination waited for Close grace period")
			}
		})
	}
}

func TestRelaySimultaneousClose(t *testing.T) {
	_, client, upstream, done := closeHandshakeRelay(t, time.Second)
	writes := make(chan error, 2)
	go func() { writes <- writeFrame(client, finBit|opcodeClose, []byte{3, 232}, true) }()
	go func() { writes <- writeFrame(upstream, finBit|opcodeClose, []byte{3, 233}, false) }()
	for i := 0; i < 2; i++ {
		if err := <-writes; err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		conn           net.Conn
		serverToClient bool
		payload        []byte
	}{
		{client, true, []byte{3, 233}},
		{upstream, false, []byte{3, 232}},
	} {
		first, body, ok := readFrame(bufio.NewReader(tc.conn), tc.serverToClient)
		if !ok || first != finBit|opcodeClose || !bytes.Equal(body, tc.payload) {
			t.Fatalf("simultaneous Close lost: %x %x %v", first, body, ok)
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("simultaneous Close did not terminate relay")
	}
}

func TestRelayCloseWriteIsBounded(t *testing.T) {
	_, client, _, done := closeHandshakeRelay(t, 80*time.Millisecond)
	if err := writeFrame(client, finBit|opcodeClose, nil, true); err != nil {
		t.Fatal(err)
	}
	// The upstream never reads the forwarded Close, so that write is blocked.
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked Close write left relay running")
	}
}

func TestRelayCloseWaitStopsOnPeerEOF(t *testing.T) {
	_, client, upstream, done := closeHandshakeRelay(t, time.Second)
	if err := writeFrame(client, finBit|opcodeClose, nil, true); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := readFrame(bufio.NewReader(upstream), false); !ok {
		t.Fatal("upstream did not receive Close")
	}
	upstream.Close()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("peer EOF waited for Close grace period")
	}
}
