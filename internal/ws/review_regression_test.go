package ws

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func reviewRelay(t *testing.T, input []byte, serverToClient bool) []byte {
	t.Helper()
	p := NewProxy(scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local"), "alias.local", "acmecorp.io", "unused", false, true, "", time.Second, nil)
	dst, reader := net.Pipe()
	defer reader.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer dst.Close()
		p.relayFrames(bufio.NewReader(bytes.NewReader(input)), dst, serverToClient)
	}()
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	return got
}

func TestReviewClientFramesRemainMasked(t *testing.T) {
	frame := []byte{0x81, 0x82, 1, 2, 3, 4, 'o' ^ 1, 'k' ^ 2}
	got := reviewRelay(t, frame, false)
	if len(got) < 2 || got[1]&0x80 == 0 {
		t.Fatalf("proxy sends unmasked frame upstream: %x", got)
	}
}

func TestReviewFragmentedTextIsScrubbed(t *testing.T) {
	frame := append([]byte{0x01, 0x02}, []byte("hi")...)
	frame = append(frame, 0x80, 0x08)
	frame = append(frame, []byte("AcmeCorp")...)
	got := reviewRelay(t, frame, true)
	if bytes.Contains(got, []byte("AcmeCorp")) {
		t.Errorf("continuation frame leaks token: %q", got)
	}
}

func TestReviewHugeFrameIsRejectedBeforeAllocation(t *testing.T) {
	p := NewProxy(scrub.NewGate(nil, nil, "alias.local"), "alias.local", "example.com", "unused", false, true, "", time.Second, nil)
	dst, reader := net.Pipe()
	defer dst.Close()
	defer reader.Close()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("untrusted frame header panics relay: %v", r)
		}
	}()
	frame := []byte{0x81, 0x7f, 0x80, 0, 0, 0, 0, 0, 0, 0}
	p.relayFrames(bufio.NewReader(strings.NewReader(string(frame))), dst, true)
}
