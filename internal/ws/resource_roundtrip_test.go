package ws

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/rewriter"
	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestWebSocketSubmittedResourceURLRoundTrip(t *testing.T) {
	mapper := mustMapper(t, routeURL(t, "http://main.example:8080"), "127.0.0.1:18099", "alias.local")
	gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	alias := gate.Scrub("AcmeCorp", "fixture")
	p := NewProxy(gate, "alias.local", "main.example:8080", "unused", false, true, "", time.Second, func() *rewriter.OriginMapper { return mapper })
	defer p.Close()
	for _, tc := range []struct {
		name, input, want string
		reject            bool
	}{
		{"plain", "https://127.0.0.1:18099/return", "http://main.example:8080/return", false},
		{"websocket", "wss://127.0.0.1:18099/socket", "ws://main.example:8080/socket", false},
		{"json", `{ "n":9007199254740993,"url":"https://127.0.0.1:18099/return","keep":"\u0041" }`, `{ "n":9007199254740993,"url":"http://main.example:8080/return","keep":"\u0041" }`, false},
		{"trailing", `{"url":"https://127.0.0.1:18099/return"} extra`, `{"url":"https://127.0.0.1:18099/return"} extra`, false},
		{"embedded", `log: https://127.0.0.1:18099/return`, `log: https://127.0.0.1:18099/return`, false},
		{"number-leading-text", "42 " + alias, "42 AcmeCorp", false},
		{"json-leading-text", `{"n":42} ` + alias, `{"n":42} AcmeCorp`, false},
		{"collision", `{"https://127.0.0.1:18099/k":1,"http://main.example:8080/k":2}`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var frames bytes.Buffer
			middle := len(tc.input) / 2
			if err := writeFrame(&frames, opcodeText, []byte(tc.input[:middle]), true); err != nil {
				t.Fatal(err)
			}
			if err := writeFrame(&frames, finBit, []byte(tc.input[middle:]), true); err != nil {
				t.Fatal(err)
			}
			dst, reader := net.Pipe()
			defer reader.Close()
			done := make(chan struct{})
			go func() { defer close(done); defer dst.Close(); p.relayFrames(bufio.NewReader(&frames), dst, false, nil) }()
			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			<-done
			if tc.reject {
				if len(got) != 0 {
					t.Fatal("colliding JSON was forwarded")
				}
				return
			}
			_, payload, ok := readFrame(bufio.NewReader(bytes.NewReader(got)), false)
			if !ok || string(payload) != tc.want {
				t.Fatalf("payload=%q valid=%v want=%q", payload, ok, tc.want)
			}
		})
	}
}

func TestWebSocketDomainOnlyURLResponseRoundTrip(t *testing.T) {
	mapper := mustMapper(t, routeURL(t, "http://main.example:8080"), "127.0.0.1:18099", "alias.local")
	p := NewProxy(scrub.NewGate([]string{"main.example"}, nil, "alias.local"), "alias.local", "main.example:8080", "unused", false, true, "", time.Second, func() *rewriter.OriginMapper { return mapper })
	defer p.Close()
	relay := func(payload []byte, serverToClient bool) []byte {
		t.Helper()
		var input bytes.Buffer
		if err := writeFrame(&input, finBit|opcodeText, payload, !serverToClient); err != nil {
			t.Fatal(err)
		}
		dst, reader := net.Pipe()
		defer reader.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer dst.Close()
			p.relayFrames(bufio.NewReader(&input), dst, serverToClient, nil)
		}()
		output, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		<-done
		_, result, ok := readFrame(bufio.NewReader(bytes.NewReader(output)), serverToClient)
		if !ok {
			t.Fatalf("invalid relayed frame: %x", output)
		}
		return result
	}
	for _, original := range []string{"http://main.example:8080/return", `{"url":"http://main.example:8080/return","n":9007199254740993}`} {
		view := relay([]byte(original), true)
		if strings.Contains(string(view), "main.example") {
			t.Fatalf("response leaked target: %s", view)
		}
		if got := string(relay(view, false)); got != original {
			t.Fatalf("server %s => client %s => server %s", original, view, got)
		}
	}
}
