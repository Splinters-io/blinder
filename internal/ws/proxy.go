package ws

import (
	"bufio"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Splinters-io/blinder/internal/scrub"
)

const (
	opcodeText  = 0x1
	opcodeBin   = 0x2
	opcodeClose = 0x8
	opcodePing  = 0x9
	opcodePong  = 0xA

	finBit  = 0x80
	maskBit = 0x80

	maxFrameSize = 16 * 1024 * 1024
)

var (
	ErrNotWebSocket  = errors.New("not a websocket upgrade request")
	ErrUpstreamDial  = errors.New("failed to dial upstream for websocket")
	ErrUpgradeRefused = errors.New("upstream refused websocket upgrade")
)

type Proxy struct {
	gate        *scrub.Gate
	aliasDomain string
	targetHost  string
	targetAddr  string
	useTLS      bool
	verifyTLS   bool
	socksAddr   string
	idleTimeout time.Duration
}

func NewProxy(gate *scrub.Gate, aliasDomain, targetHost, targetAddr string, useTLS, verifyTLS bool, socksAddr string, idleTimeout time.Duration) *Proxy {
	if idleTimeout <= 0 {
		idleTimeout = 5 * time.Minute
	}
	return &Proxy{
		gate:        gate,
		aliasDomain: aliasDomain,
		targetHost:  targetHost,
		targetAddr:  targetAddr,
		useTLS:      useTLS,
		verifyTLS:   verifyTLS,
		socksAddr:   socksAddr,
		idleTimeout: idleTimeout,
	}
}

func IsUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func (p *Proxy) Handle(w http.ResponseWriter, r *http.Request) error {
	if !IsUpgrade(r) {
		return ErrNotWebSocket
	}

	upstreamConn, err := p.dialUpstream()
	if err != nil {
		http.Error(w, "websocket upstream error", http.StatusBadGateway)
		return fmt.Errorf("%w: %v", ErrUpstreamDial, err)
	}

	upgradeReq := buildUpgradeRequest(r, p.targetHost, p.aliasDomain)
	if err := upgradeReq.Write(upstreamConn); err != nil {
		upstreamConn.Close()
		http.Error(w, "websocket upstream error", http.StatusBadGateway)
		return fmt.Errorf("write upgrade: %w", err)
	}

	upstreamBuf := bufio.NewReader(upstreamConn)
	upstreamResp, err := http.ReadResponse(upstreamBuf, upgradeReq)
	if err != nil {
		upstreamConn.Close()
		http.Error(w, "websocket upstream error", http.StatusBadGateway)
		return fmt.Errorf("read upgrade response: %w", err)
	}

	if upstreamResp.StatusCode != http.StatusSwitchingProtocols {
		upstreamConn.Close()
		http.Error(w, "websocket upgrade refused", http.StatusBadGateway)
		return fmt.Errorf("%w: got %d", ErrUpgradeRefused, upstreamResp.StatusCode)
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstreamConn.Close()
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return errors.New("ResponseWriter does not support Hijack")
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		upstreamConn.Close()
		return fmt.Errorf("hijack: %w", err)
	}

	switchResp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n")
	if secAccept := upstreamResp.Header.Get("Sec-WebSocket-Accept"); secAccept != "" {
		switchResp += fmt.Sprintf("Sec-WebSocket-Accept: %s\r\n", secAccept)
	}
	if proto := upstreamResp.Header.Get("Sec-WebSocket-Protocol"); proto != "" {
		switchResp += fmt.Sprintf("Sec-WebSocket-Protocol: %s\r\n", proto)
	}
	switchResp += "\r\n"

	if _, err := clientConn.Write([]byte(switchResp)); err != nil {
		clientConn.Close()
		upstreamConn.Close()
		return fmt.Errorf("write 101: %w", err)
	}

	log.Printf("[ws] upgrade complete, relaying frames")

	p.relay(clientConn, clientBuf, upstreamConn, upstreamBuf)
	return nil
}

func (p *Proxy) relay(clientConn net.Conn, clientBuf *bufio.ReadWriter, upstreamConn net.Conn, upstreamBuf *bufio.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		p.relayFrames(upstreamBuf, clientConn, true)
		clientConn.Close()
	}()

	go func() {
		defer wg.Done()
		p.relayFrames(clientBuf.Reader, upstreamConn, false)
		upstreamConn.Close()
	}()

	wg.Wait()
}

func (p *Proxy) relayFrames(src *bufio.Reader, dst net.Conn, serverToClient bool) {
	inTextMessage := false

	for {
		dst.SetWriteDeadline(time.Now().Add(p.idleTimeout))

		header := make([]byte, 2)
		if _, err := io.ReadFull(src, header); err != nil {
			return
		}

		fin := (header[0] & finBit) != 0
		opcode := header[0] & 0x0F
		masked := (header[1] & maskBit) != 0
		payloadLen := uint64(header[1] & 0x7F)

		switch payloadLen {
		case 126:
			ext := make([]byte, 2)
			if _, err := io.ReadFull(src, ext); err != nil {
				return
			}
			payloadLen = uint64(binary.BigEndian.Uint16(ext))
		case 127:
			ext := make([]byte, 8)
			if _, err := io.ReadFull(src, ext); err != nil {
				return
			}
			payloadLen = binary.BigEndian.Uint64(ext)
		}

		if payloadLen > maxFrameSize {
			return
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(src, maskKey[:]); err != nil {
				return
			}
		}

		payload := make([]byte, payloadLen)
		if payloadLen > 0 {
			if _, err := io.ReadFull(src, payload); err != nil {
				return
			}
		}

		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}

		if opcode == opcodeText {
			inTextMessage = true
		} else if opcode == opcodeBin {
			inTextMessage = false
		}

		isTextContent := opcode == opcodeText || (opcode == 0 && inTextMessage)

		if serverToClient && isTextContent {
			payload = p.gate.ScrubBytes(payload, "ws:text")
		}

		if !serverToClient && isTextContent {
			text := string(payload)
			text = strings.ReplaceAll(text, p.aliasDomain, p.targetHost)
			payload = []byte(text)
		}

		if fin && (opcode == opcodeText || opcode == 0) {
			inTextMessage = false
		}

		needMask := !serverToClient
		if err := writeFrame(dst, header[0], payload, needMask); err != nil {
			return
		}

		if opcode == opcodeClose {
			return
		}
	}
}

func writeFrame(w io.Writer, firstByte byte, payload []byte, mask bool) error {
	frame := []byte{firstByte}

	length := len(payload)
	var lenByte byte
	switch {
	case length <= 125:
		lenByte = byte(length)
	case length <= 65535:
		lenByte = 126
	default:
		lenByte = 127
	}
	if mask {
		lenByte |= maskBit
	}
	frame = append(frame, lenByte)

	switch {
	case length > 125 && length <= 65535:
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(length))
		frame = append(frame, ext...)
	case length > 65535:
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(length))
		frame = append(frame, ext...)
	}

	if mask {
		var key [4]byte
		crand.Read(key[:])
		frame = append(frame, key[:]...)
		masked := make([]byte, len(payload))
		for i, b := range payload {
			masked[i] = b ^ key[i%4]
		}
		frame = append(frame, masked...)
	} else {
		frame = append(frame, payload...)
	}

	_, err := w.Write(frame)
	return err
}

func (p *Proxy) dialUpstream() (net.Conn, error) {
	addr := p.targetAddr
	if !strings.Contains(addr, ":") {
		if p.useTLS {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}

	var conn net.Conn
	var err error

	if p.socksAddr != "" {
		conn, err = dialSOCKS5(p.socksAddr, addr)
	} else {
		conn, err = net.DialTimeout("tcp", addr, 30*time.Second)
	}
	if err != nil {
		return nil, err
	}

	if p.useTLS {
		host, _, _ := net.SplitHostPort(addr)
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: !p.verifyTLS,
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		return tlsConn, nil
	}

	return conn, nil
}

func dialSOCKS5(socksAddr, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", socksAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	conn.Write([]byte{0x05, 0x01, 0x00})

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 auth rejected: %x", resp)
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port&0xFF))
	conn.Write(req)

	connResp := make([]byte, 4)
	if _, err := io.ReadFull(conn, connResp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect: %w", err)
	}
	if connResp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect failed: status %d", connResp[1])
	}

	switch connResp[3] {
	case 0x01:
		discard := make([]byte, 4+2)
		io.ReadFull(conn, discard)
	case 0x03:
		lenByte := make([]byte, 1)
		io.ReadFull(conn, lenByte)
		discard := make([]byte, int(lenByte[0])+2)
		io.ReadFull(conn, discard)
	case 0x04:
		discard := make([]byte, 16+2)
		io.ReadFull(conn, discard)
	}

	return conn, nil
}

func buildUpgradeRequest(r *http.Request, targetHost, aliasDomain string) *http.Request {
	outReq := r.Clone(r.Context())
	outReq.Host = targetHost
	outReq.URL.Host = targetHost
	outReq.URL.Scheme = "http"
	outReq.RequestURI = r.URL.RequestURI()

	if ref := outReq.Header.Get("Origin"); ref != "" {
		outReq.Header.Set("Origin", strings.ReplaceAll(ref, aliasDomain, targetHost))
	}

	outReq.Header.Del("Accept-Encoding")

	return outReq
}
