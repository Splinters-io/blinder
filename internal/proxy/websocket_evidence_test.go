package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/har"
	"github.com/Splinters-io/blinder/internal/manifest"
)

func evidenceUpgrade(t *testing.T, addr string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req, _ := http.NewRequest("GET", "https://"+addr+"/socket?mode=test", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Protocol", "chat")
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		t.Fatal(err)
	}
	return conn, reader, resp
}

func waitWSManifest(t *testing.T, srv *Server) manifest.RequestEntry {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		entries := srv.Manifest().Requests()
		if len(entries) == 1 {
			return entries[0]
		}
		if len(entries) > 1 {
			t.Fatalf("duplicate WS manifest entries: %d", len(entries))
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("WS handshake absent from manifest")
	return manifest.RequestEntry{}
}

func TestWebSocketRefusalPreservesHTTPAndEvidence(t *testing.T) {
	for _, status := range []int{403, 302, 401, 204, 304} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			const original = `<html><body><pre>AcmeCorp E_RATE: retry this request</pre></body></html>`
			var encoded bytes.Buffer
			gz := gzip.NewWriter(&encoded)
			_, _ = gz.Write([]byte(original))
			_ = gz.Close()
			var hits atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("X-Diagnostic", "AcmeCorp E_RATE")
				w.Header().Set("Retry-After", "7")
				w.Header().Add("Set-Cookie", "session=AcmeCorp; Path=/; HttpOnly")
				w.Header().Set("WWW-Authenticate", `Basic realm="AcmeCorp"`)
				w.Header().Set("Location", "http://"+r.Host+"/retry")
				if status == 403 {
					w.WriteHeader(http.StatusEarlyHints)
				}
				w.WriteHeader(status)
				if status != 204 && status != 304 {
					_, _ = w.Write(encoded.Bytes())
				}
			}))
			defer target.Close()
			cfg := newTestConfig(t, target.URL)
			cfg.Paranoid = true
			srv, addr := startTestProxy(t, cfg)
			path := filepath.Join(t.TempDir(), "ws.har")
			srv.harWriter = har.NewWriter(path, 4096, 100)
			conn, _, resp := evidenceUpgrade(t, addr)
			defer conn.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != status || hits.Load() != 1 {
				t.Fatalf("status=%d upstream requests=%d", resp.StatusCode, hits.Load())
			}
			if resp.Header.Get("Retry-After") != "7" || !strings.Contains(resp.Header.Get("X-Diagnostic"), "E_RATE") || strings.Contains(resp.Header.Get("X-Diagnostic"), "AcmeCorp") || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Basic realm=") {
				t.Fatalf("lost refusal headers: %v", resp.Header)
			}
			if strings.Contains(resp.Header.Get("Set-Cookie"), "AcmeCorp") || len(resp.Header.Values("Set-Cookie")) != 1 {
				t.Fatalf("incorrect cookie forwarding: %v", resp.Header)
			}
			if strings.Contains(resp.Header.Get("Location"), strings.TrimPrefix(target.URL, "http://")) || !strings.Contains(resp.Header.Get("Location"), cfg.AliasDomain) {
				t.Fatalf("unmapped redirect: %s", resp.Header.Get("Location"))
			}
			entry := waitWSManifest(t, srv)
			if entry.StatusCode != status || entry.Response == nil || len(entry.Response.Upstream) != 1 {
				t.Fatalf("incorrect manifest: %+v", entry)
			}
			measured := entry.Response.Upstream[0]
			if status == 204 || status == 304 {
				if len(body) != 0 || resp.Header.Get("Content-Length") != "" || measured.DecodedBytes != 0 || entry.Response.DownstreamBytes != 0 {
					t.Fatalf("bodyless refusal changed: headers=%v body=%s metrics=%+v", resp.Header, body, entry.Response)
				}
			} else {
				if !strings.Contains(string(body), "E_RATE: retry this request") || strings.Contains(string(body), "AcmeCorp") || resp.Header.Get("Content-Encoding") != "" {
					t.Fatalf("lost refusal diagnostic: headers=%v body=%s", resp.Header, body)
				}
				if measured.EncodedBytes != int64(encoded.Len()) || measured.DecodedBytes != int64(len(original)) || entry.Response.DownstreamBytes != int64(len(body)) {
					t.Fatalf("incorrect refusal metrics: %+v", entry.Response)
				}
			}
			entries := fidelityHAR(t, srv, path).Log.Entries
			if len(entries) != 1 || entries[0].Response.Status != status {
				t.Fatalf("incorrect HAR entries: %+v", entries)
			}
			if status != 204 && status != 304 && (entries[0].Response.Content.Text != original || entries[0].Response.BodySize != encoded.Len()) {
				t.Fatalf("lost raw refusal evidence: %+v", entries[0].Response)
			}
		})
	}
}

func TestWebSocketRefusalFailuresKeepUpstreamFacts(t *testing.T) {
	for _, mode := range []string{"truncated", "bad-gzip", "unsupported-encoding", "invalid-101"} {
		t.Run(mode, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				switch mode {
				case "truncated":
					_, _ = fmt.Fprint(rw, "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 99\r\nX-Diagnostic: AcmeCorp\r\n\r\nAcmeCorp partial")
				case "bad-gzip":
					_, _ = fmt.Fprint(rw, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: 7\r\n\r\ninvalid")
				case "unsupported-encoding":
					_, _ = fmt.Fprint(rw, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Encoding: br\r\nContent-Length: 7\r\n\r\ninvalid")
				case "invalid-101":
					_, _ = fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: invalid\r\n\r\n")
				}
				_ = rw.Flush()
			}))
			defer target.Close()
			srv, addr := startTestProxy(t, newTestConfig(t, target.URL))
			path := filepath.Join(t.TempDir(), "ws.har")
			srv.harWriter = har.NewWriter(path, 4096, 100)
			conn, _, resp := evidenceUpgrade(t, addr)
			defer conn.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 502 || strings.Contains(string(body), "AcmeCorp") {
				t.Fatalf("unsafe failure: status=%d body=%s", resp.StatusCode, body)
			}
			entry := waitWSManifest(t, srv)
			entries := fidelityHAR(t, srv, path).Log.Entries
			if len(entries) != 1 {
				t.Fatalf("capture duplicated: %+v", entries)
			}
			evidence := entries[0].Response
			wantStatus := 403
			if mode == "truncated" {
				wantStatus = 503
			}
			if mode == "invalid-101" {
				wantStatus = 101
			}
			if evidence.Status != wantStatus || evidence.Content.Comment == "" || entry.Response.Upstream[0].StatusCode != wantStatus {
				t.Fatalf("lost upstream facts: HAR=%+v manifest=%+v", evidence, entry)
			}
			if mode == "truncated" && (evidence.Content.Text != "AcmeCorp partial" || evidence.BodySize != len("AcmeCorp partial")) {
				t.Fatalf("partial bytes lost: %+v", evidence)
			}
			if mode != "invalid-101" && entry.Response.Upstream[0].Complete {
				t.Fatal("failed body read marked complete")
			}
		})
	}
}

func TestWebSocketTransportFailureRecordsNoInventedResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := "http://" + listener.Addr().String()
	listener.Close()
	srv, addr := startTestProxy(t, newTestConfig(t, upstream))
	path := filepath.Join(t.TempDir(), "ws.har")
	srv.harWriter = har.NewWriter(path, 4096, 100)
	conn, _, resp := evidenceUpgrade(t, addr)
	defer conn.Close()
	_, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != 502 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	entry := waitWSManifest(t, srv)
	entries := fidelityHAR(t, srv, path).Log.Entries
	if len(entries) != 1 || entries[0].Response.Status != 0 || entries[0].Response.Content.Text != "" || entries[0].Response.BodySize != 0 || entries[0].Request.URL != upstream+"/socket?mode=test" {
		t.Fatalf("invented transport evidence: %+v", entries)
	}
	if entry.Response.Upstream[0].StatusCode != 0 || entry.Response.Upstream[0].Complete {
		t.Fatalf("invented manifest response: %+v", entry)
	}
}

func TestWebSocketHandshakeUsesConfiguredTimeout(t *testing.T) {
	release := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer func() { close(release); target.Close() }()
	cfg := newTestConfig(t, target.URL)
	cfg.UpstreamTimeout = 1
	srv, addr := startTestProxy(t, cfg)
	path := filepath.Join(t.TempDir(), "ws.har")
	srv.harWriter = har.NewWriter(path, 4096, 100)
	start := time.Now()
	conn, _, resp := evidenceUpgrade(t, addr)
	defer conn.Close()
	_, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != 502 || time.Since(start) > 3*time.Second {
		t.Fatalf("configured timeout ignored: status=%d elapsed=%s", resp.StatusCode, time.Since(start))
	}
	_ = waitWSManifest(t, srv)
	entries := fidelityHAR(t, srv, path).Log.Entries
	if len(entries) != 1 || entries[0].Response.Status != 0 || entries[0].Response.Content.Comment == "" {
		t.Fatalf("timeout evidence invented an upstream response: %+v", entries)
	}
}

func TestWebSocket101MetadataCapturedBeforeRelayEnds(t *testing.T) {
	closed := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(closed)
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: chat\r\nX-Diagnostic: AcmeCorp connected\r\nSet-Cookie: session=AcmeCorp; HttpOnly\r\n\r\n")
		_, _ = rw.Write([]byte{0x81, 5, 'h', 'e', 'l', 'l', 'o'})
		_ = rw.Flush()
		_, _ = io.Copy(io.Discard, rw)
	}))
	defer target.Close()
	srv, addr := startTestProxy(t, newTestConfig(t, target.URL))
	path := filepath.Join(t.TempDir(), "ws.har")
	srv.harWriter = har.NewWriter(path, 4096, 100)
	conn, reader, resp := evidenceUpgrade(t, addr)
	defer conn.Close()
	if resp.StatusCode != 101 || resp.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" || resp.Header.Get("Sec-WebSocket-Protocol") != "chat" {
		t.Fatalf("invalid downstream handshake: %+v", resp)
	}
	if !strings.Contains(resp.Header.Get("X-Diagnostic"), "connected") || strings.Contains(resp.Header.Get("X-Diagnostic"), "AcmeCorp") || len(resp.Header.Values("Set-Cookie")) != 1 || strings.Contains(resp.Header.Get("Set-Cookie"), "AcmeCorp") {
		t.Fatalf("metadata missing or unredacted: %v", resp.Header)
	}
	var frame [7]byte
	if _, err := io.ReadFull(reader, frame[:]); err != nil {
		t.Fatal(err)
	}
	if string(frame[2:]) != "hello" {
		t.Fatalf("relay failed: %x", frame)
	}
	select {
	case <-closed:
		t.Fatal("upstream closed before handshake evidence checked")
	default:
	}
	entry := waitWSManifest(t, srv)
	if entry.StatusCode != 101 || entry.Response.DownstreamBytes != 0 || entry.Response.OriginalBodyBytes != 0 || entry.Response.RewrittenBodyBytes != 0 {
		t.Fatalf("frames counted as HTTP body: %+v", entry)
	}
	entries := fidelityHAR(t, srv, path).Log.Entries
	if len(entries) != 1 || entries[0].Response.Status != 101 || entries[0].Response.BodySize != 0 || entries[0].Response.Content.Size != 0 {
		t.Fatalf("missing live-handshake capture: %+v", entries)
	}
	foundRaw := false
	for _, header := range entries[0].Response.Headers {
		if strings.EqualFold(header.Name, "X-Diagnostic") && header.Value == "AcmeCorp connected" {
			foundRaw = true
		}
	}
	if !foundRaw {
		t.Fatal("HAR omitted original101 headers")
	}
	conn.Close()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("upstream connection did not close")
	}
	if len(srv.Manifest().Requests()) != 1 || srv.harWriter.Len() != 0 {
		t.Fatal("post-relay capture duplicated handshake")
	}
}
