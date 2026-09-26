// Package fixture serves synthetic data for functional tests and manual UAT.
// It has no dependency on Blinder's implementation and never contacts a real target.
package fixture

import (
	"compress/gzip"
	"crypto/sha1"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const SessionName = "AcmeCorp_session"

//go:embed websocket.js
var websocketClient string

func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ready")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><title>AcmeCorp fixture</title>
<h1>AcmeCorp synthetic target</h1><p>Use tester / fixture-only. No real accounts.</p>
<form method="post" action="/login"><input name="username" value="tester">
<input name="password" type="password" value="fixture-only"><button>Log in</button></form>
<p><a href="/form">Origin-checked form</a> · <a href="/api">JSON</a> ·
<a href="/gzip">Gzip JSON</a> · <a href="/unsupported" title="Negative test: malformed encoding; expect HTTP 502">Unsupported encoding</a> ·
<a href="/error" title="Upstream error test: expect HTTP 500 with a preserved SQLSTATE diagnostic">Upstream error</a> ·
<a href="/document.pdf" title="Binary replacement test: expect a transparent GIF">Document placeholder</a> · <a href="/absolute-redirect">Absolute redirect</a></p>
<p id="live">WebSocket connecting…</p><p id="socket-state" role="status"></p><script>`)
		fmt.Fprint(w, websocketClient)
		fmt.Fprint(w, `</script>`)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.ParseForm() != nil || r.Form.Get("username") != "tester" || r.Form.Get("password") != "fixture-only" {
			http.Error(w, "invalid synthetic credentials", http.StatusUnauthorized)
			return
		}
		host, _, _ := net.SplitHostPort(r.Host)
		http.SetCookie(w, &http.Cookie{Name: SessionName, Value: "synthetic-session", Domain: host, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, "/account", http.StatusSeeOther)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionName)
		if err != nil || cookie.Value != "synthetic-session" {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<h1>AcmeCorp account</h1><p id="session">session-ok</p><a href="/logout">Log out</a>`)
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: SessionName, Value: "", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `<form method="post"><input name="message" value="hello"><button>Submit</button></form>`)
			return
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if r.Header.Get("Origin") != scheme+"://"+r.Host {
			http.Error(w, "origin rejected", http.StatusForbidden)
			return
		}
		if r.ParseForm() != nil || r.Form.Get("message") != "hello" {
			http.Error(w, "unexpected form data", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, "form accepted")
	})
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.Header().Set("Server", "AcmeCorp service/1.0")
		fmt.Fprint(w, `{"name":"Acme\u0043orp","id":9007199254740993,"ok":true,"nested":{"count":3}}`)
	})
	mux.HandleFunc("/gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		fmt.Fprint(gz, `{"name":"AcmeCorp","ok":true}`)
		gz.Close()
	})
	mux.HandleFunc("/unsupported", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "br")
		fmt.Fprint(w, "AcmeCorp opaque bytes")
	})
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Application-Error", "AcmeCorp: E_QUERY")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `<!doctype html><title>AcmeCorp: SQLSTATE[42000] syntax error</title><h1>Synthetic query failure</h1><pre>AcmeCorp: SQLSTATE[42000]: syntax error near &#39; at line 1</pre><a href="/">Return to fixture</a>`)
	})
	mux.HandleFunc("/absolute-redirect", func(w http.ResponseWriter, r *http.Request) {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		http.Redirect(w, r, scheme+"://"+r.Host+"/account", http.StatusFound)
	})
	mux.HandleFunc("/document.pdf", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		io.WriteString(w, "%PDF-1.7\n/Author (AcmeCorp)\n/Producer (AcmeCorp PDF)\n%%EOF")
	})
	mux.HandleFunc("/ws", websocket)
	return mux
}

// A minimal deterministic server sends one text message split through an identity.
// Pings keep the manual fixture active while the operator tests other features;
// a deliberately silent stream would otherwise hit the proxy's idle deadline.
func websocket(w http.ResponseWriter, r *http.Request) {
	websocketWithHeartbeat(w, r, 20*time.Second)
}

func websocketWithHeartbeat(w http.ResponseWriter, r *http.Request, interval time.Duration) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "WebSocket upgrade required", http.StatusBadRequest)
		return
	}
	key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
	if err != nil || len(key) != 16 {
		http.Error(w, "invalid WebSocket key", http.StatusBadRequest)
		return
	}
	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
	rw.Write([]byte{0x01, 4})
	rw.WriteString("Acme")
	rw.Write([]byte{0x80, 9})
	rw.WriteString("Corp live")
	if rw.Flush() != nil {
		return
	}
	// Heartbeats and control replies share a writer so a Close acknowledgement
	// is the final frame even when a heartbeat becomes ready at the same time.
	var writeMu sync.Mutex
	closing := false
	writeControl := func(opcode byte, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if closing {
			return io.ErrClosedPipe
		}
		closing = opcode == 8
		if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return err
		}
		frame := append([]byte{0x80 | opcode, byte(len(payload))}, payload...)
		_, err := conn.Write(frame)
		return err
	}
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if writeControl(9, nil) != nil {
					conn.Close() // Unblock the reader after a failed heartbeat.
					return
				}
			}
		}
	}()
	defer func() {
		close(stop)
		conn.Close()
		<-stopped
	}()
	for {
		// A stalled or truncated client frame cannot keep this fixture alive
		// indefinitely. Browsers answer the heartbeat before this deadline.
		conn.SetReadDeadline(time.Now().Add(2*interval + 5*time.Second))
		opcode, payload, err := readFixtureFrame(rw.Reader)
		if err != nil {
			return
		}
		switch opcode {
		case 8:
			if len(payload) != 1 {
				writeControl(8, payload)
			}
			return
		case 9:
			if writeControl(10, payload) != nil {
				return
			}
		}
	}
}

// readFixtureFrame only handles the small client frames needed by this fixture.
// Application messages are discarded with bounded reads; this is not a general
// WebSocket implementation and deliberately has no dependency on proxy code.
func readFixtureFrame(r io.Reader) (byte, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	opcode := header[0] & 15
	control := opcode >= 8
	if header[0]&0x70 != 0 || header[1]&0x80 == 0 ||
		(opcode != 0 && opcode != 1 && opcode != 2 && opcode != 8 && opcode != 9 && opcode != 10) ||
		(control && (header[0]&0x80 == 0 || header[1]&0x7f > 125)) {
		return 0, nil, fmt.Errorf("invalid fixture WebSocket frame")
	}
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(r, extended[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(extended[:]))
		if length < 126 {
			return 0, nil, fmt.Errorf("nonminimal fixture WebSocket length")
		}
	case 127:
		// The fixture accepts at most 65535 bytes per application frame.
		return 0, nil, fmt.Errorf("fixture WebSocket frame too large")
	}
	var mask [4]byte
	if _, err := io.ReadFull(r, mask[:]); err != nil {
		return 0, nil, err
	}
	if !control {
		_, err := io.CopyN(io.Discard, r, int64(length))
		return opcode, nil, err
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return opcode, payload, nil
}
