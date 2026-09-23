// Package fixture serves synthetic data for functional tests and manual UAT.
// It has no dependency on Blinder's implementation and never contacts a real target.
package fixture

import (
	"compress/gzip"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

const SessionName = "AcmeCorp_session"

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
<a href="/gzip">Gzip JSON</a> · <a href="/unsupported">Unsupported encoding</a> ·
<a href="/document.pdf">Document placeholder</a> · <a href="/absolute-redirect">Absolute redirect</a></p>
<p id="live">WebSocket connecting…</p><script>
const socket = new WebSocket('wss://' + location.host + '/ws');
socket.onmessage = event => { document.getElementById('live').textContent = event.data; };
socket.onerror = () => { document.getElementById('live').textContent = 'WebSocket failed'; };
</script>`)
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
// It leaves the connection open so tests can also exercise proxy shutdown.
func websocket(w http.ResponseWriter, r *http.Request) {
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
	if rw.Flush() == nil {
		io.Copy(io.Discard, rw)
	}
}
