package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/scrub"
	"github.com/Splinters-io/blinder/internal/sri"
)

func TestWebSocketLiteralOrdinaryAndSRIPrefetchBytesMatch(t *testing.T) {
	const extraOrigin = "https://socket.example:8443"
	var script string
	var ordinaryFetches, sriFetches atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ordinary", "/asset":
			if r.URL.Path == "/ordinary" {
				ordinaryFetches.Add(1)
			} else {
				sriFetches.Add(1)
			}
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, script)
		case "/page":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, audit267SRIPage("/asset", script))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	primarySocket := strings.Replace(upstream.URL, "http://", "ws://", 1) + "/socket?channel=one"
	script = "const primary = new WebSocket('" + primarySocket + "');\n" +
		`const extra = new WebSocket("wss://socket.example:8443/socket?channel=two");` + "\n" +
		`const product = "AcmeCorp";` + "\n"
	// The actual server constructor must supply the same OriginMapper to both
	// the ordinary response rewrite and the pipeline's captured ScrubFn.
	cfg, err := config.New(upstream.URL, "127.0.0.1:18099", "alias.local", []string{"AcmeCorp"}, true, false, false, "", "", 0, "", "", 30, 60, extraOrigin)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.transport.(*http.Transport).CloseIdleConnections()
	defer s.captchaQueue.Shutdown()
	ordinary := audit267SRIRequest(s, "GET", "/ordinary", "", "")
	if ordinary.Code != http.StatusOK || ordinaryFetches.Load() != 1 {
		t.Fatalf("ordinary fixture response failed: status=%d body=%q", ordinary.Code, ordinary.Body.String())
	}
	extraAlias := scrub.AliasOrigin("https", "socket.example", "8443", "alias.local")
	for _, want := range []string{"wss://127.0.0.1:18099/socket?channel=one", "wss://" + extraAlias + ":18099/socket?channel=two"} {
		if !strings.Contains(ordinary.Body.String(), want) {
			t.Fatalf("ordinary JS omitted registered WebSocket route including local port %q: %s", want, ordinary.Body.String())
		}
	}
	page := audit267SRIRequest(s, "GET", "/page", "", "")
	if page.Code != http.StatusOK || sriFetches.Load() != 1 {
		t.Fatalf("SRI page did not prefetch resource: status=%d fetches=%d body=%q", page.Code, sriFetches.Load(), page.Body.String())
	}
	reference := audit267SRIAttribute(page.Body.String(), "src")
	if reference == "" || !strings.Contains(reference, "__blv=") {
		t.Fatalf("missing version-bound SRI resource reference: %s", page.Body.String())
	}
	resource := audit267SRIRequest(s, "GET", reference, "", "")
	if resource.Code != http.StatusOK || sriFetches.Load() != 1 {
		t.Fatalf("version-bound cached SRI response failed/refetched: status=%d fetches=%d body=%q", resource.Code, sriFetches.Load(), resource.Body.String())
	}
	if !bytes.Equal(ordinary.Body.Bytes(), resource.Body.Bytes()) {
		t.Fatalf("normal and SRI JS rewriting diverged:\nnormal %q\n   SRI %q", ordinary.Body.String(), resource.Body.String())
	}
	integrity := audit267SRIAttribute(page.Body.String(), "integrity")
	if ok, _ := sri.Verify(resource.Body.Bytes(), sri.ParseIntegrity(integrity)); !ok {
		t.Fatalf("browser SRI would reject the delivered WebSocket script: integrity=%q body=%q", integrity, resource.Body.String())
	}
	if strings.Contains(resource.Body.String(), "AcmeCorp") || strings.Contains(resource.Body.String(), primarySocket) || strings.Contains(resource.Body.String(), "wss://socket.example:8443") {
		t.Fatal("SRI path missed normal redaction or origin rewriting")
	}
}
