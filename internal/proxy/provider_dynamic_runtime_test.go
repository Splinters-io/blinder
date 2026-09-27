package proxy

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// The routing bootstrap necessarily names each configured provider origin in
// its immutable origin map. Resource-bearing markup must still use aliases.
func providerAttributesContain(body, value string) bool {
	z := html.NewTokenizer(strings.NewReader(body))
	for z.Next() != html.ErrorToken {
		for _, attr := range z.Token().Attr {
			if strings.Contains(attr.Val, value) {
				return true
			}
		}
	}
	return false
}

func TestProviderDynamicRuntimeKeepsScriptBytesAndSkipsPolicies(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "target") }))
	defer target.Close()
	const script = `const origin="https://provider.example"; window.fixture=origin;`
	const markup = `<!doctype html><head><script src="/v1/api.js" integrity="sha384-original" crossorigin="anonymous"></script></head>`
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/v1/api.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Set("ETag", `"provider-original"`)
			io.WriteString(w, script)
		case "/v1/enforcing":
			w.Header().Set("Content-Security-Policy", "script-src 'self'")
			io.WriteString(w, markup)
		case "/v1/report-only":
			w.Header().Set("Content-Security-Policy-Report-Only", "script-src 'none'")
			io.WriteString(w, markup)
		case "/v1/meta":
			io.WriteString(w, `<meta http-equiv="Content-Security-Policy" content="script-src 'none'">`+markup)
		default:
			w.Header().Set("Content-Encoding", "gzip")
			compressed := gzip.NewWriter(w)
			io.WriteString(compressed, markup)
			compressed.Close()
		}
	}))
	defer provider.Close()
	_, _, client, aliases, _ := providerOriginFixture(t, target, []*httptest.Server{provider}, true)
	status, headers, body := providerOriginDo(t, client, "GET", aliases[0].String()+"/v1/widget", "", nil)
	if status != 200 || headers.Get("Content-Encoding") != "" || headers.Get("Content-Length") != fmt.Sprint(len(body)) || headers.Get("X-Blinder-View") != "transformed" || headers.Get("X-Blinder-Original-Body-Bytes") != fmt.Sprint(len(markup)) || headers.Get("X-Blinder-Rewritten-Body-Bytes") != fmt.Sprint(len(body)) || !strings.Contains(body, "const aliases = new Map") || !strings.Contains(body, `integrity="sha384-original" crossorigin="anonymous"`) {
		t.Fatalf("provider helper or response framing incorrect: %d %v %s", status, headers, body)
	}
	for _, path := range []string{"enforcing", "report-only", "meta"} {
		_, _, body = providerOriginDo(t, client, "GET", aliases[0].String()+"/v1/"+path, "", nil)
		if strings.Contains(body, "const aliases = new Map") || !strings.Contains(body, markup) {
			t.Errorf("policy document changed unexpectedly: %s %s", path, body)
		}
	}
	status, headers, body = providerOriginDo(t, client, "GET", aliases[0].String()+"/v1/api.js", "", nil)
	if status != 200 || body != script || headers.Get("ETag") != `"provider-original"` {
		t.Fatalf("provider script bytes changed: %d %v %q", status, headers, body)
	}
}
