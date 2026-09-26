package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Splinters-io/blinder/internal/cache"
	"golang.org/x/net/html"
)

// These synthetic pages model a length difference, a readable diagnostic and
// a submitted value. They do not establish that arbitrary vulnerabilities
// survive HTML rewriting.
func TestBodySizeFitPreservesPairedResponseDifference(t *testing.T) {
	const diagnostic = "E_ROW_COUNT: expected=1; observed=0."
	const formValue = "AcmeCorp & café"
	page := func(repetitions int) string {
		return `<!doctype html><html><head><title>AcmeCorp</title></head><body><p>` +
			strings.Repeat("Decorative prose with ample space for size adjustment. ", repetitions) +
			`</p><div role="alert">` + diagnostic + `</div>` +
			`<form method="post" action="/submit"><textarea name="note">AcmeCorp &amp; café</textarea>` +
			`<input name="csrf" value="fixed-token"></form><script>window.fixtureAnswer = 42;</script></body></html>`
	}
	originals := []string{page(30), page(12)}
	encoded := make([][]byte, len(originals))
	for i, original := range originals {
		encoded[i] = []byte(original)
		if i == 0 {
			var buf bytes.Buffer
			writer := gzip.NewWriter(&buf)
			if _, err := writer.Write([]byte(original)); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			encoded[i] = buf.Bytes()
		}
	}
	if len(encoded[0]) == len(originals[0]) {
		t.Fatal("gzip fixture does not distinguish encoded and decoded lengths")
	}
	posted := make(chan url.Values, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/submit" {
			if r.Method != http.MethodPost {
				t.Errorf("form method changed: %s", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Errorf("restored form rejected: %v", err)
			}
			posted <- r.PostForm
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"accepted":true}`)
			return
		}
		i := 0
		if r.URL.Path == "/short" {
			i = 1
		}
		if r.Header.Get("Accept-Encoding") != "gzip, identity" {
			t.Errorf("encoded length could be hidden by automatic decompression: %q", r.Header.Get("Accept-Encoding"))
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Blinder-Body-Size-Match", "upstream-spoof")
		if i == 0 {
			w.Header().Set("Content-Encoding", "gzip")
		}
		w.Write(encoded[i])
	}))
	defer upstream.Close()
	s := mappingReviewEphemeralServer(t, upstream.URL, []string{"AcmeCorp"}, nil)
	s.cfg.Paranoid = true
	defer s.transport.(*http.Transport).CloseIdleConnections()
	completed := make(chan struct{}, 1)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.ServeHTTP(w, r)
		completed <- struct{}{}
	}))
	defer local.Close()
	client := local.Client()
	readResponse := func(response *http.Response) []byte {
		t.Helper()
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		<-completed // The deferred manifest write has completed too.
		return body
	}
	finalLengths := make([]int, len(originals))
	for i, path := range []string{"/long", "/short"} {
		response, err := client.Get(local.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body := readResponse(response)
		finalLengths[i] = len(body)
		if response.StatusCode != 200 || len(body) != len(originals[i]) || !utf8.Valid(body) {
			t.Fatalf("size target missed: status=%d original=%d final=%d", response.StatusCode, len(originals[i]), len(body))
		}
		if response.Header.Get("X-Blinder-Body-Size-Match") != "exact" || response.Header.Get("Content-Length") != strconv.Itoa(len(body)) || response.Header.Get("ETag") != cache.ComputeETag(body) || response.Header.Get("Content-Encoding") != "" {
			t.Fatalf("metadata does not describe final identity bytes: %v", response.Header)
		}
		if !bytes.Contains(body, []byte(diagnostic)) || !bytes.Contains(body, []byte("window.fixtureAnswer = 42;")) || bytes.Contains(body, []byte("AcmeCorp")) || bytes.Contains(body, []byte("Decorative prose")) {
			t.Fatalf("diagnostic/executable content or configured transformation changed: %s", body)
		}
		metrics := lastResponseMetrics(t, s)
		if metrics.OriginalBodyBytes != int64(len(originals[i])) || metrics.RewrittenBodyBytes != int64(len(body)) || metrics.DownstreamBytes != int64(len(body)) || metrics.RewriteDeltaBytes == nil || *metrics.RewriteDeltaBytes != 0 || len(metrics.Upstream) != 1 {
			t.Fatalf("wrong final measurements: %+v", metrics)
		}
		read := metrics.Upstream[0]
		if read.EncodedBytes != int64(len(encoded[i])) || read.DecodedBytes != int64(len(originals[i])) || !read.Complete {
			t.Fatalf("encoded and decoded measurements confused: %+v", read)
		}
		// Submit the transformed textarea through the real proxy and transport;
		// checking the upstream value exercises restoration and framing as well.
		document, err := html.Parse(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		values := url.Values{}
		var visit func(*html.Node)
		visit = func(node *html.Node) {
			if node.Type == html.ElementNode {
				attrs := make(map[string]string)
				for _, attr := range node.Attr {
					attrs[attr.Key] = attr.Val
				}
				if node.Data == "textarea" {
					var value strings.Builder
					for child := node.FirstChild; child != nil; child = child.NextSibling {
						if child.Type == html.TextNode {
							value.WriteString(child.Data)
						}
					}
					values.Set(attrs["name"], value.String())
				}
				if node.Data == "input" {
					values.Set(attrs["name"], attrs["value"])
				}
			}
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				visit(child)
			}
		}
		visit(document)
		if values.Get("note") == formValue || s.gate.RestoreBody(values.Get("note")) != formValue || values.Get("csrf") != "fixed-token" {
			t.Fatalf("form value no longer reversibly transformed: %v", values)
		}
		submitted, err := client.PostForm(local.URL+"/submit", values)
		if err != nil {
			t.Fatal(err)
		}
		readResponse(submitted)
		if submitted.StatusCode != 200 {
			t.Fatalf("restored form status=%d", submitted.StatusCode)
		}
		if got := <-posted; got.Get("note") != formValue || got.Get("csrf") != "fixed-token" {
			t.Fatalf("upstream form changed after size fitting: %v", got)
		}
	}
	wantDelta := len(originals[1]) - len(originals[0])
	if wantDelta >= 0 || finalLengths[1]-finalLengths[0] != wantDelta {
		t.Fatalf("signed response difference changed: original=%d final=%d", wantDelta, finalLengths[1]-finalLengths[0])
	}
}

func TestBodySizeFitReportsUnavoidableDifference(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"no_prose", `<pre>E_INPUT: Org invalid résumé</pre><textarea name="note">Org</textarea>`, 200},
		{"error_response", `<p>Org service unavailable</p><pre>E_TIMEOUT: retry in 30 seconds</pre>`, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := mappingReviewServer(t, "https://main.example", []string{"Org"}, func(*http.Request) (*http.Response, error) {
				response := audit267SRIResponse("text/html", tc.body)
				response.StatusCode = tc.status
				response.Header.Set("Retry-After", "30")
				response.Header.Set("X-Blinder-Body-Size-Match", "exact")
				return response, nil
			})
			s.cfg.Paranoid = true
			response := audit267CacheRequest(s, "GET", "/diagnostic", nil)
			body := response.Body.String()
			if response.Code != tc.status || len(body) == len(tc.body) || response.Header().Get("X-Blinder-Body-Size-Match") != "different" || response.Header().Get("Content-Length") != strconv.Itoa(len(body)) {
				t.Fatalf("unavoidable difference hidden: status=%d original=%d final=%d headers=%v", response.Code, len(tc.body), len(body), response.Header())
			}
			if s.gate.RestoreBody(html.UnescapeString(body)) != tc.body || response.Header().Get("Retry-After") != "30" {
				t.Fatalf("diagnostic/form content changed to satisfy size target: %s", body)
			}
			metrics := lastResponseMetrics(t, s)
			if metrics.RewriteDeltaBytes == nil || *metrics.RewriteDeltaBytes != int64(len(body)-len(tc.body)) || metrics.OriginalBodyBytes != int64(len(tc.body)) || metrics.RewrittenBodyBytes != int64(len(body)) {
				t.Fatalf("residual difference not accurately recorded: %+v", metrics)
			}
		})
	}
}

func TestBodySizeFitUncachedHEADReportsUnknown(t *testing.T) {
	s := mappingReviewServer(t, "https://main.example", nil, func(*http.Request) (*http.Response, error) {
		response := audit267SRIResponse("text/html", "")
		response.Header.Set("Content-Length", "1024")
		response.Header.Set("X-Blinder-Body-Size-Match", "exact")
		return response, nil
	})
	s.cfg.Paranoid = true
	response := audit267CacheRequest(s, "HEAD", "/unknown", nil)
	if response.Code != 200 || response.Body.Len() != 0 || response.Header().Get("X-Blinder-Body-Size-Match") != "unknown" || response.Header().Get("Content-Length") != "" {
		t.Fatalf("unseen representation claimed an exact match: status=%d headers=%v", response.Code, response.Header())
	}
}
