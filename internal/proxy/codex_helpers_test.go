package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/rewriter"
	"github.com/Splinters-io/blinder/internal/sri"
	"golang.org/x/net/html"
)

type codexSRITransport func(*http.Request) (*http.Response, error)

func (f codexSRITransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func codexSRIServer(t *testing.T, fn codexSRITransport) *Server {
	t.Helper()
	cfg, err := config.New("https://main.example", "127.0.0.1:18099", "alias.local", []string{"AcmeCorp"}, true, false, false, "", "", 0, "", "", 30, 60)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	s.transport = fn
	s.sriPipeline = sri.NewPipeline(sri.PipelineConfig{
		Transport: fn,
		Cache:     s.sriCache,
		ScrubFn: func(body []byte, contentType, path string) []byte {
			return rewriter.RewriteBody(body, contentType, path, s.gate, s.cfg.Paranoid).Body
		},
		IsAllowedOrigin: s.origins.IsKnownFullOrigin,
		CookieRestoreFn: s.gate.RestoreCookieHeader,
		OnFetch: func(rec sri.FetchRecord) {
			if s.harWriter != nil {
				if rec.Error != "" {
					s.harWriter.RecordFetchFailure(rec.Request, rec.Status, rec.Headers, rec.Body, rec.Error, rec.Elapsed)
					return
				}
				s.harWriter.Record(rec.Request, nil, &http.Response{StatusCode: rec.Status, Status: fmt.Sprintf("%d %s", rec.Status, http.StatusText(rec.Status)), Header: rec.Headers, Proto: "HTTP/1.1"}, rec.Body, rec.Elapsed)
			}
		},
	})
	return s
}

func codexSRIResponse(ct, body string) *http.Response {
	return &http.Response{StatusCode: 200, Status: "200 OK", Proto: "HTTP/1.1", Header: http.Header{"Content-Type": {ct}}, Body: io.NopCloser(strings.NewReader(body))}
}

func codexSRIPage(src, body string) string {
	return fmt.Sprintf(`<script src="%s" integrity="%s" crossorigin="anonymous"></script>`, src, sri.ComputeIntegrity([]byte(body), "sha384"))
}

func codexSRIRequest(s *Server, method, path, cookie, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://127.0.0.1:18099"+path, nil)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func codexSRIAttribute(body, key string) string {
	z := html.NewTokenizer(strings.NewReader(body))
	for z.Next() != html.ErrorToken {
		tok := z.Token()
		for _, a := range tok.Attr {
			if a.Key == key {
				return a.Val
			}
		}
	}
	return ""
}

func codexCacheResponse(body string) *http.Response {
	r := codexSRIResponse("text/plain", body)
	r.Header.Set("Cache-Control", "max-age=3600")
	return r
}

func codexCacheRequest(s *Server, method, path string, headers http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://127.0.0.1:18099"+path, nil)
	r.Header = headers.Clone()
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
