package captcha

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type relayTestTransport func(*http.Request) (*http.Response, error)

func (f relayTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func relayTestHandler(t *testing.T, fn relayTestTransport) (*OperatorHandler, *ChallengeQueue, string) {
	t.Helper()
	cfg, err := ParseConfig([]byte("version: 1\ncaptcha:\n  custom:\n    - name: fixture\n      resource_origins: [https://provider.test]\n      resource_url_regex: ['^https://provider\\.test/widget/']\n"))
	if err != nil {
		t.Fatal(err)
	}
	q := NewChallengeQueue(time.Minute)
	h, _ := NewOperatorHandler(q, cfg.Matcher, fn, true)
	id := q.Submit("fixture", "https://target.test/account", []byte("challenge"), "text/html")
	return h, q, id
}

func TestProviderRelayRejectsRedirectEscapeAndOversize(t *testing.T) {
	for _, destination := range []string{"https://unknown.test/widget/next", "https://provider.test/private", "http://provider.test/widget/next", "https://user:password@provider.test/widget/next"} {
		t.Run(destination, func(t *testing.T) {
			h, _, id := relayTestHandler(t, func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{destination}}, Body: io.NopCloser(strings.NewReader("redirect"))}, nil
			})
			got := relayTestRequest(h, id, "GET", "https://provider.test/widget/start", "")
			if got.Code != 502 || got.Header().Get("Location") != "" {
				t.Fatalf("redirect escaped: status=%d headers=%v", got.Code, got.Header())
			}
		})
	}
	calls := 0
	h, _, id := relayTestHandler(t, func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, fmt.Errorf("unexpected upstream request")
	})
	got := relayTestRequest(h, id, "POST", "https://provider.test/widget/verify", strings.Repeat("x", 2*1024*1024+1))
	if got.Code != 413 || calls != 0 {
		t.Fatalf("oversized POST reached upstream: status=%d calls=%d", got.Code, calls)
	}
}

func TestProviderRelayResponseReadDeadline(t *testing.T) {
	var cancelled atomic.Bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		cancelled.Store(true)
	}))
	defer provider.Close()
	u, _ := url.Parse(provider.URL)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	h, _, id := relayTestHandler(t, func(r *http.Request) (*http.Response, error) {
		copy := r.Clone(r.Context())
		copy.URL.Scheme, copy.URL.Host = u.Scheme, u.Host
		return transport.RoundTrip(copy)
	})
	h.SetResourceTimeout(100 * time.Millisecond)
	started := time.Now()
	got := relayTestRequest(h, id, "GET", "https://provider.test/widget/start", "")
	if got.Code != 502 || time.Since(started) > 2*time.Second {
		t.Fatalf("response body deadline not enforced: status=%d elapsed=%v", got.Code, time.Since(started))
	}
	provider.Close()
	if !cancelled.Load() {
		t.Fatal("upstream request was not cancelled")
	}
}

func relayTestRequest(h *OperatorHandler, id, method, target, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, resourcePath+"?u="+url.QueryEscape(target)+"&sid="+url.QueryEscape(id), strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "null")
	r.Header.Set("Cookie", "__blinder_op=must-not-export; sid=target-secret")
	r.Header.Set("Authorization", "Bearer target-secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestProviderRelayPOSTSessionIsolationAndExpiry(t *testing.T) {
	var calls int
	h, q, id := relayTestHandler(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Authorization") != "" || strings.Contains(r.Header.Get("Cookie"), "target-secret") || strings.Contains(r.Header.Get("Cookie"), "__blinder_op") {
			t.Error("target/operator credentials exported")
		}
		resp := &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"token":"fixture"}`))}
		if r.URL.Path == "/widget/start" {
			resp.Header.Add("Set-Cookie", "provider_session=one; Path=/widget/; Secure; HttpOnly")
			return resp, nil
		}
		if r.URL.Path == "/widget/verify" {
			b, _ := io.ReadAll(r.Body)
			if r.Method != "POST" || string(b) != `{"answer":"synthetic"}` || r.ContentLength != int64(len(b)) {
				t.Errorf("API request changed: %s %q length=%d", r.Method, b, r.ContentLength)
			}
			if r.Header.Get("Cookie") != "provider_session=one" {
				t.Errorf("provider session lost: %q", r.Header.Get("Cookie"))
			}
		} else if r.Header.Get("Cookie") != "" {
			t.Error("another challenge received provider cookies")
		}
		return resp, nil
	})
	if got := relayTestRequest(h, id, "GET", "https://provider.test/widget/start", ""); got.Code != 200 {
		t.Fatalf("initial resource: %d %s", got.Code, got.Body.String())
	}
	got := relayTestRequest(h, id, "POST", "https://provider.test/widget/verify", `{"answer":"synthetic"}`)
	if got.Code != 200 || got.Header().Get("Access-Control-Allow-Origin") != "null" {
		t.Fatalf("sandbox API request failed: %d %s headers=%v", got.Code, got.Body.String(), got.Header())
	}
	id2 := q.Submit("fixture", "https://target.test/other", nil, "text/html")
	if got := relayTestRequest(h, id2, "GET", "https://provider.test/widget/other", ""); got.Code != 200 {
		t.Fatal("second challenge failed")
	}
	q.Cancel(id)
	before := calls
	if got := relayTestRequest(h, id, "POST", "https://provider.test/widget/verify", `{}`); got.Code < 400 || calls != before {
		t.Fatal("expired session contacted provider")
	}
}

func TestProviderRelayPreflightRedirectAndScope(t *testing.T) {
	calls := 0
	h, _, id := relayTestHandler(t, func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 307, Header: http.Header{"Location": []string{"next?x=1&x=2"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	r := httptest.NewRequest("OPTIONS", resourcePath+"?sid="+id+"&u="+url.QueryEscape("https://provider.test/widget/start"), nil)
	r.Header.Set("Origin", "null")
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "content-type")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 || calls != 0 {
		t.Fatalf("preflight forwarded/rejected: %d calls=%d", w.Code, calls)
	}
	got := relayTestRequest(h, id, "GET", "https://provider.test/widget/start", "")
	u, err := url.Parse(got.Header().Get("Location"))
	if err != nil || u.Query().Get("u") != "https://provider.test/widget/next?x=1&x=2" || u.Query().Get("sid") != id {
		t.Fatalf("redirect escaped relay: %d %v", got.Code, got.Header())
	}
	for _, target := range []string{"https://provider.test/private", "https://unknown.test/widget/start"} {
		before := calls
		got := relayTestRequest(h, id, "POST", target, `{}`)
		if got.Code < 400 || calls != before {
			t.Fatal(fmt.Sprintf("out-of-scope request forwarded: %s", target))
		}
	}
}
