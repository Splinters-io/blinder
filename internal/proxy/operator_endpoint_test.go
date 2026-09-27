package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Splinters-io/blinder/internal/captcha"
	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/endpoint"
)

func TestOperatorHostnameReservedAndCoveredByTLS(t *testing.T) {
	for _, field := range []string{"target", "alias", "extra"} {
		cfg, err := config.New("https://main.example", "127.0.0.1:18099", "alias.local", nil, true, false, false, "", "", 0, "", "", 30, 60)
		if err != nil {
			t.Fatal(err)
		}
		switch field {
		case "target":
			cfg.TargetURL.Host = captcha.OperatorHost
		case "alias":
			cfg.AliasDomain = strings.ToUpper(captcha.OperatorHost) + "."
		case "extra":
			other := *cfg.TargetURL
			other.Host = captcha.OperatorHost
			cfg.ExtraOrigins = append(cfg.ExtraOrigins, &other)
		}
		if _, err := NewWithCertificate(cfg, tls.Certificate{}); err == nil {
			t.Errorf("operator hostname accepted for %s", field)
		}
	}
	cfg, err := config.New("https://main.example", "127.0.0.1:18099", "alias.local", nil, true, false, false, "", "", 0, "", t.TempDir()+"/certs", 30, 60)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.transport.(*http.Transport).CloseIdleConnections()
	leaf, err := x509.ParseCertificate(s.server.TLSConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname(captcha.OperatorHost); err != nil {
		t.Fatal(err)
	}
	if s.CaptchaOperatorURL() != "https://"+captcha.OperatorHost+":18099/__blinder/captcha/" {
		t.Fatal(s.CaptchaOperatorURL())
	}
}

func TestOperatorHostNeverServesTargetOrTargetWorker(t *testing.T) {
	var upstreamCalls atomic.Int32
	s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
		upstreamCalls.Add(1)
		return audit267SRIResponse("text/plain", "target response"), nil
	})
	for _, tc := range []struct {
		host, path, peer string
		status           int
	}{
		{captcha.OperatorHost + ":18099", "/__blinder/captcha/", "127.0.0.1:4567", 200},
		{strings.ToUpper(captcha.OperatorHost) + ":018099", "/__blinder/captcha/", "[::1]:4567", 200},
		{captcha.OperatorHost + ":18099", "/worker.js", "127.0.0.1:4567", 404},
		{captcha.OperatorHost + ":18098", "/__blinder/captcha/", "127.0.0.1:4567", 421},
		{captcha.OperatorHost + ".:18099", "/__blinder/captcha/", "127.0.0.1:4567", 421},
		{captcha.OperatorHost + ":18099", "/__blinder/captcha/", "192.0.2.1:4567", 403},
		{"alias.local:18099", "/__blinder/captcha/", "127.0.0.1:4567", 404},
		{"alias.local:18099", "/__blinder/captcha/login?token=ignored", "127.0.0.1:4567", 404},
	} {
		t.Run(tc.host+tc.path+tc.peer, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://"+tc.host+tc.path, nil)
			req.RemoteAddr = tc.peer
			req.Header.Set("Authorization", "Bearer "+s.CaptchaOperatorToken())
			w := httptest.NewRecorder()
			s.server.Handler.ServeHTTP(w, req)
			if w.Code != tc.status || upstreamCalls.Load() != 0 {
				t.Fatalf("operator/target boundary failed: status=%d want=%d upstream=%d", w.Code, tc.status, upstreamCalls.Load())
			}
			if tc.status == 200 {
				cookies := w.Result().Cookies()
				if len(cookies) != 1 || cookies[0].Name != captcha.OperatorCookieName || cookies[0].Path != "/" || cookies[0].Domain != "" || !cookies[0].Secure || !cookies[0].HttpOnly {
					t.Fatalf("operator cookie is not host isolated: %+v", cookies)
				}
			}
		})
	}
	request := httptest.NewRequest("GET", "https://alias.local:18099/worker.js", nil)
	request.Header.Set("Service-Worker", "script")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, request)
	if w.Code != 200 || w.Body.String() != "target response" || upstreamCalls.Load() != 1 {
		t.Fatal("operator isolation changed target service-worker behavior")
	}
}

func TestChallengeNamespaceNeverFallsThroughToTarget(t *testing.T) {
	var calls atomic.Int32
	s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return audit267SRIResponse("text/plain", "target"), nil
	})
	for _, host := range []string{endpoint.ChallengeSuffix, "unknown." + endpoint.ChallengeSuffix, "0123456789abcdef0123456789abcdef." + endpoint.ChallengeSuffix, "UNKNOWN." + strings.ToUpper(endpoint.ChallengeSuffix) + "."} {
		for _, path := range []string{"/", "/worker.js", "/__blinder/captcha/", "/__blinder/captcha/login?token=ignored"} {
			r := httptest.NewRequest("GET", "https://"+host+":18099"+path, nil)
			r.RemoteAddr = "127.0.0.1:4555"
			r.Header.Set("Authorization", "Bearer "+s.CaptchaOperatorToken())
			w := httptest.NewRecorder()
			s.server.Handler.ServeHTTP(w, r)
			if w.Code < 400 || calls.Load() != 0 || len(w.Result().Cookies()) != 0 {
				t.Fatalf("reserved challenge route reached target or operator: host=%s path=%s status=%d calls=%d", host, path, w.Code, calls.Load())
			}
		}
	}
	r := httptest.NewRequest("GET", "https://unknown."+endpoint.ChallengeSuffix+":18099/", nil)
	r.RemoteAddr = "192.0.2.1:4555"
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || calls.Load() != 0 {
		t.Fatal("challenge origin allowed a non-loopback peer")
	}
}

func TestChallengeNamespaceReservedInTargetRoutes(t *testing.T) {
	for _, host := range []string{endpoint.ChallengeSuffix, "view." + endpoint.ChallengeSuffix, "VIEW." + strings.ToUpper(endpoint.ChallengeSuffix) + "."} {
		for _, field := range []string{"target", "alias", "extra"} {
			cfg, err := config.New("https://main.example", "127.0.0.1:18099", "alias.local", nil, true, false, false, "", "", 0, "", "", 30, 60)
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "target":
				cfg.TargetURL.Host = host
			case "alias":
				cfg.AliasDomain = host
			case "extra":
				other := *cfg.TargetURL
				other.Host = host
				cfg.ExtraOrigins = append(cfg.ExtraOrigins, &other)
			}
			if _, err := NewWithCertificate(cfg, tls.Certificate{}); err == nil {
				t.Errorf("challenge namespace accepted as %s: %s", field, host)
			}
		}
	}
}

func TestOperatorCookieDoesNotReachTargetOnWire(t *testing.T) {
	var received string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("Cookie")
		io.WriteString(w, "ok")
	}))
	defer target.Close()
	front := httptest.NewUnstartedServer(nil)
	cfg, err := config.New(target.URL, front.Listener.Addr().String(), "alias.local", nil, true, false, false, "", "", 0, "", "", 30, 60)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.transport.(*http.Transport).CloseIdleConnections()
	front.Config.Handler = s
	front.StartTLS()
	defer front.Close()
	request, _ := http.NewRequest("GET", front.URL, nil)
	request.Header.Set("Cookie", captcha.OperatorCookieName+"=private-operator-token; __blinder_op=legacy-token; application=value")
	resp, err := front.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || received != "application=value" {
		t.Fatalf("operator cookie forwarded or application cookie lost: status=%d cookie=%q", resp.StatusCode, received)
	}
}
