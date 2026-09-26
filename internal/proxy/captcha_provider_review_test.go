package proxy

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/captcha"
	"github.com/Splinters-io/blinder/internal/config"
	"golang.org/x/net/html"
)

func TestCaptchaProviderHTMLQuerySemantics(t *testing.T) {
	for _, tc := range []struct{ name, attribute, want string }{
		{"script_path", "https://captcha.vendor.synthetic/api.js", "https://captcha.vendor.synthetic/api.js"},
		{"html_query", "https://captcha.vendor.synthetic/widget?render=explicit&amp;onload=ready", "https://captcha.vendor.synthetic/widget?render=explicit&onload=ready"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := captchaDeliveryConfig(t, `version: 1
captcha:
  custom:
    - name: fixture
      resource_origins: [https://captcha.vendor.synthetic]
`)
			var forwarded string
			s := captchaServer(t, cfg, func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "captcha.vendor.synthetic" {
					forwarded = r.URL.String()
					return audit267SRIResponse("application/javascript", "window.fixture=true;"), nil
				}
				return audit267SRIResponse("text/html", `<script src="`+tc.attribute+`"></script>`), nil
			})
			s.cfg.Tor = &config.TorConfig{SOCKSAddr: "127.0.0.1:1"}
			got := audit267CacheRequest(s, "GET", "/page", nil)
			z := html.NewTokenizer(strings.NewReader(got.Body.String()))
			var source string
			for z.Next() != html.ErrorToken {
				token := z.Token()
				if token.Data == "script" {
					for _, a := range token.Attr {
						if a.Key == "src" {
							source = a.Val
						}
					}
				}
			}
			u, err := url.Parse(source)
			if err != nil || u.Path != "/__blinder/captcha/res" {
				t.Fatalf("expected rewritten fixture: src=%q err=%v", source, err)
			}
			handler, _ := captcha.NewOperatorHandler(s.captchaQueue, s.captchaMatcher, s.transport)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", source, nil))
			if response.Code != 200 || forwarded != tc.want {
				t.Fatalf("provider relay altered URL semantics: got=%q want=%q status=%d", forwarded, tc.want, response.Code)
			}
		})
	}
}

func TestCaptchaProviderStructuredAppValueStillPasses(t *testing.T) {
	value := "1-" + strings.Repeat("a", 16) + "-" + strings.Repeat("b", 32)
	var forwarded string
	s := mappingReviewServer(t, "https://main.example", nil, func(r *http.Request) (*http.Response, error) {
		forwarded = r.URL.RequestURI()
		return audit267SRIResponse("text/plain", "ok"), nil
	})
	uri := "/api?__blv=" + value + "&keep=application"
	got := audit267CacheRequest(s, "GET", uri, nil)
	if got.Code != 200 || forwarded != uri {
		t.Fatalf("unissued application value consumed by new prefix: forwarded=%q status=%d body=%q", forwarded, got.Code, got.Body.String())
	}
}

func TestCaptchaProviderOperatorChallengeBrowserRoute(t *testing.T) {
	if os.Getenv("BLINDER_REVIEW_BROWSER") != "1" {
		t.Skip("requires local browser")
	}
	providerHits := make(chan string, 1)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		io.WriteString(w, `document.body.insertAdjacentHTML('beforeend','<p>synthetic provider loaded</p>');`)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case providerHits <- r.URL.RequestURI():
		default:
		}
	}))
	defer provider.Close()
	providerURL, _ := url.Parse(provider.URL)
	providerURL.Host = "localhost:" + providerURL.Port()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "target probe passed") }))
	defer upstream.Close()
	upURL, _ := url.Parse(upstream.URL)
	socksAddr, seen := captchaRoutingSOCKS(t, map[string]bool{upURL.Host: true, providerURL.Host: true})
	capcfg := captchaDeliveryConfig(t, fmt.Sprintf("version: 1\ncaptcha:\n  custom:\n    - name: synthetic\n      resource_origins: [%s]\n      tor_policy: route-with-target\n", providerURL.String()))
	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	defer server.Close()
	cfg, err := config.New(upstream.URL, server.Listener.Addr().String(), "alias.local", []string{"AcmeCorp"}, true, false, false, socksAddr, "", 0, "", "", 10, 60)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Captcha = capcfg
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.transport.(*http.Transport).CloseIdleConnections()
	challenge := fmt.Sprintf(`<!doctype html><p>operator challenge</p><script src="%s/widget.js"></script>`, providerURL.String())
	id := s.captchaQueue.Submit("synthetic", upstream.URL+"/protected", []byte(challenge), "text/html")
	mux.HandleFunc("/review-bootstrap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		token, _ := json.Marshal("Bearer " + s.CaptchaOperatorToken())
		targetProbe, _ := json.Marshal("http://localhost:" + strconv.Itoa(server.Listener.Addr().(*net.TCPAddr).Port) + "/target-probe")
		fmt.Fprintf(w, `<!doctype html><script>(async()=>{await fetch(%s,{mode:'no-cors'});const r=await fetch('/__blinder/captcha/',{headers:{Authorization:%s}});if(r.status===200)location.href='/__blinder/captcha/challenge/%s';})()</script>`, targetProbe, token, id)
	})
	cleanup := make(chan struct{}, 1)
	mux.HandleFunc("/review-cleanup", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: captcha.OperatorCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		io.WriteString(w, "Synthetic browser fixture complete.")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case cleanup <- struct{}{}:
		default:
		}
	})
	mux.Handle("/", s.server.Handler)
	if err := s.captchaOperator.SetOperatorOrigin("http://" + captcha.OperatorHost + ":" + strconv.Itoa(server.Listener.Addr().(*net.TCPAddr).Port)); err != nil {
		t.Fatal(err)
	}
	server.Start()
	u, _ := url.Parse(server.URL)
	u.Host = captcha.OperatorHost + ":" + u.Port()
	u.Path = "/review-bootstrap"
	os.WriteFile("/private/tmp/blinder-captcha-provider-browser-url.txt", []byte(u.String()), 0600)
	select {
	case resource := <-providerHits:
		destinations := seen()
		targetSeen, providerSeen := false, false
		for _, dst := range destinations {
			targetSeen = targetSeen || dst == upURL.Host
			providerSeen = providerSeen || dst == providerURL.Host
		}
		evidence := map[string]any{"providerRequest": resource, "socksDestinations": destinations, "target": upURL.Host, "provider": providerURL.Host, "operatorChallenge": true}
		b, _ := json.MarshalIndent(evidence, "", "  ")
		os.WriteFile("/private/tmp/blinder-captcha-provider-browser-result.json", b, 0600)
		t.Log(string(b))
		if !targetSeen {
			t.Error("fixture target did not use SOCKS")
		}
		if !providerSeen {
			t.Error("operator srcdoc challenge loaded route-with-target provider outside configured SOCKS transport")
		}
		select {
		case <-cleanup:
		case <-time.After(35 * time.Second):
			t.Log("cleanup navigation not received")
		}
	case <-time.After(55 * time.Second):
		t.Fatal("operator provider did not load")
	}
}
