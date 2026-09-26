package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/config"
)

type formFidelityRequest struct {
	method, rawQuery, body string
	contentLength          int64
}

func formFidelityUpstream(t *testing.T) (*httptest.Server, <-chan formFidelityRequest) {
	t.Helper()
	received := make(chan formFidelityRequest, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		received <- formFidelityRequest{r.Method, r.URL.RawQuery, string(body), r.ContentLength}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, "E_FIXTURE: original parameter interpretation remains observable")
	}))
	t.Cleanup(upstream.Close)
	return upstream, received
}

func formFidelitySend(t *testing.T, client *http.Client, endpoint, method, rawQuery, body string, received <-chan formFidelityRequest) formFidelityRequest {
	t.Helper()
	req, err := http.NewRequest(method, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.URL.RawQuery = rawQuery
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("fixture status=%d body=%q", response.StatusCode, responseBody)
	}
	select {
	case got := <-received:
		if got.contentLength != int64(len(got.body)) {
			t.Fatalf("upstream Content-Length=%d, received bytes=%d", got.contentLength, len(got.body))
		}
		return got
	case <-time.After(time.Second):
		t.Fatal("upstream did not observe the request")
		return formFidelityRequest{}
	}
}

func formFidelityMirror(t *testing.T, s *Server) *httptest.Server {
	t.Helper()
	t.Cleanup(s.transport.(*http.Transport).CloseIdleConnections)
	mirror := httptest.NewServer(s)
	t.Cleanup(mirror.Close)
	return mirror
}

func TestFormFidelityDirectAndProxyPreserveWireBytes(t *testing.T) {
	for _, source := range []string{
		"&&dup=first&dup=second&bare&blank=&encoded=%2f%2F&space=a+b&space=a%20b&&",
		"query=1%27+OR+1%3d1--&query=1%27%20OR%201%3D1--&semi=one;two&=empty-key&z=a=b",
		"bare&%62are=&%61=first&a=second&bytes=%ff%00&unicode=caf%c3%a9&",
	} {
		t.Run(source, func(t *testing.T) {
			upstream, received := formFidelityUpstream(t)
			s := mappingReviewEphemeralServer(t, upstream.URL, nil, nil)
			mirror := formFidelityMirror(t, s)
			direct := formFidelitySend(t, upstream.Client(), upstream.URL+"/fixture", "POST", source, source, received)
			proxied := formFidelitySend(t, mirror.Client(), mirror.URL+"/fixture", "POST", source, source, received)
			if direct.rawQuery != source || direct.body != source {
				t.Fatalf("direct fixture changed bytes: %#v", direct)
			}
			if proxied != direct {
				t.Fatalf("proxy changed parameter bytes:\ndirect %#v\n proxy %#v", direct, proxied)
			}
		})
	}
}

func TestFormFidelityOnlyAliasComponentsChange(t *testing.T) {
	for _, mode := range []string{"encoded_value_only", "encoded_key_and_value"} {
		t.Run(mode, func(t *testing.T) {
			upstream, received := formFidelityUpstream(t)
			s := mappingReviewEphemeralServer(t, upstream.URL, []string{"AcmeCorp"}, nil)
			mirror := formFidelityMirror(t, s)
			alias := s.gate.Scrub("AcmeCorp", "form-fidelity")
			if alias == "AcmeCorp" {
				t.Fatal("fixture did not generate an alias")
			}
			encodedAlias := url.QueryEscape(alias)
			const prefix = "&&dup=first&dup=second&bare&space=a+b&space=a%20b&path=%2f%2F&"
			const suffix = "&query=1%27+OR+1%3d1--&semi=one;two&&"
			source := prefix + "identity=" + encodedAlias + suffix
			want := prefix + "identity=AcmeCorp" + suffix
			if mode == "encoded_key_and_value" {
				// Restoration must retain both occurrences when an alias key
				// becomes identical to another application parameter's key.
				source = prefix + encodedAlias + "=" + encodedAlias + "&AcmeCorp=second" + suffix
				want = prefix + "AcmeCorp=AcmeCorp&AcmeCorp=second" + suffix
			}
			direct := formFidelitySend(t, upstream.Client(), upstream.URL+"/fixture", "POST", want, want, received)
			proxied := formFidelitySend(t, mirror.Client(), mirror.URL+"/fixture", "POST", source, source, received)
			if direct.rawQuery != want || direct.body != want {
				t.Fatalf("direct fixture changed bytes: %#v", direct)
			}
			if proxied != direct {
				t.Fatalf("restoration changed other source components:\ndirect %#v\n proxy %#v", direct, proxied)
			}
		})
	}
}

func TestFormFidelityOpaqueValuesUseRestoredKeyAndSubmissionScope(t *testing.T) {
	upstream, received := formFidelityUpstream(t)
	cfg, err := config.New(upstream.URL, "127.0.0.1:0", "alias.local", []string{"AcmeCorp", "challenge-token"}, true, false, false, "", "", 0, "", "", 30, 60)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Captcha = captchaDeliveryConfig(t, `version: 1
captcha:
  custom:
    - name: synthetic
      resource_origins: [https://captcha.vendor.synthetic]
      opaque_fields: [challenge-token]
      submissions:
        - target: primary
          method: POST
          path_regex: '^/login$'
`)
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	mirror := formFidelityMirror(t, s)
	alias := s.gate.Scrub("AcmeCorp", "form-fidelity")
	keyAlias := s.gate.Scrub("challenge-token", "form-fidelity")
	if alias == "AcmeCorp" || keyAlias == "challenge-token" {
		t.Fatal("fixture did not alias both the field name and its token-shaped value")
	}
	encodedAlias, encodedKey := url.QueryEscape(alias), url.QueryEscape(keyAlias)
	source := "&&" + encodedKey + "=" + encodedAlias + "%2f%20opaque&normal=" + encodedAlias + "&bare&" + encodedKey + "=" + encodedAlias + "&"
	const query = "dup=one+two&dup=one%20two&bare&&"
	for _, tc := range []struct {
		name, method, path string
		opaque             bool
	}{
		{"matching_submission", "POST", "/login", true},
		{"other_path", "POST", "/ordinary", false},
		{"other_method", "PUT", "/login", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, secondValue := "AcmeCorp%2F+opaque", "AcmeCorp"
			if tc.opaque {
				value, secondValue = encodedAlias+"%2f%20opaque", encodedAlias
			}
			want := "&&challenge-token=" + value + "&normal=AcmeCorp&bare&challenge-token=" + secondValue + "&"
			direct := formFidelitySend(t, upstream.Client(), upstream.URL+tc.path, tc.method, query, want, received)
			proxied := formFidelitySend(t, mirror.Client(), mirror.URL+tc.path, tc.method, query, source, received)
			if direct.body != want || direct.rawQuery != query {
				t.Fatalf("direct fixture changed bytes: %#v", direct)
			}
			if proxied != direct {
				t.Fatalf("opaque restoration or submission scope changed bytes:\ndirect %#v\n proxy %#v", direct, proxied)
			}
		})
	}
}

func TestFormFidelityMalformedEncodingReachesUpstreamUnchanged(t *testing.T) {
	for _, malformed := range []string{"bad=%", "bad=%0", "bad=%GG", "bad%q=value"} {
		t.Run(malformed, func(t *testing.T) {
			upstream, received := formFidelityUpstream(t)
			s := mappingReviewEphemeralServer(t, upstream.URL, []string{"AcmeCorp"}, nil)
			mirror := formFidelityMirror(t, s)
			alias := url.QueryEscape(s.gate.Scrub("AcmeCorp", "form-fidelity"))
			// A valid alias before the bad escape must not be partially
			// restored when the existing malformed-input policy forwards it.
			source := "identity=" + alias + "&dup=1&" + malformed + "&dup=2&bare&&"
			direct := formFidelitySend(t, upstream.Client(), upstream.URL+"/fixture", "POST", source, source, received)
			proxied := formFidelitySend(t, mirror.Client(), mirror.URL+"/fixture", "POST", source, source, received)
			if direct.body != source || direct.rawQuery != source {
				t.Fatalf("direct malformed fixture changed bytes: %#v", direct)
			}
			if proxied != direct {
				t.Fatalf("malformed encoding was normalized or partially restored:\ndirect %#v\n proxy %#v", direct, proxied)
			}
		})
	}
}
