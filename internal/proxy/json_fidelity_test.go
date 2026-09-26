package proxy

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/config"
)

// These fixtures use real HTTP transports in both directions: matching decoded
// JSON values alone would miss duplicate members and changes to lexical form.
func TestJSONFidelityDirectAndProxyPreserveWireBytes(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"duplicate_members", `{"value":"first","value":"second","nested":{"x":1,"x":2}}`},
		{"escaped_duplicate_keys", `{"k":1,"\u006b":2,"nested":{"\u006b":3,"k":4}}`},
		{"whitespace_and_order", " \r\n{\n\t\"z\" : [ 3, 2, 1 ],\r\n  \"a\" : true, \"m\" : null\n}\t\n"},
		{"string_escape_spelling", `{"text":"\u0061\u0062\/\"\\\b\f\n\r\t","unicode":"caf\u00e9 \ud83d\ude00","literal":"café 日本語"}`},
		{"number_lexemes", `{"large":9007199254740993123456789,"decimal":0.12345678901234567890123456789,"exponent":1.200e+003,"negative_zero":-0,"tiny":9E-999}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !json.Valid([]byte(tc.body)) {
				t.Fatal("invalid fixture")
			}
			received := make(chan string, 2)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				received <- string(body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnprocessableEntity)
				io.WriteString(w, tc.body)
			}))
			defer upstream.Close()
			s := mappingReviewServer(t, upstream.URL, nil, nil)
			defer s.transport.(*http.Transport).CloseIdleConnections()
			mirror := httptest.NewServer(s)
			defer mirror.Close()
			direct := jsonFidelityPost(t, upstream.Client(), upstream.URL+"/fixture", tc.body)
			proxied := jsonFidelityPost(t, mirror.Client(), mirror.URL+"/fixture", tc.body)
			for _, path := range []string{"direct", "proxy"} {
				if got := <-received; got != tc.body {
					t.Errorf("%s request bytes changed:\n got %q\nwant %q", path, got, tc.body)
				}
			}
			if direct != tc.body || proxied != direct {
				t.Fatalf("response bytes changed:\ndirect %q\n proxy %q\n  want %q", direct, proxied, tc.body)
			}
		})
	}
}

func jsonFidelityPost(t *testing.T, client *http.Client, target, body string) string {
	t.Helper()
	response, err := client.Post(target, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("unexpected fixture status: %d body=%q", response.StatusCode, data)
	}
	if length := response.Header.Get("Content-Length"); length != "" && length != strconv.Itoa(len(data)) {
		t.Fatalf("response Content-Length=%q, emitted bytes=%d", length, len(data))
	}
	return string(data)
}

func TestJSONFidelityMalformedErrorRemainsObservable(t *testing.T) {
	for _, source := range []string{
		`{"error":"SQLSTATE[42000] syntax near SELECT",`,
		`{"error":"SQLSTATE[42000] AcmeCorp"`,
		`{"error":"SQLSTATE[42000] \u0041cmeCorp`,
		`{"error":"AcmeCorp"} {"detail":"SQLSTATE[42000]"}`,
	} {
		t.Run(source, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, source)
			}))
			defer upstream.Close()
			s := mappingReviewServer(t, upstream.URL, []string{"AcmeCorp"}, nil)
			defer s.transport.(*http.Transport).CloseIdleConnections()
			alias := s.gate.Scrub("AcmeCorp", "fixture")
			want := strings.NewReplacer("AcmeCorp", alias, `\u0041cmeCorp`, alias).Replace(source)
			mirror := httptest.NewServer(s)
			defer mirror.Close()
			for _, endpoint := range []struct{ name, url, want string }{{"direct", upstream.URL, source}, {"proxy", mirror.URL, want}} {
				resp, err := http.Get(endpoint.url)
				if err != nil {
					t.Fatal(err)
				}
				body, readErr := io.ReadAll(resp.Body)
				resp.Body.Close()
				if readErr != nil {
					t.Fatal(readErr)
				}
				if resp.StatusCode != 500 || string(body) != endpoint.want || json.Valid(body) {
					t.Fatalf("%s diagnostic changed: status=%d body=%q want=%q", endpoint.name, resp.StatusCode, body, endpoint.want)
				}
				if resp.ContentLength != int64(len(body)) {
					t.Fatalf("%s length=%d bytes=%d", endpoint.name, resp.ContentLength, len(body))
				}
				if endpoint.name == "proxy" && resp.Header.Get("X-Blinder-Original-Body-Bytes") != strconv.Itoa(len(source)) {
					t.Fatalf("missing original size: %v", resp.Header)
				}
			}
		})
	}
}

func TestJSONFidelityOnlyChangedStringTokensAreReplaced(t *testing.T) {
	const responseBody = "{\n  \"name\" : \"AcmeCorp\", \"name\" : \"\\u0041cmeCorp\",\n  \"AcmeCorp\" : 1.200e+003, \"\\u0041cmeCorp\" : -0,\n  \"unchanged\" : \"keep\\u0020this\\/value\", \"large\":900719925474099312345\n}\n"
	received := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if r.ContentLength != int64(len(body)) {
			t.Errorf("restored request length=%d; bytes=%d", r.ContentLength, len(body))
		}
		received <- string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, responseBody)
	}))
	defer upstream.Close()
	s := mappingReviewServer(t, upstream.URL, []string{"AcmeCorp"}, nil)
	defer s.transport.(*http.Transport).CloseIdleConnections()
	alias := s.gate.Scrub("AcmeCorp", "fixture")
	if alias == "AcmeCorp" {
		t.Fatal("fixture did not create an alias")
	}
	quotedAlias, err := json.Marshal(alias)
	if err != nil {
		t.Fatal(err)
	}
	// Only the four changed string tokens may be serialized; every other byte,
	// including duplicate members and escaped but unchanged strings, must survive.
	wantResponse := strings.NewReplacer(`"AcmeCorp"`, string(quotedAlias), `"\u0041cmeCorp"`, string(quotedAlias)).Replace(responseBody)
	wantRequest := strings.ReplaceAll(responseBody, `"\u0041cmeCorp"`, `"AcmeCorp"`)
	mirror := httptest.NewServer(s)
	defer mirror.Close()
	escapedAlias := strings.ReplaceAll(string(quotedAlias), "[", `\u005b`)
	escapedRequest := strings.ReplaceAll(wantResponse, string(quotedAlias), escapedAlias)
	if s.gate.ContainsAlias(escapedRequest) {
		t.Fatal("escaped fixture still exposes an alias to a raw-byte guard")
	}
	for _, tc := range []struct{ name, request string }{{"plain", wantResponse}, {"json_escaped", escapedRequest}} {
		t.Run(tc.name, func(t *testing.T) {
			got := jsonFidelityPost(t, mirror.Client(), mirror.URL+"/fixture", tc.request)
			if requestBody := <-received; requestBody != wantRequest {
				t.Errorf("restoration changed bytes outside the alias tokens:\n got %q\nwant %q", requestBody, wantRequest)
			}
			if got != wantResponse {
				t.Fatalf("scrubbing changed bytes outside the identity string tokens:\n got %q\nwant %q", got, wantResponse)
			}
		})
	}
}

func TestJSONFidelityCAPTCHAOpacityPreservesNestedRawSubtree(t *testing.T) {
	captchaCfg := captchaDeliveryConfig(t, `version: 1
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
	received := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		received <- string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, `{"status":"accepted"}`)
	}))
	defer upstream.Close()
	cfg, err := config.New(upstream.URL, "127.0.0.1:18099", "alias.local", []string{"AcmeCorp"}, true, false, false, "", "", 0, "", "", 30, 60)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Captcha = captchaCfg
	s, err := NewWithCertificate(cfg, tls.Certificate{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.transport.(*http.Transport).CloseIdleConnections()
	alias := s.gate.Scrub("AcmeCorp", "fixture")
	quotedAlias, _ := json.Marshal(alias)
	// The marker is JSON-escaped so raw ContainsAlias checks cannot decide
	// whether restoration or scoped opacity is required.
	scalar := strings.ReplaceAll(string(quotedAlias), "[", `\u005b`)
	opaque := `{ "name" : ` + scalar + `, "name" : "keep\u0020raw", "nested" : [` + scalar + `,1.20e+02,-0] }`
	payload := "{\n \"challenge\": [{ \"challenge-token\" : " + opaque + ", \"ordinary\" : " + scalar + " }],\n \"duplicate\":1, \"duplicate\":2\n}\n"
	wantScoped := strings.Replace(payload, `"ordinary" : `+scalar, `"ordinary" : "AcmeCorp"`, 1)
	wantOrdinary := strings.ReplaceAll(payload, scalar, `"AcmeCorp"`)
	mirror := httptest.NewServer(s)
	defer mirror.Close()
	for _, tc := range []struct{ path, want string }{{"/login", wantScoped}, {"/ordinary", wantOrdinary}} {
		jsonFidelityPost(t, mirror.Client(), mirror.URL+tc.path, payload)
		if got := <-received; got != tc.want {
			t.Errorf("opacity/raw-byte preservation at %s:\n got %q\nwant %q", tc.path, got, tc.want)
		}
	}
}
