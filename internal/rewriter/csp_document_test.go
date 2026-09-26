package rewriter

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
	"github.com/Splinters-io/blinder/internal/sri"
)

type cspDocumentTransport func(*http.Request) (*http.Response, error)

func (f cspDocumentTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func cspDocumentPrefetch(t *testing.T, document string, policies []string) []string {
	t.Helper()
	const script = "const fixture = 1;"
	hash := strings.Trim(cspBodyTestHash("sha256", script, base64.StdEncoding), "'")
	document = strings.ReplaceAll(document, "HASH", hash)
	var fetched []string
	pipeline := sri.NewPipeline(sri.PipelineConfig{
		Cache: sri.NewCache(20),
		Transport: cspDocumentTransport(func(r *http.Request) (*http.Response, error) {
			fetched = append(fetched, r.URL.String())
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/javascript"}}, Body: io.NopCloser(strings.NewReader(script)), Request: r}, nil
		}),
		ScrubFn: func(body []byte, _, _ string) []byte { return body },
	})
	page := cspExternalTestURL("https://app.example/doc/page")
	request, err := http.NewRequest(http.MethodGet, page.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	state := &sriRewriter{pipeline: pipeline, upstreamBase: page, cspPolicies: policies, baseReq: request}
	prepareSRIDecisions([]byte(document), state, nil, &CSPHashes{})
	return fetched
}

func TestCSPDocumentFirstBaseAndBaseURI(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, want string
		policies           []string
	}{
		{"first-base", `<base href="/first/"><base href="/second/">`, "https://app.example/first/asset.js", nil},
		{"empty-first-base", `<base href=""><base href="/second/">`, "https://app.example/doc/asset.js", nil},
		{"invalid-first-base", `<base href="http://[bad"><base href="/second/">`, "https://app.example/doc/asset.js", nil},
		{"missing-href-does-not-consume", `<base target="_blank"><base href="/second/">`, "https://app.example/second/asset.js", nil},
		{"first-duplicate-href", `<base href="/first/" href="/second/">`, "https://app.example/first/asset.js", nil},
		{"template-base-inert", `<template><base href="/inert/"></template><base href="/first/">`, "https://app.example/first/asset.js", nil},
		{"base-in-body-still-applies", `<body><base href="/first/">`, "https://app.example/first/asset.js", nil},
		{"data-base-rejected", `<base href="data:text/html,1"><base href="/second/">`, "https://app.example/doc/asset.js", nil},
		{"javascript-base-rejected", `<base href="javascript:1"><base href="/second/">`, "https://app.example/doc/asset.js", nil},
		{"header-denies-base", `<base href="/first/">`, "https://app.example/doc/asset.js", []string{"base-uri 'none'"}},
		{"blocked-first-base-consumed", `<base href="https://other.example/"><base href="/second/">`, "https://app.example/doc/asset.js", []string{"base-uri 'self'"}},
		{"self-base-allowed", `<base href="/first/">`, "https://app.example/first/asset.js", []string{"base-uri 'self'"}},
		{"default-src-not-base-fallback", `<base href="/first/">`, "https://app.example/first/asset.js", []string{"default-src 'none'; script-src https:"}},
		{"base-policy-intersection", `<base href="/first/">`, "https://app.example/doc/asset.js", []string{"base-uri 'self'", "base-uri 'none'"}},
		{"head-meta-base-policy", `<meta http-equiv="Content-Security-Policy" content="base-uri 'none'"><base href="/first/">`, "https://app.example/doc/asset.js", nil},
		{"body-meta-base-policy-ignored", `<body><meta http-equiv="Content-Security-Policy" content="base-uri 'none'"><base href="/first/">`, "https://app.example/first/asset.js", nil},
		{"later-meta-does-not-unset-base", `<base href="/first/"><meta http-equiv="Content-Security-Policy" content="base-uri 'none'">`, "https://app.example/first/asset.js", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cspDocumentPrefetch(t, tc.prefix+`<script src="asset.js" integrity="HASH"></script>`, tc.policies)
			if !reflect.DeepEqual(got, []string{tc.want}) {
				t.Fatalf("fetched=%v, want %s", got, tc.want)
			}
		})
	}
}

func TestCSPDocumentMetaHeadScopeAndSourceOrder(t *testing.T) {
	const deny = `<meta http-equiv="Content-Security-Policy" content="script-src 'none'">`
	const script = `<script src="asset.js" integrity="HASH"></script>`
	for _, tc := range []struct {
		name, body string
		fetch      bool
	}{
		{"implicit-head", deny + script, false},
		{"explicit-head", `<html><head>` + deny + `</head><body>` + script, false},
		{"after-head-pointer", `<head></head>` + deny + script, false},
		{"inline-text-retains-head", `<script>const a = 1;</script>` + deny + script, false},
		{"style-text-retains-head", `<style>body { color: red }</style>` + deny + script, false},
		{"title-text-retains-head", `<title>Page</title>` + deny + script, false},
		{"explicit-body-meta-ignored", `<body>` + deny + script, true},
		{"implicit-body-element-meta-ignored", `<p>Page</p>` + deny + script, true},
		{"implicit-body-text-meta-ignored", `Page` + deny + script, true},
		{"template-meta-inert", `<template>` + deny + `</template>` + script, true},
		{"nested-template-meta-inert", `<template><template></template>` + deny + `</template>` + script, true},
		{"template-script-inert", `<template>` + script + `</template>`, false},
		{"meta-after-resource-not-retroactive", script + deny, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cspDocumentPrefetch(t, tc.body, nil)
			if (len(got) == 1) != tc.fetch || len(got) > 1 {
				t.Fatalf("fetched=%v, want one fetch=%v", got, tc.fetch)
			}
		})
	}
	got := cspDocumentPrefetch(t, script+deny+strings.ReplaceAll(script, "asset.js", "later.js"), nil)
	if !reflect.DeepEqual(got, []string{"https://app.example/doc/asset.js"}) {
		t.Fatalf("source-order fetches=%v", got)
	}
}

func TestCSPDocumentResourceCallbackUsesPreparedBase(t *testing.T) {
	for _, policies := range [][]string{nil, {"base-uri 'none'"}} {
		page := cspExternalTestURL("https://app.example/doc/page")
		var resolved []string
		state := &sriRewriter{upstreamBase: page, cspPolicies: policies,
			resourceURL: func(raw string, base *url.URL) (string, bool) {
				if raw == "probe" || raw == "first/" {
					resolved = append(resolved, resolveResourceURL(raw, base))
				}
				return raw, false
			},
		}
		gate := scrub.NewGate(nil, nil, "target-001.local")
		rewriteHTML([]byte(`<base href="first/"><base href="/second/"><a href="probe">open</a>`), gate, false, false, nil, state)
		want := []string{"https://app.example/doc/first/", "https://app.example/doc/first/probe"}
		if len(policies) != 0 {
			want[1] = "https://app.example/doc/probe"
		}
		if !reflect.DeepEqual(resolved, want) {
			t.Fatalf("policies=%v: callback URLs=%v, want %v", policies, resolved, want)
		}
	}
}
