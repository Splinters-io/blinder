package captcha

import (
	"bytes"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"
)

func providerRuntimeFixture(t *testing.T) (*url.URL, *ProviderRoutes) {
	t.Helper()
	cfg, err := ParseConfig([]byte("version: 1\ncaptcha:\n  custom:\n    - name: fixture\n      resource_origins: [https://provider.example]\n      resource_url_regex: ['^https://provider\\.example/widget/']\n      tor_policy: route-with-target\n"))
	if err != nil {
		t.Fatal(err)
	}
	routes, err := NewProviderRoutes(cfg.Matcher, "https", "127.0.0.1:8099")
	if err != nil {
		t.Fatal(err)
	}
	document, _ := url.Parse("https://provider.example/widget/frame?stage=one")
	return document, routes
}

func TestProviderRuntimePreservesScriptsIntegrityAndDocumentPrefix(t *testing.T) {
	document, routes := providerRuntimeFixture(t)
	const prefix = "<!doctype html>\n<!-- fixture -->\n<html lang=\"en\"><head>"
	const scripts = `<script nonce="upstream-nonce">const upstream = 'https://provider.example';</script><script src="/widget/api.js" integrity="sha384-original" crossorigin="use-credentials"></script>`
	body := []byte(prefix + scripts + "</head><body>Provider</body></html>")
	got := InjectProviderRoutingRuntime(body, document, routes, nil)
	if bytes.Equal(got, body) || !bytes.HasPrefix(got, []byte(prefix+"<script>")) || !bytes.HasSuffix(got, []byte(scripts+"</head><body>Provider</body></html>")) {
		t.Fatalf("provider script/control bytes or leading document structure changed: %s", got)
	}
	for _, forbidden := range []string{"blinder-operator", "/__blinder/", `"session":`, `"fields":`, `"endpoint":`, "publishFields", "postMessage", "unsafe-inline"} {
		if bytes.Contains(got, []byte(forbidden)) {
			t.Errorf("provider helper contains operator metadata or policy grant %q", forbidden)
		}
	}
	if !bytes.Contains(got, []byte(routes.Routes()[0].Local.String())) {
		t.Fatal("provider alias map absent")
	}
}

func TestProviderRuntimeSkipsEveryPolicyRepresentation(t *testing.T) {
	document, routes := providerRuntimeFixture(t)
	for _, tc := range []struct {
		name, body string
		headers    http.Header
	}{
		{"enforcing_header", "<script src=api.js></script>", http.Header{"Content-Security-Policy": {"script-src 'self'"}}},
		{"report_only_header", "<script src=api.js></script>", http.Header{"Content-Security-Policy-Report-Only": {"script-src 'none'"}}},
		{"empty_header", "<script src=api.js></script>", http.Header{"content-security-policy": {""}}},
		{"nil_header_values", "<script src=api.js></script>", http.Header{"CONTENT-SECURITY-POLICY-REPORT-ONLY": nil}},
		{"meta", `<head><meta http-equiv="Content-Security-Policy" content="script-src 'none'"></head>`, nil},
		{"report_only_meta", `<meta http-equiv="Content-Security-Policy-Report-Only" content="script-src 'none'">`, nil},
		{"late_meta", `<body><script src=api.js></script><META HTTP-EQUIV="Content-Security-Policy" content=""></body>`, nil},
		{"entity_meta", `<meta http-equiv="Content&#45;Security&#45;Policy" content="">`, nil},
		{"template_meta", `<template><meta http-equiv="Content-Security-Policy" content=""></template>`, nil},
		{"duplicate_attribute", `<meta http-equiv="refresh" http-equiv="Content-Security-Policy" content="">`, nil},
		{"incomplete_meta", `<meta http-equiv="Content-Security-Policy" content="`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			if got := InjectProviderRoutingRuntime(body, document, routes, tc.headers); !bytes.Equal(body, got) {
				t.Fatalf("added provider bootstrap despite policy: %s", got)
			}
		})
	}
}

func TestProviderRuntimeOnlyRegisteredProviderDocuments(t *testing.T) {
	document, routes := providerRuntimeFixture(t)
	body := []byte("<p>unchanged</p>")
	unknown, _ := url.Parse("https://unknown.example/widget/frame")
	for _, base := range []*url.URL{nil, unknown} {
		if got := InjectProviderRoutingRuntime(body, base, routes, nil); !bytes.Equal(body, got) {
			t.Fatal("helper injected into an unknown document")
		}
	}
	if got := InjectProviderRoutingRuntime(body, document, nil, nil); !bytes.Equal(body, got) {
		t.Fatal("helper injected without routes")
	}
	withBOM := append([]byte{0xef, 0xbb, 0xbf}, body...)
	if got := InjectProviderRoutingRuntime(withBOM, document, routes, nil); !bytes.Equal(withBOM, got) {
		t.Fatal("helper changed BOM document parsing")
	}
}

func TestProviderRuntimeConfigurationCannotTerminateScript(t *testing.T) {
	document, routes := providerRuntimeFixture(t)
	document.RawQuery = `x=</script><script>alert(1)</script>`
	got := string(InjectProviderRoutingRuntime([]byte("<p>fixture</p>"), document, routes, nil))
	if strings.Count(got, "</script>") != 1 || strings.Contains(got, "<script>alert(1)") {
		t.Fatal("document URL terminated bootstrap")
	}
}

func TestProviderRuntimeSkipsUnsupportedDocumentEncodings(t *testing.T) {
	document, routes := providerRuntimeFixture(t)
	for _, tc := range []struct {
		name, contentType string
		body              []byte
	}{
		{"utf16be", "text/html; charset=utf-16be", []byte{0, '<', 0, 'p', 0, '>'}},
		{"utf16le", "text/html; charset=utf-16le", []byte{'<', 0, 'p', 0, '>', 0}},
		{"utf16be_bom", "text/html", []byte{0xfe, 0xff, 0, '<', 0, 'p', 0, '>'}},
		{"utf16le_bom", "text/html", []byte{0xff, 0xfe, '<', 0, 'p', 0, '>', 0}},
		{"invalid_utf8", "text/html; charset=utf-8", []byte{'<', 'p', '>', 0xff}},
		{"unsupported_charset", "text/html; charset=windows-1252", []byte("<p>ASCII fixture</p>")},
		{"invalid_mime", "text/html; charset=", []byte("<p>fixture</p>")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{"Content-Type": {tc.contentType}}
			if got := InjectProviderRoutingRuntime(tc.body, document, routes, headers); !bytes.Equal(got, tc.body) {
				t.Fatalf("injected a bootstrap into unsupported encoding: %q", got)
			}
		})
	}
	for _, contentType := range []string{"text/html", "text/html; charset=utf-8", "text/html; charset=us-ascii"} {
		body := []byte("<p>fixture</p>")
		if got := InjectProviderRoutingRuntime(body, document, routes, http.Header{"Content-Type": {contentType}}); bytes.Equal(got, body) {
			t.Errorf("supported encoding did not receive helper: %s", contentType)
		}
	}
}

func TestProviderRoutingRuntimeNativeRequests(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for provider routing runtime tests")
	}
	if output, err := exec.Command(node, "provider_runtime_test.js").CombinedOutput(); err != nil {
		t.Fatalf("provider runtime: %v\n%s", err, output)
	}
}
