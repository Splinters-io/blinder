package rewriter

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestCSPBodyDoesNotRepairInvalidHashPadding(t *testing.T) {
	const source = `window.marker = "AcmeCorp";`
	result := RewriteBody([]byte("<script>"+source+"</script>"), "text/html", "/", newTestGate(), false)
	valid := cspBodyTestHash("sha256", source, base64.StdEncoding)
	invalid := strings.TrimSuffix(valid, "'") + "='"
	policy := "script-src " + invalid
	headers := http.Header{"Content-Security-Policy": {policy}}
	result.CSPHashes.RewriteHeaders(headers)
	if got := headers.Get("Content-Security-Policy"); got != policy {
		t.Fatalf("invalid padding was repaired: %q => %q", policy, got)
	}
}

func cspBodyTestHash(algorithm, source string, encoding *base64.Encoding) string {
	var digest []byte
	switch algorithm {
	case "sha256":
		h := sha256.Sum256([]byte(source))
		digest = h[:]
	case "sha384":
		h := sha512.Sum384([]byte(source))
		digest = h[:]
	case "sha512":
		h := sha512.Sum512([]byte(source))
		digest = h[:]
	}
	return "'" + algorithm + "-" + encoding.EncodeToString(digest) + "'"
}

func cspBodyTestElements(t *testing.T, source, tag string) []*html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	var result []*html.Node
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == tag {
			result = append(result, n)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(doc)
	return result
}

func cspBodyTestText(n *html.Node) string {
	var result strings.Builder
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.TextNode {
			result.WriteString(child.Data)
		}
	}
	return result.String()
}

func cspBodyTestAttr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}

func TestCSPBodyHashAlgorithmsAndBase64Representations(t *testing.T) {
	for _, algorithm := range []string{"sha256", "sha384", "sha512"} {
		for name, encoding := range map[string]*base64.Encoding{"standard": base64.StdEncoding, "standard-unpadded": base64.RawStdEncoding, "url": base64.URLEncoding, "url-unpadded": base64.RawURLEncoding} {
			t.Run(algorithm+"/"+name, func(t *testing.T) {
				gate := newTestGate()
				original := `window.name = "AcmeCorp";`
				result := RewriteBody([]byte("<script>"+original+"</script>"), "text/html", "/", gate, false)
				scripts := cspBodyTestElements(t, string(result.Body), "script")
				if len(scripts) != 1 {
					t.Fatalf("unexpected script count: %s", result.Body)
				}
				rewritten := cspBodyTestText(scripts[0])
				if rewritten == original {
					t.Fatal("fixture did not change")
				}
				policy := "script-src " + cspBodyTestHash(algorithm, original, encoding)
				headers := http.Header{"Content-Security-Policy": {policy}, "Content-Security-Policy-Report-Only": {policy, "object-src 'none'"}}
				result.CSPHashes.RewriteHeaders(headers)
				want := "script-src " + cspBodyTestHash(algorithm, rewritten, base64.StdEncoding)
				if headers.Get("Content-Security-Policy") != want || headers.Get("Content-Security-Policy-Report-Only") != want {
					t.Fatalf("original grant was not translated: %v; want %s", headers, want)
				}
				if got := headers.Values("Content-Security-Policy-Report-Only"); len(got) != 2 || got[1] != "object-src 'none'" {
					t.Fatalf("independent report-only policy changed: %v", got)
				}
			})
		}
	}
}

func TestCSPBodyHashUsesParsedRawText(t *testing.T) {
	for _, tag := range []string{"script", "style"} {
		t.Run(tag, func(t *testing.T) {
			const original = "/* AcmeCorp\r\nnext\rlast\x00 &amp; */"
			body := "<" + tag + ">" + original + "</" + tag + ">"
			before := cspBodyTestText(cspBodyTestElements(t, body, tag)[0])
			if before != "/* AcmeCorp\nnext\nlast\ufffd &amp; */" {
				t.Fatalf("fixture DOM normalization differs: %q", before)
			}
			result := RewriteBody([]byte(body), "text/html", "/", newTestGate(), false)
			after := cspBodyTestText(cspBodyTestElements(t, string(result.Body), tag)[0])
			headers := http.Header{"Content-Security-Policy": {tag + "-src " + cspBodyTestHash("sha384", before, base64.StdEncoding)}}
			result.CSPHashes.RewriteHeaders(headers)
			if got, want := headers.Get("Content-Security-Policy"), tag+"-src "+cspBodyTestHash("sha384", after, base64.StdEncoding); got != want {
				t.Fatalf("policy was hashed over transport bytes instead of parsed text: %q; want %q", got, want)
			}
		})
	}
}

func TestCSPBodyRewriteCannotRescueOriginallyInvalidHash(t *testing.T) {
	for _, algorithm := range []string{"sha256", "sha384", "sha512"} {
		t.Run(algorithm, func(t *testing.T) {
			result := RewriteBody([]byte(`<script>window.name = "AcmeCorp";</script>`), "text/html", "/", newTestGate(), false)
			after := cspBodyTestText(cspBodyTestElements(t, string(result.Body), "script")[0])
			policy := "script-src 'unsafe-inline' " + cspBodyTestHash(algorithm, after, base64.StdEncoding)
			headers := http.Header{"Content-Security-Policy": {policy}}
			result.CSPHashes.RewriteHeaders(headers)
			fields := strings.Fields(headers.Get("Content-Security-Policy"))
			if len(fields) != 3 || fields[1] != "'unsafe-inline'" || !cspNonceHashRe.MatchString(fields[2]) {
				t.Fatalf("blocking hash-source syntax or inline keyword lost: %v", fields)
			}
			encoded := strings.TrimSuffix(strings.TrimPrefix(fields[2], "'"+algorithm+"-"), "'")
			digest, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil || len(digest) != 1 {
				t.Fatalf("invalid original became a valid output digest: %s", fields[2])
			}
		})
	}
}

func TestCSPBodyMetaPoliciesKeepTheirDocumentScope(t *testing.T) {
	const first, second, third = `window.first = "AcmeCorp";`, `window.second = "AcmeCorp";`, `window.third = "AcmeCorp";`
	hash := func(source string) string { return cspBodyTestHash("sha256", source, base64.StdEncoding) }
	firstPolicy := "script-src " + hash(first) + " " + hash(second) + ",script-src " + hash(third)
	secondPolicy := "script-src " + hash(second) + " " + hash(third)
	body := fmt.Sprintf(`<head><script>%s</script><meta http-equiv="Content-Security-Policy" content="%s"><script>%s</script><meta http-equiv="Content-Security-Policy" content="%s"><script>%s</script></head>`, first, html.EscapeString(firstPolicy), second, html.EscapeString(secondPolicy), third)
	result := RewriteBody([]byte(body), "text/html", "/", newTestGate(), false)
	scripts := cspBodyTestElements(t, string(result.Body), "script")
	metas := cspBodyTestElements(t, string(result.Body), "meta")
	if len(scripts) != 3 || len(metas) != 2 {
		t.Fatalf("document structure changed: %s", result.Body)
	}
	wantFirst := "script-src " + hash(first) + " " + hash(cspBodyTestText(scripts[1])) + ",script-src " + hash(cspBodyTestText(scripts[2]))
	wantSecond := "script-src " + hash(second) + " " + hash(cspBodyTestText(scripts[2]))
	if got := cspBodyTestAttr(metas[0], "content"); got != wantFirst {
		t.Errorf("first meta has wrong source scope: %q; want %q", got, wantFirst)
	}
	if got := cspBodyTestAttr(metas[1], "content"); got != wantSecond {
		t.Errorf("second meta has wrong source scope: %q; want %q", got, wantSecond)
	}
}

func TestCSPBodyUnsafeHashesAttributesUseDecodedValues(t *testing.T) {
	for _, tc := range []struct{ attribute, directive, value string }{
		{"onclick", "script-src-attr", `this.title = "AcmeCorp & cafe"`},
		{"style", "style-src-attr", `--label: "AcmeCorp & cafe"`},
	} {
		t.Run(tc.attribute, func(t *testing.T) {
			body := `<button ` + tc.attribute + `="` + html.EscapeString(tc.value) + `">click</button>`
			result := RewriteBody([]byte(body), "text/html", "/", newTestGate(), false)
			after := cspBodyTestAttr(cspBodyTestElements(t, string(result.Body), "button")[0], tc.attribute)
			for _, keyword := range []string{"'unsafe-hashes' ", ""} {
				policy := tc.directive + " " + keyword + cspBodyTestHash("sha512", tc.value, base64.StdEncoding)
				headers := http.Header{"Content-Security-Policy": {policy}}
				result.CSPHashes.RewriteHeaders(headers)
				want := tc.directive + " " + keyword + cspBodyTestHash("sha512", after, base64.StdEncoding)
				if got := headers.Get("Content-Security-Policy"); got != want {
					t.Fatalf("attribute grant or unsafe-hashes flag changed: %q; want %q", got, want)
				}
			}
		})
	}
}

func TestCSPBodyDistinctOriginalsCannotGainTheSameHashGrant(t *testing.T) {
	const allowed = `fetch("https://target.example.com:8443/api")`
	const blocked = `fetch("https://127.0.0.1:8099/api")`
	for _, order := range []struct {
		name, first, second string
		blockedIndex        int
	}{
		{"allowed-first", allowed, blocked, 1},
		{"blocked-first", blocked, allowed, 0},
	} {
		t.Run(order.name, func(t *testing.T) {
			gate, origins := resourceRouteFixture(t)
			result := RewriteBody([]byte("<script>"+order.first+"</script><script>"+order.second+"</script>"), "text/html", "/", gate, false, RewriteOpts{Origins: origins})
			headers := http.Header{"Content-Security-Policy": {"script-src " + cspBodyTestHash("sha256", allowed, base64.StdEncoding)}}
			result.CSPHashes.RewriteHeaders(headers)
			scripts := cspBodyTestElements(t, string(result.Body), "script")
			if len(scripts) == 2 {
				downstreamBlockedHash := cspBodyTestHash("sha256", cspBodyTestText(scripts[order.blockedIndex]), base64.StdEncoding)
				if strings.Contains(headers.Get("Content-Security-Policy"), downstreamBlockedHash) {
					t.Fatalf("originally blocked script gained the allowed script's translated hash: body=%s policy=%s", result.Body, headers.Get("Content-Security-Policy"))
				}
				downstreamAllowedHash := cspBodyTestHash("sha256", cspBodyTestText(scripts[1-order.blockedIndex]), base64.StdEncoding)
				if !strings.Contains(headers.Get("Content-Security-Policy"), downstreamAllowedHash) {
					t.Fatalf("collision handling blocked the permitted script: policy=%s", headers.Get("Content-Security-Policy"))
				}
			}
		})
	}
}
