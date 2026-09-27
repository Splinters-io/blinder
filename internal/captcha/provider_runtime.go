package captcha

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

//go:embed provider_runtime.js
var providerRoutingRuntime string

// InjectProviderRoutingRuntime routes dynamically constructed provider URLs
// without changing the provider's script bytes or integrity metadata. This is
// deliberately bounded to documents without any CSP, including report-only and
// meta policies: adding a bootstrap must not change a policy's decisions or its
// violation reports. The relay still validates each requested resource URL.
func InjectProviderRoutingRuntime(body []byte, document *url.URL, routes *ProviderRoutes, headers http.Header) []byte {
	if document == nil || routes == nil || !providerRuntimeEncodingSupported(body, headers) || providerDocumentHasPolicy(body, headers) {
		return body
	}
	origin, ok := resourceURLOrigin(document)
	if !ok || routes.MapOrigin(origin, false) == origin {
		return body
	}
	aliases := make(map[string]string)
	for _, route := range routes.Routes() {
		aliases[route.Upstream.String()] = route.Local.String()
	}
	cfg, err := json.Marshal(struct {
		Base    string            `json:"base"`
		Aliases map[string]string `json:"aliases"`
	}{Base: document.String(), Aliases: aliases})
	if err != nil {
		return body
	}
	bootstrap := []byte("<script>;(function(cfg){" + providerRoutingRuntime + "})(" + string(cfg) + ");</script>")
	position := providerBootstrapPosition(body)
	result := make([]byte, 0, len(body)+len(bootstrap))
	result = append(result, body[:position]...)
	result = append(result, bootstrap...)
	return append(result, body[position:]...)
}

func providerRuntimeEncodingSupported(body []byte, headers http.Header) bool {
	if !utf8.Valid(body) || bytes.HasPrefix(body, []byte{0xef, 0xbb, 0xbf}) {
		return false
	}
	contentType := headers.Get("Content-Type")
	if contentType == "" {
		// Callers already selected an HTML document. An absent charset keeps
		// the existing ASCII-compatible path; an explicit encoding must match.
		return true
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	charset := strings.ToLower(params["charset"])
	return err == nil && mediaType == "text/html" && (charset == "" || charset == "utf-8" || charset == "us-ascii")
}

func providerDocumentHasPolicy(body []byte, headers http.Header) bool {
	for name := range headers {
		if strings.EqualFold(name, "Content-Security-Policy") || strings.EqualFold(name, "Content-Security-Policy-Report-Only") {
			return true
		}
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		kind := z.Next()
		if kind == html.ErrorToken {
			// Conservatively cover incomplete meta tags too. False positives
			// leave the original provider document unchanged.
			raw := strings.ToLower(html.UnescapeString(string(z.Raw())))
			return strings.Contains(raw, "<meta") && strings.Contains(raw, "content-security-policy")
		}
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
			continue
		}
		raw := strings.ToLower(html.UnescapeString(string(z.Raw())))
		token := z.Token()
		if token.Data != "meta" {
			continue
		}
		// Token decoding discards duplicate attributes. Any policy-shaped
		// meta tag is enough to decline injection, including malformed forms.
		if strings.Contains(raw, "content-security-policy") {
			return true
		}
		for _, attr := range token.Attr {
			if strings.EqualFold(attr.Key, "http-equiv") && strings.HasPrefix(strings.ToLower(strings.TrimSpace(attr.Val)), "content-security-policy") {
				return true
			}
		}
	}
}

// Keep a leading doctype, comments, whitespace and explicit head in place.
// Provider code must encounter the routing helper before its own first script.
func providerBootstrapPosition(body []byte) int {
	z := html.NewTokenizer(bytes.NewReader(body))
	position := 0
	for {
		kind := z.Next()
		raw := z.Raw()
		switch kind {
		case html.DoctypeToken, html.CommentToken:
			position += len(raw)
		case html.TextToken:
			if len(bytes.TrimSpace(raw)) != 0 {
				return position
			}
			position += len(raw)
		case html.StartTagToken:
			token := z.Token()
			if token.Data == "head" {
				return position + len(raw)
			}
			if token.Data != "html" {
				return position
			}
			position += len(raw)
		default:
			return position
		}
	}
}
