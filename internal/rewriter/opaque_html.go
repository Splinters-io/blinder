package rewriter

import (
	"bytes"
	"net/url"
	"strings"

	"github.com/Splinters-io/blinder/internal/urlutil"
	"golang.org/x/net/html"
)

// RewriteOpaqueHTML changes only URL attributes and CSP meta URL sources in a
// provider document. Script/style text, integrity and nonce values remain the
// original bytes; no bootstrap script or policy permission is injected.
func RewriteOpaqueHTML(body []byte, document *url.URL, policies []string, mapURL func(string, *url.URL) (string, bool), mapPolicy func(string) string) []byte {
	base := document
	active := append([]string(nil), policies...)
	state := cspDocumentState{}
	z := html.NewTokenizer(bytes.NewReader(body))
	var out bytes.Buffer
	for {
		kind := z.Next()
		if kind == html.ErrorToken {
			break
		}
		raw := append([]byte(nil), z.Raw()...)
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken && kind != html.EndTagToken {
			state.observe(kind, "", raw)
			out.Write(raw)
			continue
		}
		token := z.Token()
		inHead := state.observe(kind, token.Data, raw)
		if kind == html.EndTagToken {
			out.Write(raw)
			continue
		}
		attrs := make(map[string]string)
		for _, a := range token.Attr {
			if _, exists := attrs[a.Key]; !exists {
				attrs[a.Key] = a.Val
			}
		}
		isMeta := token.Data == "meta" && strings.EqualFold(attrs["http-equiv"], "Content-Security-Policy")
		if isMeta && inHead {
			active = append(active, attrs["content"])
		}
		if token.Data == "base" && state.templateDepth == 0 && !state.baseSeen {
			if href, ok := attrs["href"]; ok {
				state.baseSeen = true
				if document != nil {
					if candidate, err := document.Parse(href); err == nil && cspAllowsBase(active, candidate, document) {
						base = candidate
					}
				}
			}
		}
		changed := false
		for i, a := range token.Attr {
			value := a.Val
			switch a.Key {
			case "src", "href", "action", "formaction", "poster", "cite", "data":
				attributeBase := base
				if token.Data == "base" {
					attributeBase = document
				}
				if mapURL != nil {
					if mapped, ok := mapURL(value, attributeBase); ok {
						value = mapped
					}
				}
			case "srcdoc":
				value = string(RewriteOpaqueHTML([]byte(value), base, active, mapURL, mapPolicy))
			case "content":
				if isMeta && mapPolicy != nil {
					value = mapPolicy(value)
				} else if token.Data == "meta" && strings.EqualFold(attrs["http-equiv"], "refresh") && mapURL != nil {
					value, _ = urlutil.RewriteRefresh(value, func(raw string) (string, bool) { return mapURL(raw, base) })
				}
			}
			if value != a.Val {
				token.Attr[i].Val = value
				changed = true
			}
		}
		if changed {
			out.WriteString(token.String())
		} else {
			out.Write(raw)
		}
	}
	return out.Bytes()
}
