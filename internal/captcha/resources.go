package captcha

import (
	"bytes"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

const resourcePath = "/__blinder/captcha/res"

// RewriteResourceURL operates on a decoded URL attribute, before identity
// scrubbing. Provider URLs are opaque: filenames and token values are not domains
// or identity text. Fragments stay browser-side, outside the relay parameter.
func (m *Matcher) RewriteResourceURL(raw string, base *url.URL, route bool) (string, bool) {
	if m == nil {
		return raw, false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw, false
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	if u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || !m.IsProviderResource(u) {
		return raw, false
	}
	if !route || !m.ShouldRouteResource(u) {
		return raw, true
	}
	fragment := u.EscapedFragment()
	u.Fragment, u.RawFragment = "", ""
	result := resourcePath + "?u=" + url.QueryEscape(u.String())
	if fragment != "" {
		result += "#" + fragment
	}
	return result, true
}

// RewriteProviderHTML is also used for the operator's srcdoc and relayed provider
// frames. Tokenization decodes HTML entities exactly once; serialization escapes
// the resulting local URL exactly once. Raw script text is never URL-substituted.
func (m *Matcher) RewriteProviderHTML(body []byte, base *url.URL, sessions ...string) []byte {
	session := ""
	if len(sessions) > 0 {
		session = sessions[0]
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	var out bytes.Buffer
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			out.Write(z.Raw())
			continue
		}
		t := z.Token()
		if t.Data == "base" {
			for _, a := range t.Attr {
				if a.Key == "href" && base != nil {
					if u, err := base.Parse(a.Val); err == nil {
						base = u
					}
				}
			}
			// Upstream bases must not turn relay-relative URLs into direct requests.
			continue
		}
		for i, a := range t.Attr {
			switch a.Key {
			case "src", "href", "action", "formaction", "poster", "cite", "data":
				if v, ok := m.RewriteResourceURL(a.Val, base, true); ok {
					if session != "" && strings.HasPrefix(v, resourcePath+"?") {
						u, _ := url.Parse(v)
						q := u.Query()
						q.Set("sid", session)
						u.RawQuery = q.Encode()
						v = u.String()
					}
					if v == a.Val && base != nil {
						if u, err := base.Parse(v); err == nil {
							v = u.String()
						}
					}
					t.Attr[i].Val = v
				}
			case "srcdoc":
				t.Attr[i].Val = string(m.RewriteProviderHTML([]byte(a.Val), base, session))
			}
		}
		out.WriteString(t.String())
	}
	return out.Bytes()
}

// The operator page is an isolated human-only surface. In Tor mode, unhandled
// dynamic network references must be blocked rather than silently sent directly.
// Explicit direct providers remain permitted. This is containment, not a claim
// that every provider's dynamically assembled URLs are already compatible.
func (m *Matcher) OperatorCSP() string {
	sources := "'self'"
	for _, p := range m.providers {
		if p.TorPolicy != TorPolicyDirect {
			continue
		}
		for _, origin := range p.ResourceOrigins {
			if u, err := url.Parse(origin); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.User == nil {
				sources += " " + u.Scheme + "://" + u.Host
			}
		}
	}
	return strings.Join([]string{
		"frame-ancestors 'none'", "default-src " + sources,
		"script-src " + sources + " 'unsafe-inline'", "style-src " + sources + " 'unsafe-inline'",
		"img-src " + sources + " data: blob:", "font-src " + sources + " data:",
		"connect-src " + sources, "frame-src " + sources, "form-action 'self'",
		"base-uri 'none'", "object-src 'none'",
	}, "; ")
}
