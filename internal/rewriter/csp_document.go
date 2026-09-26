package rewriter

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// Track the head insertion modes needed by the static SRI prepass. The head
// may be implicit, and metadata immediately after </head> is inserted through
// the head pointer until the body begins. Template contents remain inert.
// This does not attempt to execute document.write or model DOM mutations.
type cspDocumentState struct {
	phase         uint8 // before head, in head, after head, in body
	templateDepth int
	textTag       string
	baseSeen      bool
}

func (d *cspDocumentState) observe(kind html.TokenType, tag string, raw []byte) bool {
	if kind == html.TextToken {
		if d.templateDepth == 0 && d.textTag == "" && strings.TrimFunc(string(raw), cspASCIIWhitespace) != "" {
			d.phase = 3
		}
		return false
	}
	if kind == html.EndTagToken {
		if d.textTag == tag {
			d.textTag = ""
		}
		if tag == "template" && d.templateDepth > 0 {
			d.templateDepth--
			return false
		}
		if d.templateDepth > 0 {
			return false
		}
		if tag == "head" && d.phase < 2 {
			d.phase = 2
		} else if (tag == "body" || tag == "html" || tag == "br") && d.phase < 3 {
			d.phase = 3
		}
		return false
	}
	if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
		return false
	}
	if tag == "template" {
		if d.phase == 0 {
			d.phase = 1
		}
		d.templateDepth++
		return false
	}
	if d.templateDepth > 0 {
		return false
	}
	if tag == "html" {
		return false
	}
	if tag == "head" {
		if d.phase == 0 {
			d.phase = 1
		}
		return false
	}
	metadata := false
	switch tag {
	case "base", "basefont", "bgsound", "link", "meta", "noframes", "script", "style":
		metadata = true
	case "title", "noscript":
		metadata = d.phase < 2
	}
	if !metadata {
		d.phase = 3
	} else if d.phase == 0 {
		d.phase = 1
	}
	switch tag {
	case "script", "style", "title", "noscript", "noframes", "xmp", "iframe", "noembed", "plaintext", "textarea":
		d.textTag = tag
	}
	return metadata && d.phase < 3
}

// base-uri is a navigation directive: default-src does not provide a fallback,
// and nonces/hashes do not grant a URL. Each enforcing policy must permit it.
func cspAllowsBase(policies []string, candidate, document *url.URL) bool {
	for _, field := range policies {
		for _, policy := range strings.Split(field, ",") {
			sources, exists := cspExternalDirectives(policy)["base-uri"]
			if !exists {
				continue
			}
			allowed := false
			for _, source := range sources {
				if cspExternalURLMatches(source, candidate, document) {
					allowed = true
					break
				}
			}
			if !allowed {
				return false
			}
		}
	}
	return true
}
