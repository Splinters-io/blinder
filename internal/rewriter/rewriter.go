package rewriter

import (
	"strings"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func RewriteBody(body []byte, contentType string, path string, gate *scrub.Gate, paranoid bool) []byte {
	ct := normalizeContentType(contentType)

	switch {
	case strings.HasPrefix(ct, "text/html"):
		return rewriteHTML(body, gate, paranoid)
	case ct == "application/json" || strings.HasSuffix(ct, "+json"):
		return gate.ScrubBytes(body, "body:json:"+path)
	case strings.HasPrefix(ct, "text/javascript") || ct == "application/javascript":
		return gate.ScrubBytes(body, "body:js:"+path)
	case strings.HasPrefix(ct, "text/css"):
		return rewriteCSS(body, gate, path)
	case strings.HasPrefix(ct, "text/xml") || ct == "application/xml" || strings.HasSuffix(ct, "+xml"):
		return gate.ScrubBytes(body, "body:xml:"+path)
	case strings.HasPrefix(ct, "image/"):
		return rewriteBinaryImage(ct)
	case strings.HasPrefix(ct, "text/"):
		return gate.ScrubBytes(body, "body:text:"+path)
	default:
		return gate.ScrubBytes(body, "body:generic:"+path)
	}
}

func normalizeContentType(ct string) string {
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = ct[:idx]
	}
	return strings.TrimSpace(strings.ToLower(ct))
}
