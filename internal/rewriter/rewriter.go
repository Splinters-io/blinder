package rewriter

import (
	"strings"

	"github.com/Splinters-io/blinder/internal/metadata"
	"github.com/Splinters-io/blinder/internal/scrub"
)

type BodyResult struct {
	Body     []byte
	Metadata *metadata.Result
}

func RewriteBody(body []byte, contentType string, path string, gate *scrub.Gate, paranoid bool) BodyResult {
	ct := normalizeContentType(contentType)

	switch {
	case strings.HasPrefix(ct, "text/html"):
		return BodyResult{Body: rewriteHTML(body, gate, paranoid)}
	case ct == "application/json" || strings.HasSuffix(ct, "+json"):
		return BodyResult{Body: gate.ScrubBytes(body, "body:json:"+path)}
	case strings.HasPrefix(ct, "text/javascript") || ct == "application/javascript":
		return BodyResult{Body: gate.ScrubBytes(body, "body:js:"+path)}
	case strings.HasPrefix(ct, "text/css"):
		return BodyResult{Body: rewriteCSS(body, gate, path)}
	case strings.HasPrefix(ct, "text/xml") || ct == "application/xml" || strings.HasSuffix(ct, "+xml"):
		return BodyResult{Body: gate.ScrubBytes(body, "body:xml:"+path)}
	case isBinaryContent(ct):
		meta := metadata.Extract(body)
		return BodyResult{Body: rewriteBinaryImage(ct), Metadata: &meta}
	case strings.HasPrefix(ct, "text/"):
		return BodyResult{Body: gate.ScrubBytes(body, "body:text:"+path)}
	default:
		return BodyResult{Body: gate.ScrubBytes(body, "body:generic:"+path)}
	}
}

func isBinaryContent(ct string) bool {
	return strings.HasPrefix(ct, "image/") ||
		strings.HasPrefix(ct, "video/") ||
		strings.HasPrefix(ct, "audio/") ||
		ct == "application/pdf" ||
		ct == "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
		ct == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" ||
		ct == "application/vnd.openxmlformats-officedocument.presentationml.presentation" ||
		ct == "font/ttf" || ct == "font/otf" || ct == "font/woff" || ct == "font/woff2" ||
		ct == "application/font-woff" || ct == "application/font-woff2"
}

func normalizeContentType(ct string) string {
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = ct[:idx]
	}
	return strings.TrimSpace(strings.ToLower(ct))
}
