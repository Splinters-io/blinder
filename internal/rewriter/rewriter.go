package rewriter

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/Splinters-io/blinder/internal/metadata"
	"github.com/Splinters-io/blinder/internal/scrub"
	"github.com/Splinters-io/blinder/internal/sri"
)

type BodyResult struct {
	Body        []byte
	Metadata    *metadata.Result
	ContentType string     // Nonempty when a replacement changes the media type.
	CSPHashes   *CSPHashes // Policy bindings for this HTML representation.
}

type RewriteOpts struct {
	CSPPolicies     []string // Original enforcing header policies, before URL/hash translation.
	StatusCode      int      // Upstream status; diagnostic HTML must not become filler text.
	Origins         *OriginMapper
	SRIPipeline     *sri.Pipeline
	UpstreamBase    *url.URL
	BaseRequest     *http.Request
	RegisterVersion func(upstreamURL, bodyVersion string) string
	// ResourceURL handles configured opaque resources before generic scrubbing.
	ResourceURL func(raw string, base *url.URL) (string, bool)
}

func RewriteBody(body []byte, contentType string, path string, gate *scrub.Gate, paranoid bool, opts ...RewriteOpts) BodyResult {
	ct := normalizeContentType(contentType)

	var opt RewriteOpts
	if len(opts) > 0 {
		opt = opts[0]
	}

	switch {
	case strings.HasPrefix(ct, "text/html"):
		meta := extractHTMLMetadata(body)
		var sr *sriRewriter
		if opt.SRIPipeline != nil || opt.ResourceURL != nil {
			sr = &sriRewriter{
				pipeline:        opt.SRIPipeline,
				upstreamBase:    opt.UpstreamBase,
				baseReq:         opt.BaseRequest,
				registerVersion: opt.RegisterVersion,
				resourceURL:     opt.ResourceURL,
				cspPolicies:     append([]string(nil), opt.CSPPolicies...),
			}
		}
		hashes := &CSPHashes{}
		return BodyResult{Body: rewriteHTML(body, gate, paranoid && opt.StatusCode < 400, opt.StatusCode >= 400, opt.Origins, sr, hashes), Metadata: meta, CSPHashes: hashes}
	case ct == "application/json" || strings.HasSuffix(ct, "+json"):
		return BodyResult{Body: scrubJSON(body, gate, "body:json:"+path)}
	case strings.HasPrefix(ct, "text/javascript") || ct == "application/javascript":
		return BodyResult{Body: rewriteJS(body, gate, path, opt.Origins)}
	case strings.HasPrefix(ct, "text/css"):
		return BodyResult{Body: rewriteCSS(body, gate, path, opt.Origins)}
	case strings.HasPrefix(ct, "text/xml") || ct == "application/xml" || strings.HasSuffix(ct, "+xml"):
		return BodyResult{Body: gate.ScrubBytes(body, "body:xml:"+path)}
	case strings.HasPrefix(ct, "image/"):
		meta := metadata.Extract(body)
		img := rewriteImage(body, gate, "body:image:"+path)
		return BodyResult{Body: img.body, Metadata: &meta, ContentType: img.contentType}
	case isBinaryContent(ct):
		meta := metadata.Extract(body)
		return BodyResult{Body: rewriteBinaryImage(ct), Metadata: &meta, ContentType: "image/gif"}
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
