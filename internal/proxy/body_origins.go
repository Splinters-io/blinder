package proxy

import (
	"net/http"
	"net/url"

	"github.com/Splinters-io/blinder/internal/rewriter"
	"github.com/Splinters-io/blinder/internal/scrub"
	"github.com/Splinters-io/blinder/internal/sri"
)

// Select the same representation for SRI prefetch and the eventual browser
// resource request. A resource on another configured origin is fetched through
// that route's alias, not the document's entry authority.
func scopeSRIRepresentation(cfg sri.PipelineConfig, origins *rewriter.OriginMapper, gate *scrub.Gate, paranoid bool) sri.PipelineConfig {
	cfg.ResourceRequest = func(resourceURL string, baseReq *http.Request) *http.Request {
		request := baseReq.Clone(baseReq.Context())
		view := origins.ForRequestHost(baseReq.Host)
		if view != nil {
			local, err := url.Parse(view.RewriteUpstreamURL(resourceURL))
			if err == nil && origins.Resolve(local.Host) != nil {
				request.Host = local.Host
			}
		}
		return request
	}
	cfg.RequestScrubFn = func(body []byte, contentType, path string, request *http.Request) []byte {
		result := rewriter.RewriteBody(body, contentType, path, gate.ForRequest(), paranoid, rewriter.RewriteOpts{Origins: origins.ForRequestHost(request.Host)})
		return result.Body
	}
	return cfg
}
