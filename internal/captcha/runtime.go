package captcha

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

//go:embed runtime.js
var resourceRuntime string

//go:embed operator_completion.js
var operatorCompletionRuntime string

func (h *OperatorHandler) injectRuntime(body []byte, base *url.URL, r *http.Request, session string, allowedFields ...[]string) []byte {
	if base == nil {
		return body
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	endpoint := scheme + "://" + r.Host + resourcePath
	var fields []string
	for _, p := range h.matcher.providers {
		fields = append(fields, p.OpaqueFields...)
	}
	if len(allowedFields) > 0 {
		fields = allowedFields[0]
	}
	var origins []string
	if h.routeResources {
		origins = h.matcher.RouteWithTargetOrigins()
	}
	aliases := make(map[string]string)
	for _, route := range h.providerRoutes.Routes() {
		aliases[route.Upstream.String()] = route.Local.String()
	}
	cfg, _ := json.Marshal(map[string]any{"base": base.String(), "endpoint": endpoint, "session": session, "origins": origins, "aliases": aliases, "fields": fields, "parentOrigin": h.operatorOrigin})
	bootstrap := []byte("<script>;(function(cfg){" + resourceRuntime + "})(" + string(cfg) + ");</script>")
	pos := 0
	trim := bytes.TrimLeft(body, " \r\n\t")
	if bytes.HasPrefix(bytes.ToLower(trim), []byte("<!doctype")) {
		if end := bytes.IndexByte(trim, '>'); end >= 0 {
			pos = len(body) - len(trim) + end + 1
		}
	}
	result := make([]byte, 0, len(body)+len(bootstrap))
	result = append(result, body[:pos]...)
	result = append(result, bootstrap...)
	result = append(result, body[pos:]...)
	return result
}

func operatorTokenBridge(id string, fields []string) string {
	return operatorCompletionScript(id, fields, false)
}

func operatorSolveSubmission(id string, fields []string) string {
	return operatorCompletionScript(id, fields, true)
}

func operatorCompletionScript(id string, fields []string, automatic bool, expectedOrigin ...string) string {
	if fields == nil {
		fields = []string{}
	}
	origin := ""
	if len(expectedOrigin) > 0 {
		origin = expectedOrigin[0]
	}
	data, _ := json.Marshal(map[string]any{"session": id, "fields": fields, "automatic": automatic, "origin": origin})
	return `<script>(function(c){` + operatorCompletionRuntime + `})(` + strings.TrimSpace(string(data)) + `);</script>`
}
