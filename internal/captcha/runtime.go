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

func (h *OperatorHandler) injectRuntime(body []byte, base *url.URL, r *http.Request, session string) []byte {
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
	var origins []string
	if h.routeResources {
		origins = h.matcher.RouteWithTargetOrigins()
	}
	cfg, _ := json.Marshal(map[string]any{"base": base.String(), "endpoint": endpoint, "session": session, "origins": origins, "fields": fields})
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

func operatorCompletionScript(id string, fields []string, automatic bool) string {
	if fields == nil {
		fields = []string{}
	}
	data, _ := json.Marshal(map[string]any{"session": id, "fields": fields, "automatic": automatic})
	return `<script>(function(c){` + operatorCompletionRuntime + `})(` + strings.TrimSpace(string(data)) + `);</script>`
}
