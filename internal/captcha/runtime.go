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
	cfg, _ := json.Marshal(map[string]any{"base": base.String(), "endpoint": endpoint, "session": session, "origins": h.matcher.RouteWithTargetOrigins(), "fields": fields})
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
	data, _ := json.Marshal(map[string]any{"session": id, "fields": fields})
	return `<script>(function(c){const frame=document.querySelector('iframe');const form=document.querySelector('form.fields');window.addEventListener('message',function(e){if(e.source!==frame.contentWindow||!e.data||e.data.type!=='blinder-fields'||e.data.session!==c.session)return;for(const name of c.fields){const value=e.data.fields&&e.data.fields[name];if(typeof value!=='string'||value.length>65536)continue;for(const input of form.elements){if(input.name===name)input.value=value;}}});})(` + strings.TrimSpace(string(data)) + `);</script>`
}
