package rewriter

import (
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"

	"github.com/Splinters-io/blinder/internal/scrub"
)

var passthroughHeaders = map[string]bool{
	"content-type":                        true,
	"cache-control":                       true,
	"pragma":                              true,
	"expires":                             true,
	"vary":                                true,
	"x-content-type-options":              true,
	"x-frame-options":                     true,
	"x-xss-protection":                    true,
	"x-powered-by":                        true,
	"x-aspnet-version":                    true,
	"x-aspnetmvc-version":                 true,
	"x-generator":                         true,
	"x-drupal-cache":                      true,
	"x-varnish":                           true,
	"x-cache":                             true,
	"x-cache-hits":                        true,
	"x-served-by":                         true,
	"x-runtime":                           true,
	"x-request-id":                        true,
	"content-security-policy":             true,
	"content-security-policy-report-only": true,
	"strict-transport-security":           true,
	"access-control-allow-origin":         true,
	"access-control-allow-methods":        true,
	"access-control-allow-headers":        true,
	"access-control-expose-headers":       true,
	"access-control-max-age":              true,
	"access-control-allow-credentials":    true,
	"permissions-policy":                  true,
	"referrer-policy":                     true,
	"cross-origin-opener-policy":          true,
	"cross-origin-embedder-policy":        true,
	"cross-origin-resource-policy":        true,
	"www-authenticate":                    true,
	"retry-after":                         true,
	"server":                              true,
	"via":                                 true,
}

// This rewriter serves a new representation over a separate connection. The
// proxy computes its own framing and ETag; upstream byte ranges, digests and
// message signatures do not describe the rewritten output. Keep these explicit
// now that ordinary application headers no longer require an allowlist entry.
var droppedResponseHeaders = map[string]bool{
	"connection":                true,
	"proxy-connection":          true,
	"keep-alive":                true,
	"proxy-authenticate":        true,
	"proxy-authorization":       true,
	"proxy-authentication-info": true,
	"te":                        true,
	"trailer":                   true,
	"transfer-encoding":         true,
	"upgrade":                   true,
	"content-length":            true,
	"content-encoding":          true,
	"etag":                      true,
	"last-modified":             true,
	"accept-ranges":             true,
	"content-range":             true,
	"content-md5":               true,
	"digest":                    true,
	"content-digest":            true,
	"repr-digest":               true,
	"signature":                 true,
	"signature-input":           true,
	"authentication-info":       true,
	// These origin-bound controls were previously suppressed. Passing them
	// through could direct the browser outside the selected proxy route or
	// install reporting endpoints without origin-aware handling.
	"alt-svc":             true,
	"alt-used":            true,
	"nel":                 true,
	"report-to":           true,
	"reporting-endpoints": true,
}

var identityRiskHeaders = map[string]bool{
	"server":                      true,
	"x-powered-by":                true,
	"x-aspnet-version":            true,
	"x-aspnetmvc-version":         true,
	"x-generator":                 true,
	"x-served-by":                 true,
	"www-authenticate":            true,
	"access-control-allow-origin": true,
	"via":                         true,
}

var scrubHeaders = map[string]bool{
	"location":         true,
	"content-location": true,
	"link":             true,
	"refresh":          true,
	"p3p":              true,
	"x-redirect-by":    true,
}

var cspKeywords = map[string]bool{
	"'self'":                       true,
	"'unsafe-inline'":              true,
	"'unsafe-eval'":                true,
	"'strict-dynamic'":             true,
	"'none'":                       true,
	"'wasm-unsafe-eval'":           true,
	"'unsafe-hashes'":              true,
	"'report-sample'":              true,
	"'unsafe-allow-redirects'":     true,
	"'trusted-types-eval'":         true,
	"'inline-speculation-rules'":   true,
	"'report-sha256'":              true,
	"'report-sha384'":              true,
	"'report-sha512'":              true,
	"'unsafe-webtransport-hashes'": true,
}

var cspSchemeRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:$`)
var cspNonceHashRe = regexp.MustCompile(`(?i)^'(nonce|sha256|sha384|sha512)-[A-Za-z0-9+/_-]+={0,2}'$`)
var cspNonceValueRe = regexp.MustCompile(`^[A-Za-z0-9+/_-]+={0,2}$`)

var cspSourceDirectives = map[string]bool{
	"default-src": true, "child-src": true, "connect-src": true,
	"font-src": true, "frame-src": true, "img-src": true,
	"manifest-src": true, "media-src": true, "object-src": true,
	"script-src": true, "script-src-elem": true, "script-src-attr": true,
	"style-src": true, "style-src-elem": true, "style-src-attr": true,
	"worker-src": true, "base-uri": true, "form-action": true,
	"frame-ancestors": true,
}

// RewriteCSPNonce coordinates nonce-source values with HTML nonce attributes.
// Only identity-bearing values change. The valid-base64 namespace escapes
// literal values bearing our prefix, so an unchanged nonce cannot accidentally
// equal a generated nonce. Invalid inputs stay invalid instead of acquiring a
// valid source expression as a side effect of masking.
func RewriteCSPNonce(value string, gate *scrub.Gate) string {
	const prefix = scrub.OpaqueValueAliasPrefix
	masked := gate.Scrub(value, "csp:nonce")
	if !cspNonceValueRe.MatchString(value) {
		if cspNonceValueRe.MatchString(masked) {
			return "~" + masked
		}
		return masked
	}
	if masked != value {
		alias := prefix + "a-" + base64.RawURLEncoding.EncodeToString([]byte(masked))
		if gate.RegisterOpaqueValueAlias(alias, value) {
			return alias
		}
		// Conflicting registrations must never overwrite another value's
		// inverse or authorise that value through a shared nonce.
		return "~" + alias
	}
	return value
}

type ResponseHeaderOpts struct {
	OriginMapper  *OriginMapper
	RequestOrigin string
}

func RewriteResponseHeaders(resp http.Header, gate *scrub.Gate, aliasDomain string, targetHost string, opts ...ResponseHeaderOpts) http.Header {
	var originMapper *OriginMapper
	var requestOrigin string
	if len(opts) > 0 {
		originMapper = opts[0].OriginMapper
		requestOrigin = opts[0].RequestOrigin
	}
	out := make(http.Header)
	connectionFields := make(map[string]bool)
	for name, values := range resp {
		if !strings.EqualFold(name, "Connection") {
			continue
		}
		for _, value := range values {
			for _, field := range strings.Split(value, ",") {
				connectionFields[strings.ToLower(strings.TrimSpace(field))] = true
			}
		}
	}

	for name, values := range resp {
		lower := strings.ToLower(name)
		if droppedResponseHeaders[lower] || connectionFields[lower] {
			continue
		}

		if passthroughHeaders[lower] {
			if lower == "content-security-policy" || lower == "content-security-policy-report-only" {
				scrubbed := make([]string, len(values))
				for i, v := range values {
					scrubbed[i] = rewriteCSP(v, gate, aliasDomain, originMapper)
				}
				out[name] = scrubbed
				continue
			}
			if lower == "access-control-allow-origin" && originMapper != nil {
				scrubbed := make([]string, len(values))
				for i, v := range values {
					rewritten := originMapper.RewriteResponseOrigin(v, requestOrigin)
					// Mapped origins are already in the proxy namespace. Do not
					// rescrub them or the CORS protocol values; only raw upstream
					// values still need generic identity scrubbing.
					if rewritten != v || v == "*" || v == "null" {
						scrubbed[i] = rewritten
					} else {
						scrubbed[i] = gate.Scrub(v, "header:"+lower)
					}
				}
				out[name] = scrubbed
				continue
			}
			if identityRiskHeaders[lower] {
				scrubbed := make([]string, len(values))
				for i, v := range values {
					scrubbed[i] = gate.Scrub(v, "header:"+lower)
				}
				out[name] = scrubbed
				continue
			}
			out[name] = copyValues(values)
			continue
		}

		if scrubHeaders[lower] {
			scrubbed := make([]string, len(values))
			for i, v := range values {
				if lower == "location" || lower == "content-location" {
					scrubbed[i] = scrubResourceURL(v, gate, "header:"+lower, originMapper)
				} else {
					scrubbed[i] = gate.Scrub(v, "header:"+lower)
				}
			}
			out[name] = scrubbed
			continue
		}

		if lower == "set-cookie" {
			scrubbed := make([]string, len(values))
			for i, v := range values {
				scrubbed[i] = rewriteSetCookie(v, gate, aliasDomain, targetHost)
			}
			out[name] = scrubbed
			continue
		}

		// Unknown end-to-end fields can carry application diagnostics and other
		// observable behaviour. Preserve their values and multiplicity using the
		// same configured redaction as other identity-bearing response headers.
		// Identity-bearing field names remain suppressed as before: body aliases
		// are not valid HTTP field-name tokens, and safe reversible name mapping
		// needs its own collision-aware namespace.
		if gate.ResidualLeakCount(name) > 0 {
			continue
		}
		for _, value := range values {
			out.Add(name, gate.Scrub(value, "header:"+lower))
		}
	}

	return out
}

func RewriteRequestHeaders(req *http.Request, targetHost string, gate *scrub.Gate, origins *OriginMapper) *http.Request {
	clone := req.Clone(req.Context())
	clone.Host = targetHost

	if cookies := clone.Cookies(); len(cookies) > 0 {
		var parts []string
		for _, c := range cookies {
			originalName := gate.OriginalCookieName(c.Name)
			originalValue := gate.RestoreCookieValue(c.Name, c.Value, targetHost)
			parts = append(parts, originalName+"="+originalValue)
		}
		clone.Header.Set("Cookie", strings.Join(parts, "; "))
	}

	if values := clone.Header.Values("Referer"); len(values) == 1 {
		clone.Header.Set("Referer", origins.Rewrite(values[0], false))
	}
	if values := clone.Header.Values("Origin"); len(values) == 1 {
		clone.Header.Set("Origin", origins.Rewrite(values[0], true))
	}

	clone.Header.Del("Accept-Encoding")

	return clone
}

func rewriteCSP(csp string, gate *scrub.Gate, aliasDomain string, origins ...*OriginMapper) string {
	var originMapper *OriginMapper
	if len(origins) > 0 {
		originMapper = origins[0]
	}
	// A single field value can contain multiple independently enforced policies.
	// A comma is a policy delimiter even when no whitespace surrounds it.
	policies := strings.Split(csp, ",")
	for i, policy := range policies {
		policies[i] = rewriteCSPPolicy(policy, gate, originMapper)
	}
	return strings.Join(policies, ",")
}

func cspASCIIWhitespace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f'
}

func cspHasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return true
		}
	}
	return false
}

func rewriteCSPPolicy(policy string, gate *scrub.Gate, originMapper *OriginMapper) string {
	directives := strings.Split(policy, ";")
	rewritten := make([]string, 0, len(directives))

	for _, directive := range directives {
		directive = strings.TrimFunc(directive, cspASCIIWhitespace)
		if directive == "" {
			continue
		}

		// CSP discards non-ASCII directives. Unicode whitespace normalization or
		// masking must not turn such an ignored directive into an active one.
		if cspHasNonASCII(directive) {
			masked := gate.Scrub(directive, "csp:invalid")
			if !cspHasNonASCII(masked) {
				masked = "\uFFFD" + masked
			}
			rewritten = append(rewritten, masked)
			continue
		}
		tokens := strings.FieldsFunc(directive, cspASCIIWhitespace)
		if len(tokens) == 0 {
			continue
		}

		name := tokens[0]
		if !cspSourceDirectives[strings.ToLower(name)] && !strings.EqualFold(name, "report-uri") {
			// Fixed control grammar is not identity text. Application-defined
			// policy/report names still need masking; preserving every token
			// here would newly expose identities through these directives.
			for i, token := range tokens[1:] {
				if !cspControlKeyword(strings.ToLower(name), strings.ToLower(token)) {
					tokens[i+1] = gate.Scrub(token, "csp:control-name")
				}
			}
			rewritten = append(rewritten, strings.Join(tokens, " "))
			continue
		}
		scrubbed := []string{name}

		for _, token := range tokens[1:] {
			if cspNonceHashRe.MatchString(token) && strings.HasPrefix(strings.ToLower(token), "'nonce-") {
				scrubbed = append(scrubbed, token[:7]+RewriteCSPNonce(token[7:len(token)-1], gate)+"'")
			} else if cspKeywords[strings.ToLower(token)] || cspSchemeRe.MatchString(token) || cspNonceHashRe.MatchString(token) || token == "*" {
				scrubbed = append(scrubbed, token)
			} else {
				// Exact registered origins follow the resource URL mapping. The
				// helper protects generated local authorities and keeps path
				// restrictions. Wildcard and scheme-less sources do not name an
				// exact origin, so retain their existing generic scrubbing.
				scrubbed = append(scrubbed, scrubResourceURL(token, gate, "csp", originMapper))
			}
		}

		rewritten = append(rewritten, strings.Join(scrubbed, " "))
	}

	return strings.Join(rewritten, "; ")
}

func cspControlKeyword(directive, token string) bool {
	if directive == "sandbox" {
		switch token {
		case "allow-downloads", "allow-forms", "allow-modals", "allow-orientation-lock", "allow-pointer-lock", "allow-popups", "allow-popups-to-escape-sandbox", "allow-presentation", "allow-same-origin", "allow-scripts", "allow-storage-access-by-user-activation", "allow-top-navigation", "allow-top-navigation-by-user-activation", "allow-top-navigation-to-custom-protocols":
			return true
		}
	}
	if directive == "require-trusted-types-for" {
		return token == "'script'"
	}
	if directive == "trusted-types" {
		return token == "*" || token == "'none'" || token == "'allow-duplicates'"
	}
	return false
}

func rewriteSetCookie(cookie string, gate *scrub.Gate, aliasDomain string, targetHost string) string {
	parts := strings.Split(cookie, ";")
	rewritten := make([]string, 0, len(parts))

	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		lower := strings.ToLower(trimmed)

		if strings.HasPrefix(lower, "domain=") {
			continue
		}

		if i == 0 {
			eqIdx := strings.IndexByte(trimmed, '=')
			if eqIdx > 0 {
				cookieName := trimmed[:eqIdx]
				cookieValue := trimmed[eqIdx+1:]
				hashedName := gate.AliasCookieNameAndRecord(cookieName)
				scrubbed := gate.Scrub(cookieValue, "cookie:value")
				actual := gate.RecordCookieValue(hashedName, cookieValue, scrubbed, targetHost)
				rewritten = append(rewritten, hashedName+"="+actual)
				continue
			}
		}

		rewritten = append(rewritten, part)
	}

	return strings.Join(rewritten, ";")
}

func copyValues(vals []string) []string {
	out := make([]string, len(vals))
	copy(out, vals)
	return out
}
