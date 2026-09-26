package rewriter

import (
	"encoding/base64"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Splinters-io/blinder/internal/sri"
)

// CSPAllowsExternal checks original enforcing source lists before an initial
// parser-inserted script or stylesheet fetch. Callers must exclude report-only
// policies and pass the document origin (not a cross-origin base URL). A nonce
// must already have passed the element's HTML nonceability check. "link" means
// a stylesheet here; other link destinations need their own directive mapping.
//
// This is not a complete browser control evaluator: redirects, response checks,
// document sandboxing, mixed-content and upgrade-insecure-requests processing
// are separate. Unknown source expressions never grant prefetch permission.
// https://www.w3.org/TR/CSP3/#script-pre-request
func CSPAllowsExternal(policies []string, resource, page *url.URL, tag, nonce, integrity string) bool {
	if resource == nil || page == nil || resource.Scheme == "" || page.Scheme == "" {
		return false
	}
	family := ""
	switch strings.ToLower(tag) {
	case "script":
		family = "script"
	case "style", "link":
		family = "style"
	default:
		return false
	}
	for _, field := range policies {
		for _, policy := range strings.Split(field, ",") {
			directives := cspExternalDirectives(policy)
			var sources []string
			found := false
			for _, name := range []string{family + "-src-elem", family + "-src", "default-src"} {
				if sources, found = directives[name]; found {
					break
				}
			}
			if found && !cspExternalSourcesAllow(sources, resource, page, family == "script", nonce, integrity) {
				return false
			}
		}
	}
	return true
}

func cspExternalDirectives(policy string) map[string][]string {
	result := make(map[string][]string)
	for _, directive := range strings.Split(policy, ";") {
		if cspHasNonASCII(directive) {
			continue
		}
		fields := strings.FieldsFunc(directive, cspASCIIWhitespace)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		if _, exists := result[name]; !exists {
			result[name] = fields[1:]
		}
	}
	return result
}

func cspExternalSourcesAllow(sources []string, resource, page *url.URL, script bool, nonce, integrity string) bool {
	strictDynamic := false
	for _, source := range sources {
		if nonce != "" && cspNonceHashRe.MatchString(source) && strings.HasPrefix(strings.ToLower(source), "'nonce-") && source[7:len(source)-1] == nonce {
			return true
		}
		strictDynamic = strictDynamic || strings.EqualFold(source, "'strict-dynamic'")
	}
	if script {
		if cspExternalIntegrityMatches(sources, integrity) {
			return true
		}
		if strictDynamic {
			return false
		}
	}
	for _, source := range sources {
		if cspExternalURLMatches(source, resource, page) {
			return true
		}
	}
	return false
}

// CSP checks membership of every supported integrity item, not only the
// strongest SRI algorithm. This is metadata comparison, not body verification.
func cspExternalIntegrityMatches(sources []string, integrity string) bool {
	allowed := make(map[string]bool)
	for _, source := range sources {
		if cspNonceHashRe.MatchString(source) && !strings.HasPrefix(strings.ToLower(source), "'nonce-") {
			parts := strings.SplitN(source[1:len(source)-1], "-", 2)
			if digest, ok := cspExternalDigest(parts[1]); ok {
				allowed[strings.ToLower(parts[0])+"-"+digest] = true
			}
		}
	}
	// Attribute algorithms use the browser's SRI parser, not CSP's
	// case-insensitive hash-source grammar. Unknown attribute algorithms do
	// not impose a membership requirement; supported invalid digests do.
	entries := sri.ParseIntegrity(integrity)
	for _, entry := range entries {
		if !allowed[entry.Algorithm+"-"+string(entry.Digest)] {
			return false
		}
	}
	return len(entries) > 0
}

// Browsers compare decoded integrity bytes: valid unpadded and URL-safe
// spellings name the same digest. Do not trim padding indiscriminately: extra
// padding is invalid and must not turn an ignored CSP source into a grant.
func cspExternalDigest(value string) (string, bool) {
	value = strings.NewReplacer("-", "+", "_", "/").Replace(value)
	encoding := base64.StdEncoding
	if !strings.Contains(value, "=") {
		encoding = base64.RawStdEncoding
	}
	digest, err := encoding.DecodeString(value)
	return string(digest), err == nil
}

var cspExternalHostSource = regexp.MustCompile(`(?i)^(?:([a-z][a-z0-9+.-]*)://)?(\*|(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.?)(?::(\*|[0-9]+))?(/[^?#]*)?$`)

func cspExternalURLMatches(source string, resource, page *url.URL) bool {
	if source == "*" {
		return resource.Scheme == "http" || resource.Scheme == "https" || strings.EqualFold(resource.Scheme, page.Scheme)
	}
	if strings.EqualFold(source, "'self'") {
		if resource.Hostname() == "" || !strings.EqualFold(resource.Hostname(), page.Hostname()) || resource.Scheme == "blob" {
			return false
		}
		samePort := cspExternalPort(resource) == cspExternalPort(page)
		if strings.EqualFold(resource.Scheme, page.Scheme) && samePort {
			return true
		}
		defaults := cspExternalPort(resource) == cspExternalDefaultPort(resource.Scheme) && cspExternalPort(page) == cspExternalDefaultPort(page.Scheme)
		return (samePort || defaults) && (resource.Scheme == "https" || resource.Scheme == "wss" || page.Scheme == "http" && (resource.Scheme == "http" || resource.Scheme == "ws"))
	}
	if cspSchemeRe.MatchString(source) {
		return cspExternalSchemeMatches(strings.TrimSuffix(source, ":"), resource.Scheme)
	}
	parts := cspExternalHostSource.FindStringSubmatch(source)
	if parts == nil || resource.Hostname() == "" {
		return false
	}
	scheme := parts[1]
	if scheme == "" {
		scheme = page.Scheme
	}
	if !cspExternalSchemeMatches(scheme, resource.Scheme) {
		return false
	}
	host, pattern := strings.ToLower(resource.Hostname()), strings.ToLower(parts[2])
	// The loopback exception is the deployed CSP host-source behavior used by
	// local acceptance fixtures; arbitrary IP literals are not source grants.
	if ip := net.ParseIP(host); ip != nil && host != "127.0.0.1" {
		return false
	}
	if pattern != "*" {
		if strings.HasPrefix(pattern, "*.") {
			if !strings.HasSuffix(host, pattern[1:]) {
				return false
			}
		} else if host != pattern {
			return false
		}
	}
	if parts[3] != "*" {
		port := cspExternalDefaultPort(resource.Scheme)
		if parts[3] != "" {
			parsed, err := strconv.Atoi(parts[3])
			if err != nil || parsed > 65535 {
				return false
			}
			port = parsed
		}
		// Secure upgrade of the explicit insecure default port upgrades both
		// scheme and port, not just the scheme. See CSP3's changes from CSP2
		// and Chromium's InsecureHostSchemePortMatchesSecurePort regression.
		if parts[3] != "" && port == 80 && (strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "ws")) && (resource.Scheme == "https" || resource.Scheme == "wss") {
			port = 443
		}
		if cspExternalPort(resource) != port {
			return false
		}
	}
	return cspExternalPathMatches(parts[4], resource.EscapedPath())
}

func cspExternalSchemeMatches(pattern, scheme string) bool {
	pattern, scheme = strings.ToLower(pattern), strings.ToLower(scheme)
	return pattern == scheme || pattern == "http" && scheme == "https" || pattern == "ws" && (scheme == "wss" || scheme == "http" || scheme == "https") || pattern == "wss" && scheme == "https"
}

func cspExternalDefaultPort(scheme string) int {
	switch strings.ToLower(scheme) {
	case "http", "ws":
		return 80
	case "https", "wss":
		return 443
	case "ftp":
		return 21
	}
	return -1
}

func cspExternalPort(u *url.URL) int {
	if u.Port() == "" {
		return cspExternalDefaultPort(u.Scheme)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return -2
	}
	return port
}

func cspExternalPathMatches(pattern, path string) bool {
	if pattern == "" || pattern == "/" && path == "" {
		return true
	}
	a, b := strings.Split(pattern, "/"), strings.Split(path, "/")
	exact := !strings.HasSuffix(pattern, "/")
	if len(a) > len(b) || exact && len(a) != len(b) {
		return false
	}
	if !exact {
		a = a[:len(a)-1]
	}
	for i, part := range a {
		left, errA := url.PathUnescape(part)
		right, errB := url.PathUnescape(b[i])
		if errA != nil || errB != nil || left != right {
			return false
		}
	}
	return true
}
