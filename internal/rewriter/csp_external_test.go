package rewriter

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func cspExternalTestURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func TestCSPExternalDirectivePrecedenceAndPolicyIntersection(t *testing.T) {
	page := cspExternalTestURL("https://app.example/page")
	resource := cspExternalTestURL("https://cdn.example/script.js")
	for _, tc := range []struct {
		name, tag string
		policies  []string
		want      bool
	}{
		{"no-policy", "script", nil, true},
		{"unrelated-policy", "script", []string{"object-src 'none'"}, true},
		{"default-denies", "script", []string{"default-src 'none'"}, false},
		{"empty-directive-denies", "script", []string{"script-src"}, false},
		{"script-overrides-default", "script", []string{"default-src 'none'; script-src https://cdn.example"}, true},
		{"elem-overrides-script", "script", []string{"script-src https:; script-src-elem 'none'"}, false},
		{"attr-does-not-grant-element", "script", []string{"default-src 'none'; script-src-attr https:"}, false},
		{"style-elem-overrides-style", "link", []string{"style-src 'none'; style-src-elem https://cdn.example"}, true},
		{"style-does-not-use-script", "link", []string{"default-src 'none'; script-src https:"}, false},
		{"style-alias", "style", []string{"style-src https://cdn.example"}, true},
		{"first-duplicate-wins", "script", []string{"ScRiPt-SrC 'none'; script-src https:"}, false},
		{"first-empty-duplicate-wins", "script", []string{"script-src; script-src https:"}, false},
		{"none-alongside-grant-ignored", "script", []string{"script-src 'none' https://cdn.example"}, true},
		{"multiple-header-intersection", "script", []string{"script-src https:", "script-src 'self'"}, false},
		{"comma-intersection", "script", []string{"script-src https:,script-src 'none'"}, false},
		{"matching-intersection", "script", []string{"script-src https:", "script-src https://cdn.example"}, true},
		{"non-ascii-directive-ignored", "script", []string{"script-src\u00a0'none'"}, true},
		{"unknown-destination-conservative", "img", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CSPAllowsExternal(tc.policies, resource, page, tc.tag, "", ""); got != tc.want {
				t.Fatalf("allowed=%v, want %v for %v", got, tc.want, tc.policies)
			}
		})
	}
}

func TestCSPExternalNoncesIntegrityAndParserInsertedStrictDynamic(t *testing.T) {
	page := cspExternalTestURL("https://app.example/page")
	resource := cspExternalTestURL("https://cdn.example/script.js")
	h256 := cspBodyTestHash("sha256", "fixture", base64.StdEncoding)
	h384 := cspBodyTestHash("sha384", "fixture", base64.StdEncoding)
	i256, i384 := strings.Trim(h256, "'"), strings.Trim(h384, "'")
	for _, tc := range []struct {
		name, tag, policy, nonce, integrity string
		want                                bool
	}{
		{"matching-nonce", "script", "script-src 'nonce-AaBB=='", "AaBB==", "", true},
		{"nonce-is-case-sensitive", "script", "script-src 'nonce-AaBB=='", "aabb==", "", false},
		{"nonce-is-not-base64-normalized", "script", "script-src 'nonce-AaBB=='", "AaBB", "", false},
		{"nonce-alternative-to-url", "script", "script-src 'nonce-other' https:", "AaBB==", "", true},
		{"style-nonce", "link", "style-src 'nonce-AaBB=='", "AaBB==", "", true},
		{"hash-grant", "script", "script-src " + h256, "", i256, true},
		{"all-integrity-metadata-required", "script", "script-src " + h384, "", i256 + " " + i384, false},
		{"all-integrity-metadata-present", "script", "script-src " + h256 + " " + h384, "", i256 + " " + i384, true},
		{"unsupported-metadata-ignored", "script", "script-src " + h256, "", "unknown-Abcd " + i256, true},
		{"uppercase-attribute-algorithm-ignored", "script", "script-src " + h256, "", strings.Replace(i384, "sha384", "SHA384", 1) + " " + i256, true},
		{"uppercase-only-attribute-does-not-grant", "script", "script-src " + h256, "", strings.Replace(i256, "sha256", "SHA256", 1), false},
		{"legacy-attribute-alias", "script", "script-src " + h256, "", strings.Replace(i256, "sha256", "sha-256", 1), true},
		{"csp-algorithm-remains-case-insensitive", "script", "script-src " + strings.Replace(h256, "sha256", "SHA256", 1), "", i256, true},
		{"malformed-supported-stronger-item-still-constrains", "script", "script-src " + h256, "", i256 + " " + i384 + "=", false},
		{"invalid-metadata-does-not-grant", "script", "script-src " + h256, "", "sha256-not!base64", false},
		{"metadata-options", "script", "script-src " + h256, "", i256 + "?future-option", true},
		{"no-metadata-does-not-grant", "script", "script-src " + h256, "", "", false},
		{"style-hash-not-an-external-grant", "link", "style-src " + h256, "", i256, false},
		{"strict-dynamic-disables-host", "script", "script-src 'strict-dynamic' https:", "", "", false},
		{"strict-dynamic-nonce-grant", "script", "script-src 'strict-dynamic' 'nonce-AaBB=='", "AaBB==", "", true},
		{"strict-dynamic-hash-grant", "script", "script-src 'strict-dynamic' " + h256, "", i256, true},
		{"strict-dynamic-irrelevant-to-style", "link", "style-src 'strict-dynamic' https:", "", "", true},
		{"unsafe-inline-does-not-grant-external", "script", "script-src 'unsafe-inline'", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CSPAllowsExternal([]string{tc.policy}, resource, page, tc.tag, tc.nonce, tc.integrity); got != tc.want {
				t.Fatalf("allowed=%v, want %v for %s", got, tc.want, tc.policy)
			}
		})
	}
	if CSPAllowsExternal([]string{"script-src 'nonce-AaBB=='", "script-src 'none'"}, resource, page, "script", "AaBB==", "") {
		t.Fatal("nonce bypassed a separate enforcing policy")
	}
}

func TestCSPExternalURLSourceRestrictions(t *testing.T) {
	for _, tc := range []struct {
		name, source, resource, page string
		want                         bool
	}{
		{"self", "'self'", "https://app.example:8443/a", "https://app.example:8443/page", true},
		{"self-port-mismatch", "'self'", "https://app.example:443/a", "https://app.example:8443/page", false},
		{"self-default-upgrade", "'self'", "https://app.example/a", "http://app.example/page", true},
		{"self-no-downgrade", "'self'", "http://app.example/a", "https://app.example/page", false},
		{"self-ip", "'self'", "http://127.0.0.1:8099/a", "http://127.0.0.1:8099/page", true},
		{"scheme-upgrade", "http:", "https://cdn.example/a", "", true},
		{"scheme-no-downgrade", "https:", "http://cdn.example/a", "", false},
		{"host-case-insensitive", "https://CDN.example", "https://cdn.example/a", "", true},
		{"schemeless-inherits", "cdn.example", "https://cdn.example/a", "", true},
		{"schemeless-no-downgrade", "cdn.example", "http://cdn.example/a", "", false},
		{"explicit-port", "https://cdn.example:9443", "https://cdn.example:9443/a", "", true},
		{"insecure-default-port-upgrades", "http://cdn.example:80", "https://cdn.example:443/a", "", true},
		{"insecure-default-upgrade-requires-both", "http://cdn.example:80", "https://cdn.example:80/a", "", false},
		{"insecure-default-no-port-only-upgrade", "http://cdn.example:80", "http://cdn.example:443/a", "", false},
		{"omitted-port-means-default", "https://cdn.example", "https://cdn.example:9443/a", "", false},
		{"wildcard-port", "https://cdn.example:*", "https://cdn.example:9443/a", "", true},
		{"numeric-port-normalization", "https://cdn.example:00443", "https://cdn.example/a", "", true},
		{"wildcard-subdomain", "https://*.example", "https://a.b.example/a", "", true},
		{"wildcard-not-apex", "https://*.example", "https://example/a", "", false},
		{"wildcard-label-boundary", "https://*.example", "https://badexample/a", "", false},
		{"directory-path", "https://cdn.example/assets/", "https://cdn.example/assets/file.js", "", true},
		{"directory-not-string-prefix", "https://cdn.example/assets/", "https://cdn.example/assets-other/file.js", "", false},
		{"exact-path-not-prefix", "https://cdn.example/assets", "https://cdn.example/assets/file.js", "", false},
		{"path-case-sensitive", "https://cdn.example/Assets/", "https://cdn.example/assets/file.js", "", false},
		{"percent-decoded-components", "https://cdn.example/assets/%66ile.js", "https://cdn.example/assets/file.js?x=1", "", true},
		{"escaped-slash-not-separator", "https://cdn.example/a%2Fb", "https://cdn.example/a/b", "", false},
		{"unknown-source-syntax", "https://user@cdn.example", "https://cdn.example/a", "", false},
		{"network-wildcard", "*", "https://cdn.example:9443/a", "", true},
		{"wildcard-does-not-grant-data", "*", "data:text/javascript,1", "", false},
		{"explicit-data-scheme", "data:", "data:text/javascript,1", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := tc.page
			if page == "" {
				page = "https://app.example/page"
			}
			got := CSPAllowsExternal([]string{"script-src " + tc.source}, cspExternalTestURL(tc.resource), cspExternalTestURL(page), "script", "", "")
			if got != tc.want {
				t.Fatalf("source=%q resource=%s: allowed=%v want=%v", tc.source, tc.resource, got, tc.want)
			}
		})
	}
}

func TestCSPExternalIntegrityEquivalentEncodings(t *testing.T) {
	page := cspExternalTestURL("https://app.example/page")
	resource := cspExternalTestURL("https://cdn.example/script.js")
	for _, algorithm := range []string{"sha256", "sha384", "sha512"} {
		t.Run(algorithm, func(t *testing.T) {
			standard := cspBodyTestHash(algorithm, "a fixture with URL-safe digest characters", base64.StdEncoding)
			for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				alternative := cspBodyTestHash(algorithm, "a fixture with URL-safe digest characters", encoding)
				for _, pair := range [][2]string{{standard, alternative}, {alternative, standard}} {
					if !CSPAllowsExternal([]string{"script-src " + pair[0]}, resource, page, "script", "", strings.Trim(pair[1], "'")) {
						t.Errorf("equivalent digests denied: CSP %s, integrity %s", pair[0], pair[1])
					}
				}
			}
			invalid := strings.TrimSuffix(standard, "'") + "='"
			if CSPAllowsExternal([]string{"script-src " + invalid}, resource, page, "script", "", strings.Trim(standard, "'")) {
				t.Error("extra-padding CSP source granted a valid integrity digest")
			}
			if CSPAllowsExternal([]string{"script-src " + standard}, resource, page, "script", "", strings.Trim(invalid, "'")) {
				t.Error("extra-padding integrity metadata matched a valid CSP digest")
			}
		})
	}
}
