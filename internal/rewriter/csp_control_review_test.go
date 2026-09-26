package rewriter

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestCSPControlReviewSandboxTokensRemainControlSyntax(t *testing.T) {
	gate := scrub.NewGate(nil, []string{"scripts", "forms", "origin"}, "alias.local")
	const policy = "sandbox allow-scripts allow-forms allow-same-origin; object-src 'none'"
	got := RewriteResponseHeaders(http.Header{"Content-Security-Policy": {policy}}, gate, "alias.local", "target.example")
	if got.Get("Content-Security-Policy") != policy {
		t.Fatalf("identity masking changed sandbox capabilities: %q", got.Get("Content-Security-Policy"))
	}
	gate = scrub.NewGate(nil, []string{"scripts", "AcmeCorp"}, "alias.local")
	body := string(RewriteBody([]byte(`<iframe sandbox="allow-scripts AcmeCorp allow-forms"></iframe>`), "text/html", "/", gate, false).Body)
	if strings.Contains(body, "AcmeCorp") || !strings.Contains(body, "allow-scripts") || !strings.Contains(body, "allow-forms") {
		t.Fatalf("sandbox attribute control grammar or masking changed: %s", body)
	}
}

func TestCSPControlReviewApplicationNamesRemainMasked(t *testing.T) {
	gate := scrub.NewGate(nil, []string{"AcmeCorp", "script"}, "alias.local")
	policy := "trusted-types AcmeCorp 'allow-duplicates'; report-to AcmeCorp; x-extension AcmeCorp; require-trusted-types-for 'script'"
	got := rewriteCSP(policy, gate, "alias.local")
	if strings.Contains(got, "AcmeCorp") {
		t.Fatalf("configured identity leaked through a non-source directive: %q", got)
	}
	if !strings.Contains(got, "require-trusted-types-for 'script'") || !strings.Contains(got, "'allow-duplicates'") {
		t.Fatalf("fixed control syntax was masked: %q", got)
	}
}

func TestCSPControlReviewNonceAttributeMatchesPolicy(t *testing.T) {
	gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	const nonce = "AcmeCorp"
	const policy = "script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'"
	gotHeaders := RewriteResponseHeaders(http.Header{"Content-Security-Policy": {policy}}, gate, "alias.local", "target.example")
	gotBody := string(RewriteBody([]byte(`<script nonce="AcmeCorp">window.ok = true</script><style nonce="AcmeCorp">p{color:red}</style>`), "text/html", "/", gate, false).Body)
	wantNonce := RewriteCSPNonce(nonce, gate)
	if !strings.Contains(gotHeaders.Get("Content-Security-Policy"), "'nonce-"+wantNonce+"'") || strings.Count(gotBody, `nonce="`+wantNonce+`"`) != 2 {
		t.Fatalf("CSP nonce and element nonce diverged: header=%q body=%q", gotHeaders.Get("Content-Security-Policy"), gotBody)
	}
	if strings.Contains(gotBody, nonce) || strings.Contains(gotHeaders.Get("Content-Security-Policy"), nonce) {
		t.Fatal("identity-bearing nonce remains visible")
	}
}

func TestCSPControlReviewNonceLiteralAndInvalidValuesStayDistinct(t *testing.T) {
	gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	masked := RewriteCSPNonce("AcmeCorp", gate)
	literal := RewriteCSPNonce(masked, gate)
	if masked == literal || !cspNonceValueRe.MatchString(masked) || !cspNonceValueRe.MatchString(literal) {
		t.Fatalf("generated and literal nonce collide or are invalid: %q %q", masked, literal)
	}
	for _, value := range []string{"", "AcmeCorp!", "AcmeCorp ", "AcmeCorp==='", "AcmeCorp\u00a0"} {
		if got := RewriteCSPNonce(value, gate); cspNonceValueRe.MatchString(got) {
			t.Errorf("invalid nonce %q became a valid source payload %q", value, got)
		}
	}
	if got := RewriteCSPNonce("plainNonceValue", gate); got != "plainNonceValue" {
		t.Fatalf("ordinary opaque nonce changed: %q", got)
	}
}

func TestCSPControlReviewNonceRoundTrip(t *testing.T) {
	gate := scrub.NewGate(nil, []string{"AcmeCorp"}, "alias.local")
	issued := RewriteCSPNonce("AcmeCorp", gate)
	for _, original := range []string{"AcmeCorp", issued, "bn1-literal", "plainNonceValue"} {
		alias := RewriteCSPNonce(original, gate.ForRequest())
		if got := gate.RestoreBody(alias); got != original {
			t.Errorf("nonce round trip %q => %q => %q", original, alias, got)
		}
		literal := gate.Scrub(alias, "test:literal")
		if got := gate.RestoreBody(literal); got != alias {
			t.Errorf("literal alias was consumed: %q => %q", literal, got)
		}
	}
}

func TestCSPControlReviewInvalidUnicodeDirectiveStaysIgnored(t *testing.T) {
	for _, policy := range []string{"script-src\u00a0'none'", "script-src https://AcmeCorp\u212a.test"} {
		gate := scrub.NewGate(nil, []string{"AcmeCorp", "K"}, "alias.local")
		got := rewriteCSP(policy, gate, "alias.local")
		if !cspHasNonASCII(got) {
			t.Fatalf("ignored non-ASCII policy became ASCII and enforceable: %q => %q", policy, got)
		}
	}
}

func TestCSPControlReviewReportURLAndControlDirectivesHaveSeparateGrammar(t *testing.T) {
	gate, origins := resourceRouteFixture(t)
	const policy = "report-uri https://target.example.com:8443/report; require-trusted-types-for 'script'; trusted-types default 'allow-duplicates'; report-to script"
	const want = "report-uri https://127.0.0.1:8099/report; require-trusted-types-for 'script'; trusted-types default 'allow-duplicates'; report-to script"
	if got := rewriteCSP(policy, gate, "127.0.0.1", origins); got != want {
		t.Fatalf("control syntax or report route changed: %q", got)
	}
}

func TestCSPControlReviewCommaJoinedPoliciesKeepBoundaries(t *testing.T) {
	gate, origins := resourceRouteFixture(t)
	const policy = "script-src https://target.example.com:8443,script-src https://target.example.com:8443"
	const want = "script-src https://127.0.0.1:8099,script-src https://127.0.0.1:8099"
	got := RewriteResponseHeaders(http.Header{"Content-Security-Policy": {policy}}, gate, "127.0.0.1", "target.example.com:8443", ResponseHeaderOpts{OriginMapper: origins})
	if strings.ReplaceAll(got.Get("Content-Security-Policy"), ", ", ",") != want {
		t.Fatalf("combined policies did not map each source independently: %q", got.Get("Content-Security-Policy"))
	}
}

func TestCSPControlReviewMetaPolicyUsesResourceRoute(t *testing.T) {
	gate, origins := resourceRouteFixture(t)
	const source = `<head><meta http-equiv="Content-Security-Policy" content="script-src https://target.example.com:8443"><script src="https://target.example.com:8443/app"></script></head>`
	got := string(RewriteBody([]byte(source), "text/html", "/", gate, false, RewriteOpts{Origins: origins}).Body)
	if !strings.Contains(got, `content="script-src https://127.0.0.1:8099"`) || !strings.Contains(got, `src="https://127.0.0.1:8099/app"`) {
		t.Fatalf("meta policy disagrees with the routed resource: %s", got)
	}
}
