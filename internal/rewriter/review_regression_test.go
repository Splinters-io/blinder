package rewriter

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func TestReviewParanoidStillScrubsAttributes(t *testing.T) {
	gate := scrub.NewGate([]string{"acmecorp.io"}, []string{"AcmeCorp"}, "alias.local")
	body := []byte(`<a href="https://acmecorp.io/private" title="AcmeCorp">secret</a><form action='https://acmecorp.io/login'></form>`)
	got := string(RewriteBody(body, "text/html", "/", gate, true).Body)
	if strings.Contains(got, "acmecorp.io") || strings.Contains(got, "AcmeCorp") {
		t.Fatalf("paranoid mode leaks: %s", got)
	}
}

func TestReviewHeaderIdentityIsScrubbed(t *testing.T) {
	for name, value := range map[string]string{"Access-Control-Allow-Origin": "https://acmecorp.io", "WWW-Authenticate": `Basic realm="AcmeCorp"`, "X-Served-By": "edge.acmecorp.io", "Server": "AcmeCorp/1.0"} {
		t.Run(name, func(t *testing.T) {
			gate := scrub.NewGate([]string{"acmecorp.io"}, []string{"AcmeCorp"}, "alias.local")
			h := http.Header{}
			h.Set(name, value)
			got := RewriteResponseHeaders(h, gate, "alias.local", "acmecorp.io").Get(name)
			if strings.Contains(got, "acmecorp.io") || strings.Contains(got, "AcmeCorp") {
				t.Fatalf("identity reaches client: %s", got)
			}
		})
	}
}

func TestReviewJavaScriptTechnicalSurface(t *testing.T) {
	gate := scrub.NewGate(nil, nil, "alias.local")
	source := `document.querySelector("form").addEventListener("submit", function () { console.log(window.location.href); });`
	got := string(RewriteBody([]byte(source), "application/javascript", "/app.js", gate, false).Body)
	if got != source {
		t.Fatalf("ordinary executable property access corrupted: %s", got)
	}
}

func TestReviewJSONEscapedIdentity(t *testing.T) {
	gate := scrub.NewGate([]string{"acmecorp.io"}, []string{"AcmeCorp"}, "alias.local")
	body := `{"company":"\u0041cmeCorp"}`
	got := string(RewriteBody([]byte(body), "application/json", "/api", gate, false).Body)
	if got == body {
		t.Fatalf("escaped identity passes unchanged: %s", got)
	}
}
