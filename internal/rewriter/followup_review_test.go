package rewriter

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func followupGate() *scrub.Gate {
	return scrub.NewGate([]string{"acmecorp.io"}, []string{"AcmeCorp"}, "alias.local")
}

func TestFollowupInlineJavaScriptStillWorks(t *testing.T) {
	source := `<script>document.querySelector("form").addEventListener("submit", function () { console.log(window.location.href); });</script>`
	got := string(RewriteBody([]byte(source), "text/html", "/", followupGate(), false).Body)
	if got != source {
		t.Fatalf("inline JavaScript corrupted: %s", got)
	}
}

func TestFollowupJSTemplateExpressionPrivacy(t *testing.T) {
	source := "const label = `${\"AcmeCorp\"}`;"
	got := string(RewriteBody([]byte(source), "application/javascript", "/app.js", followupGate(), false).Body)
	if strings.Contains(got, "AcmeCorp") {
		t.Fatalf("template expression leaks identity: %s", got)
	}
}

func TestFollowupJSONKeyPrivacy(t *testing.T) {
	source := `{"AcmeCorp":"ok","https://acmecorp.io":true}`
	got := string(RewriteBody([]byte(source), "application/json", "/api", followupGate(), false).Body)
	if strings.Contains(got, "AcmeCorp") || strings.Contains(got, "acmecorp.io") {
		t.Fatalf("JSON object keys leak identity: %s", got)
	}
}

func TestFollowupJSONNumberFidelity(t *testing.T) {
	source := `{"id":9007199254740993}`
	got := string(RewriteBody([]byte(source), "application/json", "/api", followupGate(), false).Body)
	if got != source {
		t.Fatalf("JSON identifier changed: input %s output %s", source, got)
	}
}

func TestFollowupMediaTypeFidelity(t *testing.T) {
	for _, ct := range []string{"application/vnd.api+json", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"} {
		t.Run(ct, func(t *testing.T) {
			h := http.Header{}
			h.Set("Content-Type", ct)
			got := RewriteResponseHeaders(h, followupGate(), "alias.local", "acmecorp.io").Get("Content-Type")
			if got != ct {
				t.Fatalf("MIME type changed: %q -> %q", ct, got)
			}
		})
	}
}

func TestFollowupDomainCookieWorksOnLoopback(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "session_id=abc123; Domain=acmecorp.io; Path=/; Secure; HttpOnly")
	rewritten := RewriteResponseHeaders(h, followupGate(), "alias.local", "acmecorp.io")
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	clientURL, err := url.Parse("https://127.0.0.1:8099/login")
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{Header: rewritten}
	jar.SetCookies(clientURL, resp.Cookies())
	if got := jar.Cookies(clientURL); len(got) == 0 {
		t.Fatalf("loopback client rejects rewritten cookie: %s", rewritten.Get("Set-Cookie"))
	}
}
