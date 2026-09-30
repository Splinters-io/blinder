package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/config"
	"golang.org/x/net/html"
)

func challengeHeaderMap(raw string, base *url.URL) (string, bool) {
	u, err := base.Parse(raw)
	if err != nil || u.User != nil || u.Scheme != "https" || u.Host != "real-target.example" {
		return raw, false
	}
	u.Host = "target.localhost:8099"
	return u.String(), true
}

func TestChallengeHeaderDestinationsAreTranslatedWithoutPolicyGrants(t *testing.T) {
	base, _ := url.Parse("https://real-target.example/account/challenge")
	headers := http.Header{
		"Location":                            {"../continue?q=one&q=two"},
		"Content-Location":                    {"https://real-target.example/account/challenge"},
		"Refresh":                             {` 0 ; URL = "https://real-target.example/continue" `, "7"},
		"Content-Security-Policy":             {"script-src 'self'; report-uri /csp ../violations; report-to endpoint-name"},
		"Content-Security-Policy-Report-Only": {"default-src 'none'; report-uri https://real-target.example/reports"},
		"Reporting-Endpoints":                 {`endpoint-name="https://real-target.example/reports";priority=1;note="a,b", other.endpoint="/other"`},
		"Report-To":                           {`{"group":"real-target.example","max_age":9007199254740993,"rate":0.123456789012345678901,"note":"https://real-target.example/literal","endpoints":[{"url":"/reports","priority":12345678901234567890}]}`},
	}
	if err := rewriteChallengeHeaders(headers, base, challengeHeaderMap); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"Location":                            "https://target.localhost:8099/continue?q=one&q=two",
		"Content-Location":                    "https://target.localhost:8099/account/challenge",
		"Refresh":                             ` 0 ; URL = "https://target.localhost:8099/continue" `,
		"Content-Security-Policy":             "script-src 'self'; report-uri https://target.localhost:8099/csp https://target.localhost:8099/violations; report-to endpoint-name",
		"Content-Security-Policy-Report-Only": "default-src 'none'; report-uri https://target.localhost:8099/reports",
		"Reporting-Endpoints":                 `endpoint-name="https://target.localhost:8099/reports";priority=1;note="a,b", other.endpoint="https://target.localhost:8099/other"`,
	} {
		if got := headers.Get(name); got != want {
			t.Errorf("%s = %q; want %q", name, got, want)
		}
	}
	if headers.Values("Refresh")[1] != "7" {
		t.Fatal("delay-only refresh changed")
	}
	for _, want := range []string{`"group":"real-target.example"`, `"max_age":9007199254740993`, `"rate":0.123456789012345678901`, `"priority":12345678901234567890`, `"note":"https://real-target.example/literal"`, `"url":"https://target.localhost:8099/reports"`} {
		if !strings.Contains(headers.Get("Report-To"), want) {
			t.Errorf("Report-To lost exact field %s: %s", want, headers.Get("Report-To"))
		}
	}
}

func TestChallengeReportToPreservesGroupsAndLegacyArray(t *testing.T) {
	base, _ := url.Parse("https://real-target.example/challenge")
	group := `{"group":"one","max_age":1e+10,"endpoints":[{"url":"/report"}]}`
	for _, raw := range []string{group + ", " + group, "[" + group + "," + group + "]"} {
		headers := http.Header{"Report-To": {raw}}
		if err := rewriteChallengeHeaders(headers, base, challengeHeaderMap); err != nil {
			t.Fatal(err)
		}
		got := headers.Get("Report-To")
		if strings.HasPrefix(raw, "[") != strings.HasPrefix(got, "[") || strings.Count(got, `"max_age":1e+10`) != 2 || strings.Count(got, "https://target.localhost:8099/report") != 2 {
			t.Fatalf("report groups or exact numbers changed: %s", got)
		}
	}
}

func TestChallengeHeaderRejectsUnknownDestinationsAndUnsupportedSyntax(t *testing.T) {
	base, _ := url.Parse("https://real-target.example/challenge")
	for _, tc := range []struct{ name, value string }{
		{"Link", `<https://real-target.example/asset.js>; rel=preload; as=script`},
		{"Alt-Svc", `h3="real-target.example:443"`},
		{"Location", "https://unregistered.example/next"},
		{"Content-Location", "//unregistered.example/next"},
		{"Refresh", "0;url=https://unregistered.example/next"},
		{"Content-Security-Policy", "default-src 'self'; report-uri https://unregistered.example/report"},
		{"Report-To", `{"endpoints":[{"url":"https://unregistered.example/report"}]}`},
		{"Report-To", `{"endpoints":[{"url":123}]}`},
		{"Report-To", `{"endpoints":[{"url":null}]}`},
		{"Report-To", `{"endpoints":{}}`},
		{"Report-To", `{"endpoints":[]} trailing`},
		{"Reporting-Endpoints", `errors="https://unregistered.example/report"`},
		{"Reporting-Endpoints", `errors=("/report")`},
		{"Reporting-Endpoints", `errors="/report",`},
		{"Reporting-Endpoints", `errors="/report\q"`},
	} {
		t.Run(tc.name+"/"+tc.value, func(t *testing.T) {
			if err := rewriteChallengeHeaders(http.Header{tc.name: {tc.value}}, base, challengeHeaderMap); err == nil {
				t.Fatal("unsafe or unsupported challenge headers accepted")
			}
		})
	}
}

func TestChallengeEmptyActiveHeadersDoNotBlockView(t *testing.T) {
	base, _ := url.Parse("https://real-target.example/challenge")
	headers := http.Header{"Link": {""}, "Alt-Svc": {" \t"}}
	if err := rewriteChallengeHeaders(headers, base, challengeHeaderMap); err != nil {
		t.Fatalf("empty active headers rejected: %v", err)
	}
}

func TestChallengeViewRoutesRefreshOrFailsBeforeReplay(t *testing.T) {
	for _, tor := range []bool{false, true} {
		for _, blockedHeader := range []string{"", "Refresh", "Link", "Alt-Svc"} {
			unknown := blockedHeader != ""
			name := "direct"
			if tor {
				name = "tor"
			}
			if unknown {
				name += "/blocked-" + blockedHeader
			} else {
				name += "/target"
			}
			t.Run(name, func(t *testing.T) {
				s := captchaServer(t, captchaDeliveryConfig(t, captchaDeliveryBuiltin), nil)
				if tor {
					s.cfg.Tor = &config.TorConfig{SOCKSAddr: "127.0.0.1:9050"}
					if err := s.configureProviderRoutes("https"); err != nil {
						t.Fatal(err)
					}
				}
				target := "https://main.example/continue"
				if blockedHeader == "Refresh" {
					target = "https://unregistered.example/continue"
				}
				id := s.captchaQueue.Submit("hcaptcha", "https://main.example/protected", []byte("private challenge content"), "text/html")
				upstreamHeaders := http.Header{"Refresh": {"0;url=" + target}}
				if blockedHeader == "Link" {
					upstreamHeaders.Set("Link", `<https://main.example/asset.js>; rel=preload; as=script`)
				} else if blockedHeader == "Alt-Svc" {
					upstreamHeaders.Set("Alt-Svc", `h3="main.example:443"`)
				}
				s.captchaQueue.SetResponseHeaders(id, upstreamHeaders)
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() { defer close(done); s.captchaQueue.WaitForCompletion(ctx, id, time.Minute) }()
				defer func() { cancel(); <-done }()
				captchaFollowupWaiter(t, s, id)
				request := captchaDeliveryOperatorRequest(s, http.MethodGet, "challenge/"+id, nil)
				request.Header.Set("Authorization", "Bearer "+s.CaptchaOperatorToken())
				wrapper := httptest.NewRecorder()
				s.server.Handler.ServeHTTP(wrapper, request)
				z := html.NewTokenizer(strings.NewReader(wrapper.Body.String()))
				viewURL := ""
				for kind := z.Next(); kind != html.ErrorToken; kind = z.Next() {
					if kind != html.StartTagToken {
						continue
					}
					token := z.Token()
					if token.Data == "iframe" {
						for _, attr := range token.Attr {
							if attr.Key == "src" {
								viewURL = attr.Val
							}
						}
					}
				}
				if viewURL == "" {
					t.Fatalf("missing challenge view: %d %s", wrapper.Code, wrapper.Body.String())
				}
				viewRequest := httptest.NewRequest(http.MethodGet, viewURL, nil)
				viewRequest.RemoteAddr = "127.0.0.1:40001"
				view := httptest.NewRecorder()
				s.server.Handler.ServeHTTP(view, viewRequest)
				if unknown {
					if view.Code != http.StatusBadGateway || view.Header().Get("Refresh") != "" || view.Header().Get("Link") != "" || view.Header().Get("Alt-Svc") != "" || strings.Contains(view.Body.String(), "private challenge content") {
						t.Fatalf("unknown destination replayed: %d %v %s", view.Code, view.Header(), view.Body.String())
					}
				} else if view.Code != http.StatusOK || view.Header().Get("Refresh") != "0;url="+s.origins.Load().RewriteUpstreamURL(target) {
					t.Fatalf("target refresh escaped proxy routing: %d %v", view.Code, view.Header())
				}
				original, _ := s.captchaQueue.Get(id)
				for name := range upstreamHeaders {
					if original.ResponseHeaders.Get(name) != upstreamHeaders.Get(name) {
						t.Fatalf("upstream %s header evidence mutated", name)
					}
				}
			})
		}
	}
}
