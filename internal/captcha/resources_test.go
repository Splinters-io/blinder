package captcha

import (
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestProviderResourceURLSemantics(t *testing.T) {
	cfg, err := ParseConfig([]byte(`version: 1
captcha:
  custom:
    - name: scoped
      resource_origins: [https://provider.test:8443]
      resource_url_regex: ['^https://provider\.test:8443/assets/']
    - name: direct
      resource_origins: [https://provider.test]
      tor_policy: direct
`))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse("https://provider.test:8443/assets/frame")
	for _, raw := range []string{
		"https://provider.test:8443/assets/api.js?x=a%26b&x=c+z#ready",
		"//provider.test:8443/assets/api.js?x=1&x=2",
		"api.js?x=%2F&flag",
	} {
		got, ok := cfg.Matcher.RewriteResourceURL(raw, base, true)
		u, err := url.Parse(got)
		want, _ := base.Parse(raw)
		fragment := want.Fragment
		want.Fragment, want.RawFragment = "", ""
		if err != nil || !ok || u.Path != resourcePath || u.Query().Get("u") != want.String() || u.Fragment != fragment {
			t.Errorf("route changed URL: raw=%q result=%q want=%q", raw, got, want)
		}
		direct, ok := cfg.Matcher.RewriteResourceURL(raw, base, false)
		if !ok || direct != raw {
			t.Errorf("non-Tor rewrite: %q -> %q", raw, direct)
		}
	}
	for _, raw := range []string{"https://provider.test:8443/outside", "https://provider.test.evil/assets/api.js", "http://provider.test:8443/assets/api.js", "https://user:pass@provider.test:8443/assets/api.js"} {
		if _, ok := cfg.Matcher.RewriteResourceURL(raw, base, true); ok {
			t.Errorf("out-of-scope URL accepted: %s", raw)
		}
	}
	u, _ := url.Parse("https://provider.test:8443/assets/api.js")
	if !cfg.Matcher.ShouldRouteResource(u) {
		t.Fatal("direct rule on another port overrode Tor resource")
	}
	if got, ok := cfg.Matcher.RewriteResourceURL("https://provider.test/api.js", base, true); !ok || got != "https://provider.test/api.js" {
		t.Fatal("explicit direct rule lost")
	}
}

func TestProviderHTMLBaseEntitiesAndRawScript(t *testing.T) {
	cfg, err := ParseConfig([]byte("version: 1\ncaptcha:\n  custom:\n    - name: fixture\n      resource_origins: [https://provider.test]\n"))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse("https://provider.test/challenge/start")
	const script = `const literal="https://provider.test/do-not-rewrite.js";`
	body := `<base href="/assets/"><script>` + script + `</script><script src="api.js?x=one&amp;onload=ready"></script><iframe src="frame"></iframe>`
	got := string(cfg.Matcher.RewriteProviderHTML([]byte(body), base))
	if strings.Contains(got, "<base") || !strings.Contains(got, script) {
		t.Fatalf("base/script corruption: %s", got)
	}
	z := html.NewTokenizer(strings.NewReader(got))
	var urls []string
	for z.Next() != html.ErrorToken {
		token := z.Token()
		for _, a := range token.Attr {
			if a.Key == "src" {
				u, _ := url.Parse(a.Val)
				urls = append(urls, u.Query().Get("u"))
			}
		}
	}
	if len(urls) != 2 || urls[0] != "https://provider.test/assets/api.js?x=one&onload=ready" || urls[1] != "https://provider.test/assets/frame" {
		t.Fatalf("nested provider references: %q", urls)
	}
}
