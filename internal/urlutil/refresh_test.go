package urlutil

import "testing"

func TestRewriteRefreshPreservesBrowserAcceptedSyntax(t *testing.T) {
	for _, tc := range []struct{ name, value, raw, want string }{
		{"semicolon", "0;url=https://upstream.test/a?x=1&x=2", "https://upstream.test/a?x=1&x=2", "0;url=LOCAL"},
		{"comma", "5, URL = https://upstream.test/a", "https://upstream.test/a", "5, URL = LOCAL"},
		{"whitespace-separator", "10 \t url=/next", "/next", "10 \t url=LOCAL"},
		{"bare-url", "0; /next", "/next", "0; LOCAL"},
		{"double-quotes", "  2.9 ; uRl = \"https://upstream.test/a\"  ", "https://upstream.test/a", "  2.9 ; uRl = \"LOCAL\"  "},
		{"single-quotes-ignored-suffix", "1,'/next' ignored suffix", "/next", "1,'LOCAL' ignored suffix"},
		{"unclosed-quotes", "0; url='/next", "/next", "0; url='LOCAL"},
		{"relative-u-prefix", "0;update", "update", "0;LOCAL"},
		{"relative-url-prefix", "0;url-next", "url-next", "0;LOCAL"},
		{"url-without-equals", "0;URL /next", "URL /next", "0;LOCAL"},
		{"multiple-delay-dots", "1.2.3;url=/next", "/next", "1.2.3;url=LOCAL"},
		{"leading-dot-delay", ".1,/next", "/next", ".1,LOCAL"},
		{"bare-dot-delay", ".;/next", "/next", ".;LOCAL"},
		{"quoted-surrounding-spaces", "0;url='  /next  '", "/next", "0;url='  LOCAL  '"},
		{"unquoted-trailing-space", "0;url=/next \t", "/next", "0;url=LOCAL \t"},
		{"explicit-empty-url", "0;url=", "", "0;url=LOCAL"},
		{"quoted-empty-url", "0;url=''", "", "0;url='LOCAL'"},
		{"empty-query-and-fragment", "0;url=/next?#", "/next?#", "0;url=LOCAL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got, ok := RewriteRefresh(tc.value, func(raw string) (string, bool) {
				calls++
				if raw != tc.raw {
					t.Errorf("mapped input=%q want %q", raw, tc.raw)
				}
				return "LOCAL", true
			})
			if !ok || calls != 1 || got != tc.want {
				t.Fatalf("got=(%q,%v), calls=%d want %q", got, ok, calls, tc.want)
			}
		})
	}
}

func TestRewriteRefreshDoesNotRepairMalformedOrDelayOnlyInput(t *testing.T) {
	for _, input := range []string{"", "  ", "0", "0;", "0, ", "0 \t", "-1;url=/next", "+1;url=/next", "zero;url=/next", "0url=/next", "0x;url=/next", "\u00a00;url=/next", "0;url=http://[bad", "0;url=/bad%xx"} {
		t.Run(input, func(t *testing.T) {
			got, ok := RewriteRefresh(input, func(string) (string, bool) {
				t.Error("mapper called for malformed or delay-only input")
				return "LOCAL", true
			})
			if ok || got != input {
				t.Fatalf("input=%q repaired to (%q,%v)", input, got, ok)
			}
		})
	}
	const input = "0;url=https://unknown.test/a"
	called := false
	got, ok := RewriteRefresh(input, func(string) (string, bool) { called = true; return "bad replacement", false })
	if !called || ok || got != input {
		t.Fatalf("rejected mapping changed input: (%q,%v), called=%v", got, ok, called)
	}
}
