package rewriter

import (
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func testGate(tokens ...string) *scrub.Gate {
	return scrub.NewGate(nil, tokens, "test.localhost")
}

func TestRewriteJS_RegexLiteralNotMistokenForComment(t *testing.T) {
	gate := testGate("Acme")
	for _, tc := range []struct {
		name, input, mustContain string
	}{
		{
			"escaped_slashes_in_regex",
			`var re=/^\/\//;doStuff()`,
			`doStuff()`,
		},
		{
			"regex_after_assignment",
			`x=/pattern/g;callMe()`,
			`callMe()`,
		},
		{
			"regex_after_return",
			"return /test/i;\nconsole.log(1)",
			"console.log(1)",
		},
		{
			"regex_after_comma",
			`f(a,/x/,b);next()`,
			`next()`,
		},
		{
			"regex_after_open_paren",
			`if(/foo/.test(x))bar()`,
			`bar()`,
		},
		{
			"regex_after_colon",
			`{key:/val/};cont()`,
			`cont()`,
		},
		{
			"regex_after_semicolon",
			`a=1;/test/.exec(b)`,
			`.exec(b)`,
		},
		{
			"regex_with_char_class",
			`var re=/[/]/;after()`,
			`after()`,
		},
		{
			"regex_with_escaped_bracket",
			`var re=/[\]]/;after()`,
			`after()`,
		},
		{
			"jquery_protocol_regex",
			`$t=/^\/\//,Bt={},_t={},zt="*/".concat("*")`,
			`Bt={}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := string(rewriteJS([]byte(tc.input), gate, "/test.js"))
			if !strings.Contains(result, tc.mustContain) {
				t.Errorf("regex literal consumed code:\n  input:  %s\n  output: %s\n  expected to contain: %s", tc.input, result, tc.mustContain)
			}
		})
	}
}

func TestRewriteJS_RealCommentsStillScrubbed(t *testing.T) {
	gate := testGate("Acme")
	for _, tc := range []struct {
		name, input string
	}{
		{
			"line_comment",
			"var x = 1; // Acme Corp\nvar y = 2;",
		},
		{
			"block_comment",
			`var x = 1; /* Acme Corp */ var y = 2;`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := string(rewriteJS([]byte(tc.input), gate, "/test.js"))
			if strings.Contains(result, "Acme") {
				t.Errorf("identity token leaked in comment:\n  input:  %s\n  output: %s", tc.input, result)
			}
		})
	}
}

func TestRewriteJS_StringsScrubbed(t *testing.T) {
	gate := testGate("Acme")
	input := `var name = "Acme Corp";`
	result := string(rewriteJS([]byte(input), gate, "/test.js"))
	if strings.Contains(result, "Acme") {
		t.Errorf("identity token leaked in string: %s", result)
	}
}

func TestRewriteJS_DivisionNotMistakenForRegex(t *testing.T) {
	gate := testGate("Acme")
	input := `var x = a/b/c;`
	result := string(rewriteJS([]byte(input), gate, "/test.js"))
	if result != input {
		t.Errorf("division expression was modified:\n  input:  %s\n  output: %s", input, result)
	}
}

func TestRewriteJS_PostfixOperatorDivision(t *testing.T) {
	gate := testGate("Acme")
	for _, tc := range []struct {
		name, input string
	}{
		{"after_close_paren", `(a+b)/c`},
		{"after_close_bracket", `arr[0]/x`},
		{"after_increment", `i++/x`},
		{"after_decrement", `i--/x`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := string(rewriteJS([]byte(tc.input), gate, "/test.js"))
			if result != tc.input {
				t.Errorf("expression was modified:\n  input:  %s\n  output: %s", tc.input, result)
			}
		})
	}
}

func TestJSSlashStartsRegex(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		pos   int
		want  bool
	}{
		{"after_equals", `x=/`, 2, true},
		{"after_open_paren", `(/`, 1, true},
		{"after_comma", `,/`, 1, true},
		{"after_semicolon", `;/`, 1, true},
		{"after_return", `return /`, 7, true},
		{"after_typeof", `typeof /`, 7, true},
		{"after_close_paren", `)/`, 1, false},
		{"after_close_bracket", `]/`, 1, false},
		{"after_identifier", `foo/`, 3, false},
		{"after_number", `42/`, 2, false},
		{"after_increment", `i++/`, 3, false},
		{"after_decrement", `i--/`, 3, false},
		{"start_of_input", `/`, 0, true},
		{"after_yield", `yield /`, 6, true},
		{"after_delete", `delete /`, 7, true},
		{"not_after_return_suffix", `areturn/`, 7, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := jsSlashStartsRegex(tc.input, tc.pos)
			if got != tc.want {
				t.Errorf("jsSlashStartsRegex(%q, %d) = %v, want %v", tc.input, tc.pos, got, tc.want)
			}
		})
	}
}
