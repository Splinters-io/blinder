package rewriter

import (
	"strings"
	"unicode"
)

// These are explicit document semantics, not guesses based on words such as
// "error" in arbitrary page text. The existing redaction still applies.
type diagnosticElement struct {
	tag      string
	preserve bool
}

func inDiagnosticElement(stack []diagnosticElement) bool {
	return len(stack) > 0 && stack[len(stack)-1].preserve
}

func enterDiagnosticElement(stack []diagnosticElement, tag string, attrs []tagAttr, selfClosing bool) []diagnosticElement {
	// A trailing slash does not close these non-void HTML form elements in
	// browsers; their following text can still become a submitted value.
	if selfClosing && tag != "textarea" && tag != "option" {
		return stack
	}
	switch tag {
	case "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr":
		return stack
	}
	preserve := inDiagnosticElement(stack)
	switch tag {
	case "pre", "code", "textarea", "option",
		"button", "label", "legend", "summary",
		"output", "meter", "progress":
		preserve = true
	}
	for _, a := range attrs {
		if (a.key == "role" && strings.EqualFold(strings.TrimSpace(a.val), "alert")) ||
			(a.key == "aria-live" && strings.EqualFold(strings.TrimSpace(a.val), "assertive")) {
			preserve = true
		}
	}
	return append(stack, diagnosticElement{tag: tag, preserve: preserve})
}

var diagnosticPrefixes = []string{
	"SQLSTATE[",
	"ERROR:",
	"ORA-",
	"PLS-",
	"SP2-",
	"MySql",
	"Traceback ",
	"at line ",
	"at character ",
	"near \"",
	"Caused by:",
	"Exception in ",
	"panic:",
	"goroutine ",
	"java.lang.",
	"System.Exception",
	"TypeError:",
	"ReferenceError:",
	"SyntaxError:",
	"Fatal error:",
	"Warning:",
	"Parse error:",
	"Access denied",
	"Permission denied",
	"Forbidden",
	"Unauthorized",
	"403 ",
	"401 ",
	"500 ",
	"502 ",
	"503 ",
}

var diagnosticSubstrings = []string{
	"stack trace",
	"syntax error",
	"unexpected token",
	"undefined variable",
	"null pointer",
	"segmentation fault",
	"column does not exist",
	"table or view not found",
	"no such file",
	"failed to",
	"could not",
	"not found",
	"you do not have permission",
	"session expired",
	"token expired",
	"invalid token",
}

// textHasDiagnosticSignal detects error messages, stack traces, SQL
// diagnostics, reflected markup and other application evidence that must
// survive masking even inside an ordinary HTML element on a 200 page.
func textHasDiagnosticSignal(text string) bool {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return false
	}
	upper := strings.ToUpper(trimmed)
	for _, p := range diagnosticPrefixes {
		if strings.HasPrefix(upper, strings.ToUpper(p)) {
			return true
		}
	}
	lower := strings.ToLower(trimmed)
	for _, s := range diagnosticSubstrings {
		if strings.Contains(lower, s) {
			return true
		}
	}
	// Reflected HTML/script fragments: text containing unescaped angle
	// brackets is likely reflected input, not ordinary prose.
	if strings.ContainsAny(trimmed, "<>") {
		return true
	}
	// Code-like: high density of non-alphabetic characters relative to
	// total length suggests structured/diagnostic output rather than prose.
	if len(trimmed) >= 8 {
		nonAlpha := 0
		for _, r := range trimmed {
			if !unicode.IsLetter(r) && !unicode.IsSpace(r) {
				nonAlpha++
			}
		}
		if float64(nonAlpha)/float64(len(trimmed)) > 0.35 {
			return true
		}
	}
	return false
}
