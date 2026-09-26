package rewriter

import "strings"

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
	// Textarea contents and option labels without a value attribute can be
	// submitted as form values. They must not become decorative filler.
	preserve := inDiagnosticElement(stack) || tag == "pre" || tag == "code" || tag == "textarea" || tag == "option"
	for _, a := range attrs {
		if (a.key == "role" && strings.EqualFold(strings.TrimSpace(a.val), "alert")) ||
			(a.key == "aria-live" && strings.EqualFold(strings.TrimSpace(a.val), "assertive")) {
			preserve = true
		}
	}
	return append(stack, diagnosticElement{tag: tag, preserve: preserve})
}
