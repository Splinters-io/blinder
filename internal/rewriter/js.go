package rewriter

import (
	"strings"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func rewriteJS(body []byte, gate *scrub.Gate, path string, origins ...*OriginMapper) []byte {
	var mapper *OriginMapper
	if len(origins) > 0 {
		mapper = origins[0]
	}
	s := string(body)
	var out strings.Builder
	out.Grow(len(s))

	i := 0
	for i < len(s) {
		switch {
		case s[i] == '\'' || s[i] == '"':
			i = writeScrubbedJSString(s, i, gate, path, &out, mapper)
		case s[i] == '`':
			i = writeScrubbedJSTemplate(s, i, gate, path, &out, mapper)
		case s[i] == '/' && i+1 < len(s) && s[i+1] == '/':
			start := i
			for i < len(s) && s[i] != '\n' {
				i++
			}
			out.WriteString(gate.Scrub(s[start:i], "body:js:comment:"+path))
		case s[i] == '/' && i+1 < len(s) && s[i+1] == '*':
			start := i
			i += 2
			for i+1 < len(s) {
				if s[i] == '*' && s[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			out.WriteString(gate.Scrub(s[start:i], "body:js:comment:"+path))
		case s[i] == '/' && jsSlashStartsRegex(s, i):
			i = skipJSRegex(s, i, &out)
		default:
			out.WriteByte(s[i])
			i++
		}
	}

	return []byte(out.String())
}

// jsSlashStartsRegex reports whether a '/' at position pos begins a regex
// literal rather than a division operator or comment.  In JavaScript the
// ambiguity is resolved by the preceding token: after an expression-ending
// token (identifier, number, closing bracket/paren, ++, --) the slash is
// division; in every other position it opens a regex.
func jsSlashStartsRegex(s string, pos int) bool {
	j := pos - 1
	for j >= 0 && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\n') {
		j--
	}
	if j < 0 {
		return true
	}
	switch s[j] {
	case ')', ']':
		return false
	case '+':
		return j == 0 || s[j-1] != '+'
	case '-':
		return j == 0 || s[j-1] != '-'
	}
	if jsIsIdentChar(s[j]) || (s[j] >= '0' && s[j] <= '9') {
		end := j + 1
		start := j
		for start > 0 && jsIsIdentChar(s[start-1]) {
			start--
		}
		word := s[start:end]
		switch word {
		case "return", "typeof", "void", "delete", "throw",
			"new", "case", "in", "instanceof", "yield", "await",
			"of", "else", "do":
			return true
		}
		return false
	}
	return true
}

func jsIsIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$'
}

// skipJSRegex outputs a regex literal verbatim starting from the opening
// slash at pos.  It handles escape sequences and character classes so that
// the closing '/' is identified correctly.
func skipJSRegex(s string, pos int, out *strings.Builder) int {
	out.WriteByte('/')
	pos++
	for pos < len(s) {
		if s[pos] == '\\' && pos+1 < len(s) {
			out.WriteByte(s[pos])
			out.WriteByte(s[pos+1])
			pos += 2
			continue
		}
		if s[pos] == '[' {
			out.WriteByte('[')
			pos++
			for pos < len(s) {
				if s[pos] == '\\' && pos+1 < len(s) {
					out.WriteByte(s[pos])
					out.WriteByte(s[pos+1])
					pos += 2
					continue
				}
				if s[pos] == ']' {
					out.WriteByte(']')
					pos++
					break
				}
				out.WriteByte(s[pos])
				pos++
			}
			continue
		}
		if s[pos] == '/' {
			out.WriteByte('/')
			pos++
			for pos < len(s) && jsIsIdentChar(s[pos]) {
				out.WriteByte(s[pos])
				pos++
			}
			return pos
		}
		out.WriteByte(s[pos])
		pos++
	}
	return pos
}

func writeScrubbedJSString(s string, pos int, gate *scrub.Gate, path string, out *strings.Builder, origins *OriginMapper) int {
	quoteStart := pos
	quote := s[pos]
	out.WriteByte(quote)
	pos++
	start := pos
	for pos < len(s) {
		if s[pos] == '\\' && pos+1 < len(s) {
			pos += 2
			continue
		}
		if s[pos] == quote {
			break
		}
		pos++
	}
	value := s[start:pos]
	if pos < len(s) && !strings.ContainsRune(value, '\\') && !jsStringIsConcatenated(s, quoteStart, pos) {
		out.WriteString(scrubResourceURL(value, gate, "body:js:string:"+path, origins))
	} else {
		out.WriteString(gate.Scrub(value, "body:js:string:"+path))
	}
	if pos < len(s) {
		out.WriteByte(quote)
		pos++
	}
	return pos
}

// URL assembly is outside the literal route mapper. Conservatively leave
// obvious concatenations to the existing scrubber instead of guessing the URL.
func jsStringIsConcatenated(s string, start, end int) bool {
	before := strings.TrimRight(s[:start], " \t\r\n")
	after := strings.TrimLeft(s[end+1:], " \t\r\n")
	return strings.HasSuffix(before, "+") || strings.HasPrefix(after, "+")
}

func writeScrubbedJSTemplate(s string, pos int, gate *scrub.Gate, path string, out *strings.Builder, origins *OriginMapper) int {
	quoteStart := pos
	interpolated := false
	out.WriteByte('`')
	pos++
	textStart := pos
	for pos < len(s) {
		if s[pos] == '\\' && pos+1 < len(s) {
			pos += 2
			continue
		}
		if s[pos] == '`' {
			value := s[textStart:pos]
			if !interpolated && !strings.ContainsRune(value, '\\') && !jsStringIsConcatenated(s, quoteStart, pos) {
				out.WriteString(scrubResourceURL(value, gate, "body:js:string:"+path, origins))
			} else {
				out.WriteString(gate.Scrub(value, "body:js:string:"+path))
			}
			out.WriteByte('`')
			pos++
			return pos
		}
		if s[pos] == '$' && pos+1 < len(s) && s[pos+1] == '{' {
			interpolated = true
			out.WriteString(gate.Scrub(s[textStart:pos], "body:js:string:"+path))
			out.WriteString("${")
			pos += 2
			depth := 1
			for pos < len(s) && depth > 0 {
				switch {
				case s[pos] == '\'' || s[pos] == '"':
					pos = writeScrubbedJSString(s, pos, gate, path, out, origins)
				case s[pos] == '`':
					pos = writeScrubbedJSTemplate(s, pos, gate, path, out, origins)
				case s[pos] == '{':
					depth++
					out.WriteByte(s[pos])
					pos++
				case s[pos] == '}':
					depth--
					if depth > 0 {
						out.WriteByte(s[pos])
					}
					pos++
				default:
					out.WriteByte(s[pos])
					pos++
				}
			}
			out.WriteByte('}')
			textStart = pos
			continue
		}
		pos++
	}
	out.WriteString(gate.Scrub(s[textStart:pos], "body:js:string:"+path))
	return pos
}
