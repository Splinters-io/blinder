package rewriter

import (
	"strings"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func rewriteJS(body []byte, gate *scrub.Gate, path string) []byte {
	s := string(body)
	var out strings.Builder
	out.Grow(len(s))

	i := 0
	for i < len(s) {
		if s[i] == '\'' || s[i] == '"' {
			i = writeScrubbedJSString(s, i, gate, path, &out)
		} else if s[i] == '`' {
			i = writeScrubbedJSTemplate(s, i, gate, path, &out)
		} else if i+1 < len(s) && s[i] == '/' && s[i+1] == '/' {
			start := i
			for i < len(s) && s[i] != '\n' {
				i++
			}
			out.WriteString(gate.Scrub(s[start:i], "body:js:comment:"+path))
		} else if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
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
		} else {
			out.WriteByte(s[i])
			i++
		}
	}

	return []byte(out.String())
}

func writeScrubbedJSString(s string, pos int, gate *scrub.Gate, path string, out *strings.Builder) int {
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
	out.WriteString(gate.Scrub(s[start:pos], "body:js:string:"+path))
	if pos < len(s) {
		out.WriteByte(quote)
		pos++
	}
	return pos
}

func writeScrubbedJSTemplate(s string, pos int, gate *scrub.Gate, path string, out *strings.Builder) int {
	out.WriteByte('`')
	pos++
	textStart := pos
	for pos < len(s) {
		if s[pos] == '\\' && pos+1 < len(s) {
			pos += 2
			continue
		}
		if s[pos] == '`' {
			out.WriteString(gate.Scrub(s[textStart:pos], "body:js:string:"+path))
			out.WriteByte('`')
			pos++
			return pos
		}
		if s[pos] == '$' && pos+1 < len(s) && s[pos+1] == '{' {
			out.WriteString(gate.Scrub(s[textStart:pos], "body:js:string:"+path))
			out.WriteString("${")
			pos += 2
			depth := 1
			for pos < len(s) && depth > 0 {
				switch {
				case s[pos] == '\'' || s[pos] == '"':
					pos = writeScrubbedJSString(s, pos, gate, path, out)
				case s[pos] == '`':
					pos = writeScrubbedJSTemplate(s, pos, gate, path, out)
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
