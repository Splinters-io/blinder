package jsonedit

import (
	"bytes"
	"encoding/json"
)

// RewriteDiagnostic preserves malformed JSON grammar while replacing text in
// complete strings, a truncated final string, and unquoted diagnostic text.
// It is intended only after Rewrite has rejected the document's grammar.
// String escapes must still be unambiguous JSON escapes; unknown escapes,
// incomplete escape sequences and backslashes outside strings return an error.
// Validation finishes before replace runs. Two passes avoid retaining a list
// proportional to the number of fragments in a large malformed response.
func RewriteDiagnostic(input []byte, replace func(string) string) ([]byte, error) {
	if err := walkDiagnostic(input, nil); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.Grow(len(input))
	err := walkDiagnostic(input, func(raw, encoded []byte, quoted, closed bool) {
		var original string
		if quoted {
			original = diagnosticString(encoded)
		} else {
			original = string(raw)
		}
		value := original
		if replace != nil {
			value = replace(original)
		}
		if value == original {
			out.Write(raw)
		} else if quoted {
			rewritten, _ := json.Marshal(value)
			if !closed {
				rewritten = rewritten[:len(rewritten)-1]
			}
			out.Write(rewritten)
		} else {
			out.WriteString(value)
		}
	})
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func diagnosticString(encoded []byte) string {
	// Syntax was validated in the first pass. Keep the address passed to the
	// decoder out of the hot path for empty, tiny-fragment input.
	if len(encoded) == 2 {
		return ""
	}
	var value string
	_ = json.Unmarshal(encoded, &value)
	return value
}

func walkDiagnostic(input []byte, visit func(raw, encoded []byte, quoted, closed bool)) error {
	for start := 0; start < len(input); {
		if input[start] != '"' {
			end := start
			for end < len(input) && input[end] != '"' {
				if input[end] == '\\' {
					return ErrInvalidJSON
				}
				end++
			}
			if visit != nil {
				visit(input[start:end], nil, false, false)
			}
			start = end
			continue
		}
		end, closed := start+1, false
		for end < len(input) {
			if input[end] == '\\' {
				end += 2
				continue
			}
			if input[end] == '"' {
				end++
				closed = true
				break
			}
			end++
		}
		if end > len(input) {
			return ErrInvalidJSON
		}
		raw := input[start:end]
		encoded := raw
		if !closed {
			encoded = append(bytes.Clone(raw), '"')
		}
		if !json.Valid(encoded) {
			return ErrInvalidJSON
		}
		if visit != nil {
			visit(raw, encoded, true, closed)
		}
		start = end
	}
	return nil
}
