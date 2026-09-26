// Package jsonedit rewrites JSON strings without reserializing their enclosing
// document. All bytes outside changed string tokens are preserved.
package jsonedit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

var (
	// ErrInvalidJSON means the input is not a single complete JSON document.
	ErrInvalidJSON = errors.New("invalid JSON document")
	// ErrKeyCollision means distinct original keys would become the same key.
	ErrKeyCollision = errors.New("JSON key rewrite collision")
)

type edit struct {
	start, end int
	value      []byte
}

type editor struct {
	input     []byte
	decoder   *json.Decoder
	replace   func(string) string
	skipValue func(string) bool
	edits     []edit
}

// Rewrite applies replace to decoded JSON object keys and string values. A nil
// replace function leaves strings unchanged. Only changed string tokens are
// encoded again; whitespace, number spellings, ordering, existing duplicate
// keys, and the original escapes of unchanged strings survive byte-for-byte.
//
// skipValue, when non-nil, receives each rewritten object key. If it returns
// true, that member's entire value is preserved without invoking either
// callback within the value. The key itself may still be rewritten.
//
// The complete input is validated before either callback runs. New collisions
// between distinct original decoded keys are rejected, but repeated occurrences
// of the same original decoded key are allowed. No partial output is returned
// on error, and input is never modified. An unchanged result may alias input.
func Rewrite(input []byte, replace func(string) string, skipValue func(restoredKey string) bool) ([]byte, error) {
	if !json.Valid(input) {
		return nil, ErrInvalidJSON
	}
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	e := editor{input: input, decoder: dec, replace: replace, skipValue: skipValue}
	if err := e.value(true); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrInvalidJSON
	}
	if len(e.edits) == 0 {
		return input, nil
	}
	var out bytes.Buffer
	out.Grow(len(input))
	previousEnd := 0
	for _, change := range e.edits {
		out.Write(input[previousEnd:change.start])
		out.Write(change.value)
		previousEnd = change.end
	}
	out.Write(input[previousEnd:])
	return out.Bytes(), nil
}

func (e *editor) value(enabled bool) error {
	start := int(e.decoder.InputOffset())
	token, err := e.decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	switch token := token.(type) {
	case string:
		if enabled {
			e.stringToken(token, start)
		}
	case json.Delim:
		switch token {
		case '{':
			return e.object(enabled)
		case '[':
			for e.decoder.More() {
				if err := e.value(enabled); err != nil {
					return err
				}
			}
			return e.close(']')
		default:
			return ErrInvalidJSON
		}
	}
	return nil
}

func (e *editor) object(enabled bool) error {
	var originalsByFinalKey map[string]string
	if enabled {
		originalsByFinalKey = make(map[string]string)
	}
	for e.decoder.More() {
		start := int(e.decoder.InputOffset())
		token, err := e.decoder.Token()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
		}
		original, ok := token.(string)
		if !ok {
			return ErrInvalidJSON
		}
		editValue := enabled
		if enabled {
			final := e.stringToken(original, start)
			if previous, exists := originalsByFinalKey[final]; exists && previous != original {
				return ErrKeyCollision
			}
			originalsByFinalKey[final] = original
			if e.skipValue != nil && e.skipValue(final) {
				editValue = false
			}
		}
		if err := e.value(editValue); err != nil {
			return err
		}
	}
	return e.close('}')
}

func (e *editor) close(expected json.Delim) error {
	token, err := e.decoder.Token()
	if err != nil || token != expected {
		return ErrInvalidJSON
	}
	return nil
}

// InputOffset before a string includes its preceding whitespace and possibly a
// comma or colon. Since the document is valid, its first quote begins the token.
func (e *editor) stringToken(original string, before int) string {
	if e.replace == nil {
		return original
	}
	replacement := e.replace(original)
	// json.Marshal replaces each invalid UTF-8 byte with U+FFFD. Collision
	// checks must use that actual decoded result rather than the invalid input.
	if !utf8.ValidString(replacement) {
		replacement = string([]rune(replacement))
	}
	if replacement == original {
		return original
	}
	end := int(e.decoder.InputOffset())
	start := before + bytes.IndexByte(e.input[before:end], '"')
	encoded, _ := json.Marshal(replacement) // Marshaling a string cannot fail.
	e.edits = append(e.edits, edit{start: start, end: end, value: encoded})
	return replacement
}
