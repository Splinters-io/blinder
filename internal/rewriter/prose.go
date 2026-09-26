package rewriter

import (
	"bytes"
	"strings"
	"unicode"
)

// Rumi, The Mesnevi, Book I, XII; James W. Redhouse translation (1881).
// https://www.gutenberg.org/files/61724/61724-h/61724-h.htm
// Combined with traditional lorem ipsum as a deterministic filler corpus.
// ASCII keeps byte budgets exact without splitting UTF-8 or creating markup.
const proseText = "Each object born in nature with a lovely mien " +
	"Should always have a mirror set to catch its sheen. " +
	"Lorem ipsum dolor sit amet consectetur adipiscing elit."

var proseWords = strings.Fields(proseText)

// proseForHTMLText fills only an ordinary HTML text token. It keeps literal
// boundary whitespace and the source byte count, including entity spellings.
// Whole words are followed by spaces when the remaining budget is too small.
// This is not a padding pass over the whole document or other media types.
func proseForHTMLText(raw string) string {
	left, right := proseContentBounds(raw)
	if left == right {
		return raw
	}
	var out strings.Builder
	out.Grow(len(raw))
	out.WriteString(raw[:left])
	out.WriteString(proseForLength(right - left))
	out.WriteString(raw[right:])
	return out.String()
}

func proseContentBounds(raw string) (int, int) {
	content := strings.TrimLeftFunc(raw, unicode.IsSpace)
	left := len(raw) - len(content)
	return left, left + len(strings.TrimRightFunc(content, unicode.IsSpace))
}

func proseForLength(n int) string {
	var out strings.Builder
	out.Grow(n)
	remaining := n
	for i := 0; remaining > 0; i++ {
		word := proseWords[i%len(proseWords)]
		if i == 0 && len(word) > remaining {
			word = "I"
		}
		if len(word) > remaining {
			out.WriteString(strings.Repeat(" ", remaining))
			break
		}
		out.WriteString(word)
		remaining -= len(word)
		if remaining > 0 {
			out.WriteByte(' ')
			remaining--
		}
	}
	return out.String()
}

// A span covers only generated ASCII prose, excluding boundary whitespace.
// Offsets refer to the completed rewritten document before size fitting.
type proseSpan struct{ start, end int }

// fitProseToBodyLength aims for this response's original decoded byte length.
// It never cuts source markup/data or appends a new padding node. If the output
// cannot shrink enough while keeping every prose span visible, it gets as close
// as possible and the caller's actual-size measurements expose the remainder.
func fitProseToBodyLength(body []byte, spans []proseSpan, target int) []byte {
	if len(spans) == 0 || len(body) == target {
		return body
	}
	sizes := make([]int, len(spans))
	capacity, largest := 0, 0
	for i, span := range spans {
		sizes[i] = span.end - span.start
		capacity += sizes[i] - 1
		if sizes[i] > sizes[largest] {
			largest = i
		}
	}
	newLength := target
	if target > len(body) {
		// Prefer the largest prose block over inflating a small label.
		sizes[largest] += target - len(body)
	} else {
		remove := min(len(body)-target, capacity)
		if remove == 0 {
			return body
		}
		newLength = len(body) - remove
		remaining := remove
		for i := range sizes {
			// Proportional shrinking avoids spending the entire budget on
			// the first heading. Use int64 for 32-bit platform arithmetic.
			n := int(int64(remove) * int64(sizes[i]-1) / int64(capacity))
			sizes[i] -= n
			remaining -= n
		}
		for i := range sizes {
			n := min(remaining, sizes[i]-1)
			sizes[i] -= n
			remaining -= n
		}
	}
	var out bytes.Buffer
	out.Grow(newLength)
	previous := 0
	for i, span := range spans {
		out.Write(body[previous:span.start])
		if sizes[i] == span.end-span.start {
			out.Write(body[span.start:span.end])
		} else {
			out.WriteString(proseForLength(sizes[i]))
		}
		previous = span.end
	}
	out.Write(body[previous:])
	return out.Bytes()
}
