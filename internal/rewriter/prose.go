package rewriter

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"unicode"

	"github.com/Splinters-io/blinder/internal/scrub"
)

// Rumi, The Mesnevi, Book I, XII; James W. Redhouse translation (1881).
// https://www.gutenberg.org/files/61724/61724-h/61724-h.htm
// Combined with traditional lorem ipsum as a filler vocabulary. Word choices
// depend on a private session content tag, not just the source byte length.
// ASCII keeps byte budgets exact without splitting UTF-8 or creating markup.
const proseText = "Each object born in nature with a lovely mien " +
	"Should always have a mirror set to catch its sheen. " +
	"Lorem ipsum dolor sit amet consectetur adipiscing elit."

var proseWords = strings.Fields(proseText)

// proseForHTMLText fills only an ordinary HTML text token. It keeps literal
// boundary whitespace and the source byte count, including entity spellings.
// Whole words are followed by spaces when the remaining budget is too small.
// This is not a padding pass over the whole document or other media types.
func proseForHTMLText(raw, contentTag string, gate *scrub.Gate) string {
	left, right := proseContentBounds(raw)
	if left == right {
		return raw
	}
	var out strings.Builder
	out.Grow(len(raw))
	out.WriteString(raw[:left])
	out.WriteString(proseForBudget(right-left, contentTag, gate))
	out.WriteString(raw[right:])
	return out.String()
}

func proseForBudget(n int, contentTag string, gate *scrub.Gate) string {
	if n >= 1 && n <= 8 {
		text, _ := gate.ShortTextAlias(contentTag, n)
		return text
	}
	return proseForLength(n, contentTag)
}

func proseContentBounds(raw string) (int, int) {
	content := strings.TrimLeftFunc(raw, unicode.IsSpace)
	left := len(raw) - len(content)
	return left, left + len(strings.TrimRightFunc(content, unicode.IsSpace))
}

func proseForLength(n int, contentTag string) string {
	var out strings.Builder
	out.Grow(n)
	stream := proseStream{seed: sha256.Sum256([]byte("blinder/prose/v1\x00" + contentTag))}
	remaining := n
	for remaining > 0 {
		word := proseWords[int(stream.next())%len(proseWords)]
		if len(word) > remaining {
			if out.Len() == 0 {
				// A short label must remain visible. Its fixed-size alphabet
				// cannot encode a collision-free identity; ContentTag is the
				// separate full-size change signal for that purpose.
				for remaining > 0 {
					out.WriteByte('A' + stream.next()%26)
					remaining--
				}
			}
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

// Expand the keyed tag into deterministic choices without retaining source
// bytes or performing one cryptographic operation per output word.
type proseStream struct {
	seed     [32]byte
	block    [32]byte
	counter  uint64
	position int
}

func (s *proseStream) next() byte {
	if s.position == 0 {
		var input [40]byte
		copy(input[:32], s.seed[:])
		binary.LittleEndian.PutUint64(input[32:], s.counter)
		s.block = sha256.Sum256(input[:])
		s.counter++
	}
	value := s.block[s.position]
	s.position = (s.position + 1) % len(s.block)
	return value
}

// A span covers only generated ASCII prose, excluding boundary whitespace.
// Offsets refer to the completed rewritten document before size fitting.
type proseSpan struct {
	start, end int
	contentTag string
}

// fitProseToBodyLength aims for this response's original decoded byte length.
// It never cuts source markup/data or appends a new padding node. If the output
// cannot shrink enough while keeping every prose span visible, it gets as close
// as possible and the caller's actual-size measurements expose the remainder.
func fitProseToBodyLength(body []byte, spans []proseSpan, target int, gate *scrub.Gate) []byte {
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
			out.WriteString(proseForBudget(sizes[i], span.contentTag, gate))
		}
		previous = span.end
	}
	out.Write(body[previous:])
	return out.Bytes()
}
