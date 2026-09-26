package rewriter

import (
	"bytes"
	"io"
	"strings"

	"golang.org/x/net/html"

	"github.com/Splinters-io/blinder/internal/scrub"
)

// scrubHTMLSourceSpan retains source outside the first/last changed decoded
// bytes. Entity spellings surrounding that span stay byte-for-byte intact.
// Inside the span, HTML escaping prevents identities/replacements from creating
// literal markup. With several replacements, unchanged entities between them
// may be re-encoded; this is not a full source-preserving edit script.
func scrubHTMLSourceSpan(raw []byte, gate *scrub.Gate, context string) []byte {
	source := string(raw)
	decoded := html.UnescapeString(source)
	transformed := gate.Scrub(decoded, context)
	if transformed == decoded {
		return raw
	}
	left := 0
	for left < len(decoded) && left < len(transformed) && decoded[left] == transformed[left] {
		left++
	}
	right, transformedRight := len(decoded), len(transformed)
	for right > left && transformedRight > left && decoded[right-1] == transformed[transformedRight-1] {
		right--
		transformedRight--
	}
	rawLeft, rawRight, decodedLeft, decodedRight := htmlSourceRange(source, left, right)
	value := decoded[decodedLeft:left] + transformed[left:transformedRight] + decoded[right:decodedRight]
	var out strings.Builder
	out.Grow(len(raw) + len(value))
	out.WriteString(source[:rawLeft])
	out.WriteString(html.EscapeString(value))
	out.WriteString(source[rawRight:])
	return []byte(out.String())
}

// htmlSourceRange expands a decoded interval only if a boundary lies inside a
// character reference (including references yielding two Unicode code points).
// It uses the same UnescapeString function as the scrub path and scans each
// source byte once; numeric references may contain arbitrarily many digits.
func htmlSourceRange(source string, left, right int) (rawLeft, rawRight, decodedLeft, decodedRight int) {
	rawLeft, rawRight, decodedLeft, decodedRight = -1, -1, left, right
	for i, decodedOffset := 0, 0; i < len(source); {
		end := i + 1
		if source[i] == '&' {
			for end < len(source) && htmlEntityByte(source[end]) {
				end++
			}
			if end < len(source) && source[end] == ';' {
				end++
			}
		}
		unit := source[i:end]
		value := html.UnescapeString(unit)
		if unit == value {
			if rawLeft < 0 && left >= decodedOffset && left <= decodedOffset+len(value) {
				rawLeft = i + left - decodedOffset
			}
			if rawRight < 0 && right >= decodedOffset && right <= decodedOffset+len(value) {
				rawRight = i + right - decodedOffset
			}
		} else {
			if rawLeft < 0 && left >= decodedOffset && left < decodedOffset+len(value) {
				rawLeft, decodedLeft = i, decodedOffset
			}
			if rawRight < 0 && right > decodedOffset && right <= decodedOffset+len(value) {
				rawRight, decodedRight = end, decodedOffset+len(value)
			}
		}
		decodedOffset += len(value)
		i = end
		if rawLeft >= 0 && rawRight >= 0 {
			break
		}
	}
	if rawLeft < 0 {
		rawLeft = len(source)
	}
	if rawRight < 0 {
		rawRight = len(source)
	}
	return
}

func htmlEntityByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '#'
}

func rewriteHTMLTruncated(raw []byte, gate *scrub.Gate) []byte {
	if len(raw) == 0 {
		return raw
	}
	candidate := scrubHTMLSourceSpan(raw, gate, "html:truncated")
	if gate.ResidualLeakCount(html.UnescapeString(string(candidate))) != 0 || !isSingleHTMLToken(candidate, html.ErrorToken) {
		return nil
	}
	return candidate
}

func isSingleHTMLToken(source []byte, kind html.TokenType) bool {
	z := html.NewTokenizer(bytes.NewReader(source))
	if z.Next() != kind || len(z.Raw()) != len(source) {
		return false
	}
	if kind == html.ErrorToken {
		return z.Err() == io.EOF
	}
	return z.Next() == html.ErrorToken && z.Err() == io.EOF && len(z.Raw()) == 0
}

func sameHTMLCommentEnvelope(before, after []byte) bool {
	start := func(s []byte) string {
		for _, prefix := range []string{"<!--", "<?", "<!", "</"} {
			if bytes.HasPrefix(s, []byte(prefix)) {
				return prefix
			}
		}
		return ""
	}
	end := func(s []byte) string {
		for _, suffix := range []string{"--!>", "-->", ">"} {
			if bytes.HasSuffix(s, []byte(suffix)) {
				return suffix
			}
		}
		return ""
	}
	return start(before) == start(after) && end(before) == end(after)
}
