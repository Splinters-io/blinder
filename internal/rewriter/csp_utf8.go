package rewriter

import "unicode/utf8"

// cspUTF8 applies the UTF-8 decoder's replacement mode before hashing DOM text.
// Unlike replacing each invalid byte or each invalid run, it consumes a valid
// incomplete prefix as one error and then retries the byte which interrupted
// it. BOM handling and HTML newline/NUL preprocessing belong to the caller.
// https://encoding.spec.whatwg.org/#utf-8-decoder
func cspUTF8(source []byte) []byte {
	if utf8.Valid(source) {
		return source
	}
	out := make([]byte, 0, len(source))
	for i := 0; i < len(source); {
		b := source[i]
		if b <= 0x7f {
			out = append(out, b)
			i++
			continue
		}
		needed := 0
		lower, upper := byte(0x80), byte(0xbf)
		switch {
		case b >= 0xc2 && b <= 0xdf:
			needed = 1
		case b >= 0xe0 && b <= 0xef:
			needed = 2
			if b == 0xe0 {
				lower = 0xa0
			} else if b == 0xed {
				upper = 0x9f
			}
		case b >= 0xf0 && b <= 0xf4:
			needed = 3
			if b == 0xf0 {
				lower = 0x90
			} else if b == 0xf4 {
				upper = 0x8f
			}
		default:
			out = utf8.AppendRune(out, utf8.RuneError)
			i++
			continue
		}
		start := i
		i++
		seen := 0
		for seen < needed && i < len(source) {
			if source[i] < lower || source[i] > upper {
				break
			}
			i++
			seen++
			lower, upper = 0x80, 0xbf
		}
		if seen == needed {
			out = append(out, source[start:i]...)
		} else {
			out = utf8.AppendRune(out, utf8.RuneError)
		}
	}
	return out
}
