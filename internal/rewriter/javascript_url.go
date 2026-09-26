package rewriter

import (
	"strings"
	"unicode/utf8"

	"github.com/Splinters-io/blinder/internal/scrub"
)

// JavaScript navigation URLs carry code, not a domain-shaped string. URL input
// preprocessing removes ASCII tabs/newlines and trims surrounding C0 whitespace.
// Chromium CSP binds the percent-decoded URL including its scheme; execution
// consumes the script after the scheme. Serialization stays separate so encoded
// source spellings cannot acquire a permission that the browser originally denied.
func javascriptURL(value string) (serialized, source string, ok bool) {
	value = string(cspUTF8([]byte(value)))
	value = strings.TrimFunc(value, func(r rune) bool { return r <= 0x20 })
	value = strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(value)
	const prefix = "javascript:"
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return "", "", false
	}
	payload := value[len(prefix):]
	serialized = prefix + serializeJavaScriptURLPayload(payload)
	var decoded strings.Builder
	for i := 0; i < len(payload); i++ {
		if payload[i] == '%' && i+2 < len(payload) {
			hi, lo := unhexURL(payload[i+1]), unhexURL(payload[i+2])
			if hi >= 0 && lo >= 0 {
				decoded.WriteByte(byte(hi<<4 | lo))
				i += 2
				continue
			}
		}
		decoded.WriteByte(payload[i])
	}
	source = decoded.String()
	if !utf8.ValidString(source) {
		// Chromium's UTF8-or-isomorphic decoder falls back for the whole
		// decoded byte sequence, including earlier valid multibyte groups.
		var fallback strings.Builder
		for _, b := range []byte(source) {
			fallback.WriteRune(rune(b))
		}
		source = fallback.String()
	}
	return serialized, source, true
}

func unhexURL(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func javascriptCSPSource(value string) []byte {
	_, source, ok := javascriptURL(value)
	if !ok {
		return nil
	}
	return []byte("javascript:" + source)
}

func appendURLByte(out *strings.Builder, c byte) {
	const hex = "0123456789ABCDEF"
	out.WriteByte('%')
	out.WriteByte(hex[c>>4])
	out.WriteByte(hex[c&15])
}

// The opaque path uses the C0 encode set; query and fragment use their URL
// encode sets. Existing percent escapes are retained for CSP source identity.
func serializeJavaScriptURLPayload(payload string) string {
	var out strings.Builder
	part := byte('p')
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		if c == '#' && part != 'f' {
			part = 'f'
		} else if c == '?' && part == 'p' {
			part = 'q'
		}
		encode := c < 0x20 || c > 0x7e
		if part != 'p' {
			encode = encode || c == ' ' || c == '"' || c == '<' || c == '>' || part == 'f' && c == '`'
		}
		if encode {
			appendURLByte(&out, c)
		} else {
			out.WriteByte(c)
		}
	}
	return out.String()
}

// Percent literals and URL-stripped bytes must survive a second URL parse.
// Encode trailing spaces too, including collision-separating whitespace.
func encodeJavaScriptURL(source string) string {
	var out strings.Builder
	for i := 0; i < len(source); i++ {
		c := source[i]
		if c < 0x20 || c > 0x7e || c == '%' {
			appendURLByte(&out, c)
		} else {
			out.WriteByte(c)
		}
	}
	payload := serializeJavaScriptURLPayload(out.String())
	trimmed := strings.TrimRight(payload, " ")
	return "javascript:" + trimmed + strings.Repeat("%20", len(payload)-len(trimmed))
}

func rewriteJavaScriptURL(value string, gate *scrub.Gate, origins *OriginMapper) (string, bool) {
	_, source, ok := javascriptURL(value)
	if !ok {
		return "", false
	}
	rewritten := string(rewriteJS([]byte(source), gate, "html:javascript-url", origins))
	if rewritten == source {
		return value, true
	}
	return encodeJavaScriptURL(rewritten), true
}
