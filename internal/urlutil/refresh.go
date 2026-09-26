// Package urlutil contains URL-bearing syntax shared by response headers and
// document rewriting, without depending on either proxy or rewriter packages.
package urlutil

import (
	"net/url"
	"strings"
)

// RewriteRefresh maps an existing URL in a Refresh header or a decoded HTML
// meta refresh value. It preserves the delay, separators, whitespace, quotes
// and any ignored suffix. Delay-only and malformed values are unchanged and do
// not call mapper. The result boolean reports mapper acceptance, not merely a
// syntactic match; a caller may capture a rejected mapping in its callback.
//
// Parsing follows the shared declarative refresh steps, including the accepted
// comma separator and digit/dot delay suffix:
// https://html.spec.whatwg.org/multipage/semantics.html#shared-declarative-refresh-steps
func RewriteRefresh(value string, mapper func(string) (string, bool)) (string, bool) {
	if mapper == nil {
		return value, false
	}
	position := 0
	skipRefreshSpace(value, &position)
	start := position
	for position < len(value) && refreshDigit(value[position]) {
		position++
	}
	if position == start && (position == len(value) || value[position] != '.') {
		return value, false
	}
	for position < len(value) && (refreshDigit(value[position]) || value[position] == '.') {
		position++
	}
	if position == len(value) {
		return value, false
	}
	if value[position] != ';' && value[position] != ',' && !refreshSpace(value[position]) {
		return value, false
	}
	skipRefreshSpace(value, &position)
	if position < len(value) && (value[position] == ';' || value[position] == ',') {
		position++
	}
	skipRefreshSpace(value, &position)
	if position == len(value) {
		return value, false
	}
	urlStart, urlEnd := position, len(value)
	// An incomplete URL= prefix is itself a relative URL; the standard
	// falls back to the original URL substring rather than discarding it.
	checkQuotes := value[position] != 'U' && value[position] != 'u'
	if len(value)-position >= 3 && strings.EqualFold(value[position:position+3], "url") {
		after := position + 3
		skipRefreshSpace(value, &after)
		if after < len(value) && value[after] == '=' {
			position = after + 1
			skipRefreshSpace(value, &position)
			urlStart = position
			checkQuotes = true
		}
	}
	if checkQuotes && position < len(value) && (value[position] == '\'' || value[position] == '"') {
		quote := value[position]
		urlStart = position + 1
		if end := strings.IndexByte(value[urlStart:], quote); end >= 0 {
			urlEnd = urlStart + end
		}
	}
	// URL parsing ignores surrounding ASCII whitespace. Keep that formatting
	// outside the replacement, so a mapping cannot change the refresh delay.
	for urlStart < urlEnd && refreshSpace(value[urlStart]) {
		urlStart++
	}
	for urlEnd > urlStart && refreshSpace(value[urlEnd-1]) {
		urlEnd--
	}
	raw := value[urlStart:urlEnd]
	if _, err := url.Parse(raw); err != nil {
		return value, false
	}
	mapped, ok := mapper(raw)
	if !ok {
		return value, false
	}
	return value[:urlStart] + mapped + value[urlEnd:], true
}

func skipRefreshSpace(value string, position *int) {
	for *position < len(value) && refreshSpace(value[*position]) {
		*position++
	}
}

func refreshDigit(c byte) bool { return c >= '0' && c <= '9' }

func refreshSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }
