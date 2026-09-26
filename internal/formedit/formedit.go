// Package formedit rewrites individual URL-encoded form or query components
// without normalizing their enclosing parameter list.
package formedit

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrInvalidEncoding means a key or value contains a malformed percent escape.
var ErrInvalidEncoding = errors.New("invalid URL-encoded parameter")

type pair struct {
	rawKey, rawValue string
	key, value       string
	hasEquals        bool
}

// Rewrite applies replace to each decoded key and value, encoding only the
// components whose decoded text changes. A nil replace function is the identity.
// If skipValue returns true for a rewritten key, its original value is retained
// byte-for-byte without being passed to replace.
//
// The input is a raw query or application/x-www-form-urlencoded body, without a
// leading '?'. Only '&' separates pairs. '+' decodes as a space, and percent
// escapes follow url.QueryUnescape semantics. Literal semicolons are preserved
// as component data; unlike url.ParseQuery, Rewrite does not reject them. It
// does not interpret semicolons as another separator.
//
// All percent escapes, including those in opaque values, are validated before
// either callback runs. Empty segments, parameter order, existing or newly
// colliding keys, and untouched escape spellings are preserved. A bare key stays
// bare unless replacement gives its implicit empty value a nonempty value, or
// makes its key empty (in which case '=' retains the otherwise empty parameter).
// Changed components use url.QueryEscape's encoding. On error, Rewrite returns
// an empty string and no partial output.
func Rewrite(input string, replace func(string) string, skipValue func(restoredKey string) bool) (string, error) {
	segments := strings.Split(input, "&")
	pairs := make([]pair, len(segments))
	for i, segment := range segments {
		if segment == "" {
			continue
		}
		rawKey, rawValue, hasEquals := strings.Cut(segment, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrInvalidEncoding, err)
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrInvalidEncoding, err)
		}
		pairs[i] = pair{rawKey: rawKey, rawValue: rawValue, key: key, value: value, hasEquals: hasEquals}
	}

	var out strings.Builder
	out.Grow(len(input))
	for i, p := range pairs {
		if i != 0 {
			out.WriteByte('&')
		}
		if segments[i] == "" {
			continue
		}
		key := p.key
		if replace != nil {
			key = replace(key)
		}
		if key == p.key {
			out.WriteString(p.rawKey)
		} else {
			out.WriteString(url.QueryEscape(key))
		}
		value := p.value
		if (skipValue == nil || !skipValue(key)) && replace != nil {
			value = replace(value)
		}
		if p.hasEquals || value != "" || key == "" {
			out.WriteByte('=')
		}
		if value == p.value {
			out.WriteString(p.rawValue)
		} else {
			out.WriteString(url.QueryEscape(value))
		}
	}
	return out.String(), nil
}
