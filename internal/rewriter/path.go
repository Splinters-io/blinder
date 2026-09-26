package rewriter

import (
	"net/url"
	"strings"

	"github.com/Splinters-io/blinder/internal/scrub"
)

// RestoreURLPath restores issued mappings in decoded path segments without
// changing the URL's origin or query. Working on escaped segments keeps '%2F'
// as segment data, including slashes introduced by a restored value. Unchanged
// segments retain their original escapes; only changed segments are encoded.
func RestoreURLPath(u *url.URL, gate *scrub.Gate) {
	escapedPath := u.EscapedPath()
	segments := strings.Split(escapedPath, "/")
	changed := false
	for i, raw := range segments {
		decoded, err := url.PathUnescape(raw)
		if err != nil {
			continue
		}
		if restored := gate.RestoreBody(decoded); restored != decoded {
			segments[i] = url.PathEscape(restored)
			changed = true
		}
	}
	if changed {
		raw := strings.Join(segments, "/")
		if decoded, err := url.PathUnescape(raw); err == nil {
			u.Path, u.RawPath = decoded, raw
		}
	}
}
