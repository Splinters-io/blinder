package rewriter

import (
	"errors"

	"github.com/Splinters-io/blinder/internal/jsonedit"
	"github.com/Splinters-io/blinder/internal/scrub"
)

func scrubJSON(body []byte, gate *scrub.Gate, context string) []byte {
	out, err := jsonedit.Rewrite(body, func(value string) string {
		return gate.Scrub(value, context)
	}, nil)
	if errors.Is(err, jsonedit.ErrInvalidJSON) {
		// Keep broken grammar and diagnostic text observable, while decoding
		// supported string escapes before applying the same configured redaction.
		out, err = jsonedit.RewriteDiagnostic(body, func(value string) string {
			return gate.Scrub(value, context)
		})
		// Unusual configured tokens can span the malformed fragment boundaries
		// (for example, a literal quote in a product name). Do not expose such a
		// token or run a second replacement pass over newly emitted aliases.
		if err == nil && gate.ResidualLeakCount(string(out)) != 0 {
			return []byte("null")
		}
	}
	if err != nil {
		// Ambiguous escapes and newly colliding keys retain the safe placeholder.
		return []byte("null")
	}
	return out
}
