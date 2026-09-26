package scrub

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// aliasToken fits the reserved value grammar into the matched source's byte
// budget when possible. Case-folded matches retain separate inverse mappings
// for their exact source bytes, including Unicode variants of different sizes.
// Literal uses of the grammar are escaped before this function is called.
func (g *Gate) aliasToken(original string) string {
	if g.parent != nil {
		return g.parent.aliasToken(original)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for alias, previous := range g.tokenAliases {
		if previous == original {
			return alias
		}
	}
	width := len(original) - len(ValueAliasPrefix) - 1
	if width < 1 {
		// A reversible reserved marker cannot fit these source values. Keep
		// them unambiguous, allowing response metrics to report the expansion.
		width = 6
	}
	for {
		payload := g.tokenAliasPayload(original, width)
		initial := string(payload)
		for {
			alias := ValueAliasPrefix + string(payload) + "]"
			if _, exists := g.tokenAliases[alias]; !exists {
				g.tokenAliases[alias] = original
				return alias
			}
			incrementAliasPayload(payload)
			if string(payload) == initial {
				break
			}
		}
		// Every spelling at this width already has an inverse. Grow only
		// after exhausting it; never overwrite or ambiguously share a value.
		width++
	}
}

// tokenAliasPayload uses a session-private seed and a keyed stream so even a
// long source has an exact-length payload without repeating public identity
// digests. Hash the source once, keeping runtime linear in its length.
// The caller holds g.mu and uses the root gate.
func (g *Gate) tokenAliasPayload(original string, width int) []byte {
	mac := hmac.New(sha256.New, g.contentKey[:])
	mac.Write([]byte("blinder/value-alias/v1\x00"))
	mac.Write([]byte(original))
	seed := mac.Sum(nil)
	stream := hmac.New(sha256.New, seed)
	payload := make([]byte, width)
	var counter [8]byte
	var digest [sha256.Size]byte
	var encoded [sha256.Size * 2]byte
	for offset, block := 0, uint64(0); offset < width; block++ {
		stream.Reset()
		binary.BigEndian.PutUint64(counter[:], block)
		stream.Write(counter[:])
		hex.Encode(encoded[:], stream.Sum(digest[:0]))
		offset += copy(payload[offset:], encoded[:])
	}
	return payload
}

// Increment modulo 16^len(payload), visiting each fixed-width spelling exactly
// once before returning to the keyed starting point. Tiny namespaces can fill.
func incrementAliasPayload(payload []byte) {
	for i := len(payload) - 1; i >= 0; i-- {
		switch payload[i] {
		case 'f':
			payload[i] = '0'
		case '9':
			payload[i] = 'a'
			return
		default:
			payload[i]++
			return
		}
	}
}
