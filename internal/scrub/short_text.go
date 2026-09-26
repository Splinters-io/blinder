package scrub

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
)

const (
	shortTextAlphabet        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	shortTextMaxReservations = 4096
	shortTextMaxProbes       = 8192
)

type shortTextKey struct {
	tag  [32]byte
	size uint8
}

type shortTextOutput struct {
	value uint64
	size  uint8
}

type shortTextStore struct {
	byTag map[shortTextKey]uint64
	used  map[shortTextOutput]struct{}
}

// ShortTextAlias reserves session-stable, HTML-safe display text with a byte
// budget from 1 through 8. Only private content tags are retained, never source
// text. Reservations are immutable and bounded; they are not request aliases.
// A collision's assignment depends on which source arrived first.
//
// The bool is true only for a uniquely reserved output. Exhausting the alphabet,
// reservation budget, or bounded search returns a deterministic same-size
// fallback and false. No existing reservation is evicted or reassigned. If all
// probed candidates contain a configured identity, spaces retain the budget
// without deliberately emitting one of those rejected candidates.
func (g *Gate) ShortTextAlias(contentTag string, n int) (string, bool) {
	if g.parent != nil {
		text, unique := g.parent.ShortTextAlias(contentTag, n)
		if !unique {
			g.mu.Lock()
			g.shortTextFallbacks++
			g.mu.Unlock()
		}
		return text, unique
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if n < 1 || n > 8 {
		g.shortTextFallbacks++
		return "", false
	}
	seed := sha256.Sum256([]byte("blinder/short-text/v1\x00" + contentTag))
	key := shortTextKey{tag: seed, size: uint8(n)}
	if g.shortText == nil {
		g.shortText = &shortTextStore{
			byTag: make(map[shortTextKey]uint64),
			used:  make(map[shortTextOutput]struct{}),
		}
	}
	if value, ok := g.shortText.byTag[key]; ok {
		return shortTextEncode(value, n), true
	}
	capacity := uint64(1) << (6 * n)
	mask := capacity - 1
	value := binary.LittleEndian.Uint64(seed[:8]) & mask
	// An odd step visits each member of this power-of-two alphabet exactly
	// once before repeating. The work remains bounded even for large budgets.
	step := (binary.LittleEndian.Uint64(seed[8:16]) | 1) & mask
	probes := min(uint64(shortTextMaxProbes), capacity)
	full := len(g.shortText.byTag) >= shortTextMaxReservations
	fallback := ""
	for range probes {
		candidate := shortTextEncode(value, n)
		if g.ResidualLeakCount(candidate) == 0 {
			if fallback == "" {
				fallback = candidate
			}
			if full {
				break
			}
			output := shortTextOutput{value: value, size: uint8(n)}
			if _, exists := g.shortText.used[output]; !exists {
				g.shortText.byTag[key] = value
				g.shortText.used[output] = struct{}{}
				return candidate, true
			}
		}
		value = (value + step) & mask
	}
	if fallback == "" {
		fallback = strings.Repeat(" ", n)
	}
	g.shortTextFallbacks++
	return fallback, false
}

func shortTextEncode(value uint64, n int) string {
	var text [8]byte
	for i := n - 1; i >= 0; i-- {
		text[i] = shortTextAlphabet[value&63]
		value >>= 6
	}
	return string(text[:n])
}

// ShortTextFallbackCount counts display-text generations for which an exclusive
// same-size output could not be reserved. Request gates keep their own count;
// the session gate includes delegated calls. This is not a count of responses
// or a guarantee that longer prose is collision-free.
func (g *Gate) ShortTextFallbackCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.shortTextFallbacks
}
