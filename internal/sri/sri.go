package sri

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"strings"
)

type HashEntry struct {
	Algorithm string
	Digest    []byte
	Options   string
	// DigestValue retains the source spelling for policy coordination. Byte
	// equality determines SRI verification, but callers must not reconstruct
	// the original integrity metadata from a different base64 spelling.
	DigestValue string
}

var algorithmStrength = map[string]int{
	"sha256": 1,
	"sha384": 2,
	"sha512": 3,
}

func ParseIntegrity(attr string) []HashEntry {
	var entries []HashEntry
	for _, token := range strings.FieldsFunc(attr, integrityWhitespace) {
		if entry, ok := parseIntegrityToken(token); ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

func integrityWhitespace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f'
}

func parseIntegrityToken(token string) (HashEntry, bool) {
	// Chromium's integrity-attribute parser recognises these literal,
	// case-sensitive prefixes, including the historical hyphenated aliases.
	// CSP hash-source parsing is separate and must not inherit this rule.
	// https://raw.githubusercontent.com/chromium/chromium/main/third_party/blink/renderer/platform/loader/subresource_integrity.cc
	algo, prefix := "", ""
	for _, candidate := range []struct{ spelling, algorithm string }{
		{"sha256-", "sha256"}, {"sha-256-", "sha256"},
		{"sha384-", "sha384"}, {"sha-384-", "sha384"},
		{"sha512-", "sha512"}, {"sha-512-", "sha512"},
	} {
		if strings.HasPrefix(token, candidate.spelling) {
			algo, prefix = candidate.algorithm, candidate.spelling
			break
		}
	}
	if algo == "" {
		return HashEntry{}, false
	}
	rest := token[len(prefix):]
	var opts string
	if qIdx := strings.IndexByte(rest, '?'); qIdx >= 0 {
		opts = rest[qIdx+1:]
		rest = rest[:qIdx]
	}
	if rest == "" {
		return HashEntry{}, false
	}
	for _, c := range rest {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '-' || c == '_' || c == '=') {
			return HashEntry{}, false
		}
	}
	// Browsers accept the URL-safe alphabet and omitted padding. Do not
	// repair malformed padding: an invalid input must not become valid.
	encoded := strings.NewReplacer("-", "+", "_", "/").Replace(rest)
	encoding := base64.StdEncoding
	if !strings.Contains(encoded, "=") {
		encoding = base64.RawStdEncoding
	}
	digest, err := encoding.DecodeString(encoded)
	if err != nil {
		// Recognised algorithms with base64-shaped but invalid values still
		// participate in strongest-algorithm selection in Chromium. Do not
		// silently discard a broken SHA512 assertion in favour of valid SHA256.
		digest = nil
	}
	return HashEntry{Algorithm: algo, Digest: digest, Options: opts, DigestValue: rest}, true
}

func StrongestAlgorithm(entries []HashEntry) string {
	best := ""
	bestStrength := 0
	for _, e := range entries {
		if s := algorithmStrength[e.Algorithm]; s > bestStrength {
			bestStrength = s
			best = e.Algorithm
		}
	}
	return best
}

func Verify(data []byte, entries []HashEntry) (bool, error) {
	if len(entries) == 0 {
		return false, nil
	}
	strongest := StrongestAlgorithm(entries)
	if strongest == "" {
		return false, nil
	}
	computed := computeDigest(data, strongest)
	if computed == nil {
		return false, nil
	}
	for _, e := range entries {
		if e.Algorithm != strongest {
			continue
		}
		if bytes.Equal(e.Digest, computed) {
			return true, nil
		}
	}
	return false, nil
}

func ComputeIntegrity(data []byte, algorithm string) string {
	digest := computeDigest(data, algorithm)
	if digest == nil {
		return ""
	}
	return algorithm + "-" + base64.StdEncoding.EncodeToString(digest)
}

func computeDigest(data []byte, algorithm string) []byte {
	var h hash.Hash
	switch algorithm {
	case "sha256":
		h = sha256.New()
	case "sha384":
		h = sha512.New384()
	case "sha512":
		h = sha512.New()
	default:
		return nil
	}
	h.Write(data)
	return h.Sum(nil)
}
