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
}

var algorithmStrength = map[string]int{
	"sha256": 1,
	"sha384": 2,
	"sha512": 3,
}

func ParseIntegrity(attr string) []HashEntry {
	var entries []HashEntry
	for _, token := range strings.Fields(attr) {
		dashIdx := strings.IndexByte(token, '-')
		if dashIdx < 0 {
			continue
		}
		algo := strings.ToLower(token[:dashIdx])
		if algorithmStrength[algo] == 0 {
			continue
		}
		rest := token[dashIdx+1:]
		var opts string
		if qIdx := strings.IndexByte(rest, '?'); qIdx >= 0 {
			opts = rest[qIdx+1:]
			rest = rest[:qIdx]
		}
		digest, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			continue
		}
		entries = append(entries, HashEntry{
			Algorithm: algo,
			Digest:    digest,
			Options:   opts,
		})
	}
	return entries
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
