package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sync"

	blindertls "github.com/Splinters-io/blinder/internal/tls"
)

type versionRef struct {
	UpstreamURL string
	BodyVersion string
	Path        string
	Query       string
}

type versionRegistry struct {
	mu      sync.RWMutex
	refs    map[string]versionRef
	order   []string
	maxSize int
	secret  [32]byte
}

func newVersionRegistry(maxSize int) *versionRegistry {
	if maxSize <= 0 {
		maxSize = 1024
	}
	vr := &versionRegistry{
		refs:    make(map[string]versionRef),
		maxSize: maxSize,
	}
	if _, err := rand.Read(vr.secret[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return vr
}

func persistentVersionRegistry(maxSize int, dir string) (*versionRegistry, error) {
	vr := newVersionRegistry(maxSize)
	if dir == "" {
		return vr, nil
	} // Embedded in-memory use; CLI always selects a store.
	key, err := blindertls.SigningKey(dir)
	if err != nil {
		return nil, err
	}
	vr.secret = key
	return vr, nil
}

func (vr *versionRegistry) sign(data string) string {
	mac := hmac.New(sha256.New, vr.secret[:])
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// Token format: "1-{16 hex data}-{32 hex mac}" (51 chars).
// The prefix is only a format version. Ownership requires a valid MAC under the
// persistent local key; an absent in-memory reference then means expired.
func (vr *versionRegistry) Register(upstreamURL, bodyVersion string) string {
	h := sha256.Sum256([]byte(upstreamURL + "\x00" + bodyVersion))
	data := hex.EncodeToString(h[:8])
	sig := vr.sign(data)
	token := "1-" + data + "-" + sig

	parsed, _ := url.Parse(upstreamURL)
	var path, query string
	if parsed != nil {
		path = parsed.Path
		query = parsed.Query().Encode()
	}

	vr.mu.Lock()
	defer vr.mu.Unlock()

	if _, exists := vr.refs[data]; !exists {
		if len(vr.order) >= vr.maxSize {
			evict := vr.order[0]
			vr.order = vr.order[1:]
			delete(vr.refs, evict)
		}
		vr.order = append(vr.order, data)
	}
	vr.refs[data] = versionRef{
		UpstreamURL: upstreamURL,
		BodyVersion: bodyVersion,
		Path:        path,
		Query:       query,
	}
	return token
}

// VerifyAndLookup returns (ref, isProxy, found).
//   - isProxy=false: wrong format or invalid MAC -> application data, pass through
//   - isProxy=true, found=true: valid current token with a registered ref
//   - isProxy=true, found=false: authentic token, ref expired/evicted -> error
func (vr *versionRegistry) VerifyAndLookup(token string) (versionRef, bool, bool) {
	if !looksLikeVersionToken(token) {
		return versionRef{}, false, false
	}

	data := token[2:18]
	sig := token[19:]

	expected := vr.sign(data)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return versionRef{}, false, false
	}

	vr.mu.RLock()
	defer vr.mu.RUnlock()
	ref, ok := vr.refs[data]
	return ref, true, ok
}

// looksLikeVersionToken checks for the structured format "1-{16 hex}-{32 hex}".
// Pure hex application values never match.
func looksLikeVersionToken(token string) bool {
	if len(token) != 51 {
		return false
	}
	if token[0] != '1' || token[1] != '-' || token[18] != '-' {
		return false
	}
	return isLowerHex(token[2:18]) && isLowerHex(token[19:])
}

func isLowerHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (vr *versionRegistry) Lookup(token string) (versionRef, bool) {
	vr.mu.RLock()
	defer vr.mu.RUnlock()
	ref, ok := vr.refs[token]
	return ref, ok
}
