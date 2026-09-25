package tls

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
)

// SigningKey keeps ownership of browser version references across restarts and
// certificate renewal. It is independent of the certificate's private key and is
// never derived from public configuration. The private store lock serializes
// first creation across processes; corruption is an error, not a key rotation.
func SigningKey(dir string) ([32]byte, error) {
	var key [32]byte
	if dir == "" {
		return key, errors.New("signing key directory is required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return key, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return key, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return key, errors.New("signing key directory must be a real private directory (mode 0700)")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return key, err
	}
	defer root.Close()
	unlock, err := lockStore(root)
	if err != nil {
		return key, err
	}
	defer unlock()
	const name = "version-signing.key"
	data, err := readRegular(root, name)
	if errors.Is(err, os.ErrNotExist) {
		if _, err := rand.Read(key[:]); err != nil {
			return key, err
		}
		if err := atomicWrite(root, name, key[:]); err != nil {
			return [32]byte{}, err
		}
		return key, nil
	}
	if err != nil {
		return key, err
	}
	info, err = root.Stat(name)
	if err != nil {
		return key, err
	}
	if info.Mode().Perm()&0077 != 0 || len(data) != len(key) {
		return key, fmt.Errorf("%s must contain a 32-byte key with mode 0600; restore the original key instead of rotating it", name)
	}
	copy(key[:], data)
	return key, nil
}
