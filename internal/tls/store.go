package tls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const persistentLifetime = 90 * 24 * time.Hour
const renewBefore = 7 * 24 * time.Hour

// Material is prepared once, then used for both preflight and the listener.
type Material struct {
	Certificate tls.Certificate
	PublicPath  string
	Fingerprint string
	Host        string
	Action      string
}

func EndpointHost(listen string) (string, error) {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return "", err
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return host, nil
}

func certificateNames(alias, host string) []string {
	var names []string
	seen := make(map[string]bool)
	for _, name := range []string{"localhost", "127.0.0.1", "::1", alias, host} {
		if name != "" && !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}
	return names
}

func DefaultDir(alias, listen string) (string, error) {
	host, err := EndpointHost(listen)
	if err != nil {
		return "", err
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate certificate directory: use --cert-dir: %w", err)
	}
	key := sha256.Sum256([]byte(alias + "\x00" + host))
	return filepath.Join(base, "blinder", "certs", hex.EncodeToString(key[:12])), nil
}

// Prepare creates a private store, reuses a valid identity, and renews it near
// expiry. A corrupt identity fails explicitly; it is never silently discarded.
// The combined PEM is the canonical atomic record; the public PEM is repairable.
func Prepare(dir, alias, listen string) (*Material, error) {
	return prepare(dir, alias, listen, time.Now())
}

func prepare(dir, alias, listen string, now time.Time) (*Material, error) {
	host, err := EndpointHost(listen)
	if err != nil {
		return nil, err
	}
	if dir == "" {
		cert, _, err := generate(alias, host, now, 24*time.Hour)
		if err != nil {
			return nil, err
		}
		return material(cert, "", host, "ephemeral"), nil
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create certificate directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("certificate directory must be a real directory: %s", dir)
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("certificate directory must be private (mode 0700): %s", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	unlock, err := lockStore(root)
	if err != nil {
		return nil, err
	}
	defer unlock()
	data, err := readRegular(root, "identity.pem")
	var cert tls.Certificate
	action := "reused"
	if errors.Is(err, os.ErrNotExist) {
		action = "created"
	} else if err != nil {
		return nil, err
	} else {
		info, err := root.Stat("identity.pem")
		if err != nil {
			return nil, err
		}
		if info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("identity.pem contains a private key and must have mode 0600")
		}
		cert, err = tls.X509KeyPair(data, data)
		if err != nil {
			return nil, fmt.Errorf("invalid identity.pem; restore a valid backup or choose a new --cert-dir: %w", err)
		}
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
		leaf := cert.Leaf
		if leaf.IsCA || leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil {
			return nil, errors.New("identity.pem must contain a self-signed server certificate, not a CA")
		}
		if now.Before(leaf.NotBefore) {
			return nil, errors.New("stored certificate is not valid yet; check the system clock")
		}
		if !now.Add(renewBefore).Before(leaf.NotAfter) {
			action = "renewed"
		}
		for _, name := range certificateNames(alias, host) {
			if leaf.VerifyHostname(name) != nil {
				action = "reissued for endpoint names"
			}
		}
	}
	if action != "reused" {
		if len(cert.Certificate) > 0 {
			old := material(cert, "", host, "")
			// Retain the previous public certificate for removal of old trust.
			if err := atomicWrite(root, "previous-"+old.Fingerprint+".pem", publicPEM(cert)); err != nil {
				return nil, err
			}
		}
		cert, data, err = generate(alias, host, now, persistentLifetime)
		if err != nil {
			return nil, err
		}
		if err := atomicWrite(root, "identity.pem", data); err != nil {
			return nil, err
		}
	}
	public := publicPEM(cert)
	existing, err := readRegular(root, "certificate.pem")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if !bytes.Equal(existing, public) {
		if err := atomicWrite(root, "certificate.pem", public); err != nil {
			return nil, err
		}
	}
	return material(cert, filepath.Join(dir, "certificate.pem"), host, action), nil
}

func material(cert tls.Certificate, path, host, action string) *Material {
	sum := sha256.Sum256(cert.Certificate[0])
	return &Material{cert, path, hex.EncodeToString(sum[:]), host, action}
}

func publicPEM(cert tls.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
}

func readRegular(root *os.Root, name string) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("certificate store entry must be a regular file: %s", name)
	}
	return root.ReadFile(name)
}

func atomicWrite(root *os.Root, name string, data []byte) error {
	if info, err := root.Lstat(name); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to replace non-regular certificate entry: %s", name)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// The store lock protects this temporary name across processes. Open with
	// EXCL so a leftover file or symlink cannot be followed or truncated.
	temp := ".writing-" + strings.TrimSuffix(name, ".pem")
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create certificate temporary file (remove stale %s only after checking no setup is running): %w", temp, err)
	}
	defer root.Remove(temp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return root.Rename(temp, name)
}
