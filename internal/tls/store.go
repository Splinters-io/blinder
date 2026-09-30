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

	"github.com/Splinters-io/blinder/internal/endpoint"
)

const persistentLifetime = 90 * 24 * time.Hour
const renewBefore = 7 * 24 * time.Hour

// Material is prepared once, then used for both preflight and the listener.
type Material struct {
	Certificate   tls.Certificate
	CACertificate tls.Certificate
	PublicPath    string
	Fingerprint   string
	Host          string
	Action        string
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

func certificateNames(alias, host string, extra ...string) []string {
	var names []string
	seen := make(map[string]bool)
	base := append([]string{"localhost", "127.0.0.1", "::1", endpoint.OperatorHost, alias, "*." + alias, host}, extra...)
	for _, name := range base {
		if name != "" && !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}
	return names
}

// CADir returns a stable directory for the local CA, independent of alias,
// listen address, or extra-origin configuration. Trust the CA once; all
// future leaf certificates are automatically trusted regardless of SANs.
func CADir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate CA directory: use --cert-dir: %w", err)
	}
	return filepath.Join(base, "blinder", "ca"), nil
}

// DefaultDir returns a per-configuration directory for non-certificate state
// such as the version-signing key.
func DefaultDir(alias, listen string, extraNames ...string) (string, error) {
	host, err := EndpointHost(listen)
	if err != nil {
		return "", err
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate certificate directory: use --cert-dir: %w", err)
	}
	input := alias + "\x00" + host
	for _, name := range extraNames {
		input += "\x00" + name
	}
	key := sha256.Sum256([]byte(input))
	return filepath.Join(base, "blinder", "certs", hex.EncodeToString(key[:12])), nil
}

// Prepare loads or creates a local CA in dir and generates an in-memory leaf
// certificate signed by that CA for the given endpoint names. When dir is
// empty, it generates an ephemeral self-signed leaf with no CA.
func Prepare(dir, alias, listen string, extraNames ...string) (*Material, error) {
	return prepare(dir, alias, listen, time.Now(), extraNames...)
}

func prepare(dir, alias, listen string, now time.Time, extraNames ...string) (*Material, error) {
	host, err := EndpointHost(listen)
	if err != nil {
		return nil, err
	}
	if dir == "" {
		cert, _, err := generate(alias, host, now, 24*time.Hour, extraNames...)
		if err != nil {
			return nil, err
		}
		return ephemeralMaterial(cert, host), nil
	}

	ca, caAction, err := prepareCA(dir, now)
	if err != nil {
		return nil, err
	}

	leaf, err := generateLeaf(ca, alias, host, now, 24*time.Hour, extraNames...)
	if err != nil {
		return nil, err
	}

	caPublicPath := filepath.Join(dir, "ca-certificate.pem")
	return caMaterial(leaf, ca, caPublicPath, host, caAction), nil
}

func prepareCA(dir string, now time.Time) (tls.Certificate, string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("create CA directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return tls.Certificate{}, "", fmt.Errorf("CA directory must be a real directory: %s", dir)
	}
	if info.Mode().Perm()&0077 != 0 {
		return tls.Certificate{}, "", fmt.Errorf("CA directory must be private (mode 0700): %s", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	defer root.Close()
	unlock, err := lockStore(root)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	defer unlock()

	data, err := readRegular(root, "ca-identity.pem")
	var ca tls.Certificate
	action := "reused"
	if errors.Is(err, os.ErrNotExist) {
		action = "created"
	} else if err != nil {
		return tls.Certificate{}, "", err
	} else {
		info, err := root.Stat("ca-identity.pem")
		if err != nil {
			return tls.Certificate{}, "", err
		}
		if info.Mode().Perm()&0077 != 0 {
			return tls.Certificate{}, "", errors.New("ca-identity.pem contains a private key and must have mode 0600")
		}
		ca, err = tls.X509KeyPair(data, data)
		if err != nil {
			return tls.Certificate{}, "", fmt.Errorf("invalid ca-identity.pem; restore a valid backup or choose a new --cert-dir: %w", err)
		}
		ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0])
		if err != nil {
			return tls.Certificate{}, "", err
		}
		if !ca.Leaf.IsCA {
			return tls.Certificate{}, "", errors.New("ca-identity.pem must contain a CA certificate")
		}
		if now.Before(ca.Leaf.NotBefore) {
			return tls.Certificate{}, "", errors.New("stored CA is not valid yet; check the system clock")
		}
		if !now.Add(renewBefore).Before(ca.Leaf.NotAfter) {
			action = "renewed"
		}
	}

	if action != "reused" {
		if len(ca.Certificate) > 0 {
			sum := sha256.Sum256(ca.Certificate[0])
			oldFP := hex.EncodeToString(sum[:])
			if err := atomicWrite(root, "previous-ca-"+oldFP+".pem", publicPEM(ca)); err != nil {
				return tls.Certificate{}, "", err
			}
		}
		var caData []byte
		ca, caData, err = generateCA(now, persistentLifetime)
		if err != nil {
			return tls.Certificate{}, "", err
		}
		if err := atomicWrite(root, "ca-identity.pem", caData); err != nil {
			return tls.Certificate{}, "", err
		}
	}

	public := publicPEM(ca)
	existing, err := readRegular(root, "ca-certificate.pem")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, "", err
	}
	if !bytes.Equal(existing, public) {
		if err := atomicWrite(root, "ca-certificate.pem", public); err != nil {
			return tls.Certificate{}, "", err
		}
	}

	return ca, action, nil
}

// VerifyHostname expects a concrete endpoint. For a planned wildcard, require
// that SAN explicitly and verify an example endpoint: a certificate for one
// example hostname must not be mistaken for coverage of every challenge ID.
func certificateCoversName(leaf *x509.Certificate, name string) bool {
	if strings.HasPrefix(name, "*.") {
		found := false
		for _, san := range leaf.DNSNames {
			if strings.EqualFold(san, name) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
		name = "00000000000000000000000000000000." + strings.TrimPrefix(name, "*.")
	}
	return leaf.VerifyHostname(name) == nil
}

func ephemeralMaterial(cert tls.Certificate, host string) *Material {
	sum := sha256.Sum256(cert.Certificate[0])
	return &Material{
		Certificate: cert,
		PublicPath:  "",
		Fingerprint: hex.EncodeToString(sum[:]),
		Host:        host,
		Action:      "ephemeral",
	}
}

func caMaterial(leaf, ca tls.Certificate, caPublicPath, host, action string) *Material {
	sum := sha256.Sum256(ca.Certificate[0])
	return &Material{
		Certificate:   leaf,
		CACertificate: ca,
		PublicPath:    caPublicPath,
		Fingerprint:   hex.EncodeToString(sum[:]),
		Host:          host,
		Action:        action,
	}
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
