package tls

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// CheckTrust checks the platform verifier for this endpoint.
func (m *Material) CheckTrust() error {
	return m.CheckTrustForHost(m.Host)
}

// CheckTrustForHost checks whether the leaf certificate is trusted for a
// specific hostname. When a CA is available, it is provided as an
// intermediate so the system verifier can chain through it.
func (m *Material) CheckTrustForHost(host string) error {
	opts := x509.VerifyOptions{DNSName: host}
	if m.CACertificate.Leaf != nil {
		opts.Intermediates = x509.NewCertPool()
		opts.Intermediates.AddCert(m.CACertificate.Leaf)
	}
	_, err := m.Certificate.Leaf.Verify(opts)
	return err
}

func UserTrustSupported() bool { return runtime.GOOS == "darwin" }

// InstallUserTrust installs the local CA in the user's login Keychain so all
// leaf certificates signed by it are automatically trusted for SSL. When no
// CA is available (ephemeral mode), it falls back to trusting the self-signed
// leaf for a single endpoint.
func (m *Material) InstallUserTrust(ctx context.Context, output io.Writer) error {
	if !UserTrustSupported() {
		return fmt.Errorf("automatic user trust is available on macOS; configure your client's certificate store or CA-file option with %s", m.PublicPath)
	}
	if m.PublicPath == "" {
		return fmt.Errorf("trust installation requires a persistent certificate")
	}
	userDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "blinder-trust-*.pem")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())

	var certPEM []byte
	if m.CACertificate.Leaf != nil {
		certPEM = publicPEM(m.CACertificate)
	} else {
		certPEM = publicPEM(m.Certificate)
	}
	if _, err := f.Write(certPEM); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	keychain := filepath.Join(userDir, "Library", "Keychains", "login.keychain-db")
	var args []string
	if m.CACertificate.Leaf != nil {
		args = caTrustArgs(keychain, f.Name())
	} else {
		args = leafTrustArgs(keychain, m.Host, f.Name())
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/security", args...)
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("user Keychain trust was not installed: %w", err)
	}
	return nil
}

// caTrustArgs trusts the CA for all SSL without hostname scoping.
func caTrustArgs(keychain, cert string) []string {
	return []string{"add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", keychain, cert}
}

// leafTrustArgs trusts a single leaf certificate for one hostname (legacy fallback).
func leafTrustArgs(keychain, host, cert string) []string {
	return []string{"add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-s", host, "-k", keychain, cert}
}
