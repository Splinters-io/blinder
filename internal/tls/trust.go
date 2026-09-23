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

// CheckTrust checks the platform verifier for this endpoint. Individual clients
// may use other stores and must still be checked separately during UAT.
func (m *Material) CheckTrust() error {
	_, err := m.Certificate.Leaf.Verify(x509.VerifyOptions{DNSName: m.Host})
	return err
}

func UserTrustSupported() bool { return runtime.GOOS == "darwin" }

// InstallUserTrust is called only after an explicit CLI request and confirmation.
// It trusts a single server certificate for SSL and the selected endpoint in the
// current user's Keychain. It never installs a signing CA or uses sudo.
func (m *Material) InstallUserTrust(ctx context.Context, output io.Writer) error {
	if !UserTrustSupported() {
		return fmt.Errorf("automatic user trust is available on macOS; configure your client's certificate store or CA-file option with %s", m.PublicPath)
	}
	if m.PublicPath == "" {
		return fmt.Errorf("trust installation requires a persistent certificate")
	}
	if m.Certificate.Leaf.IsCA {
		return fmt.Errorf("refusing to install a signing CA")
	}
	userDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	// Use a private snapshot so another preflight cannot replace the certificate
	// between the displayed fingerprint/confirmation and the platform command.
	f, err := os.CreateTemp("", "blinder-trust-*.pem")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(publicPEM(m.Certificate)); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	args := userTrustArgs(filepath.Join(userDir, "Library", "Keychains", "login.keychain-db"), m.Host, f.Name())
	cmd := exec.CommandContext(ctx, "/usr/bin/security", args...)
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("user Keychain trust was not installed: %w", err)
	}
	return nil
}

func userTrustArgs(keychain, host, cert string) []string {
	return []string{"add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-s", host, "-k", keychain, cert}
}
