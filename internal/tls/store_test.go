package tls

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestCACreationAndLeafSigning(t *testing.T) {
	dir := privateStore(t)
	first, err := Prepare(dir, "alias.local", "127.0.0.1:8099")
	if err != nil {
		t.Fatal(err)
	}
	if first.Action != "created" {
		t.Fatalf("expected action 'created', got %s", first.Action)
	}
	if first.Certificate.Leaf.IsCA {
		t.Fatal("leaf certificate must not be a CA")
	}
	if first.CACertificate.Leaf == nil || !first.CACertificate.Leaf.IsCA {
		t.Fatal("CA certificate must be present and be a CA")
	}
	if first.CACertificate.Leaf.MaxPathLen != 0 || !first.CACertificate.Leaf.MaxPathLenZero {
		t.Fatal("CA must have MaxPathLen 0")
	}

	// Verify the leaf is signed by the CA
	roots := x509.NewCertPool()
	roots.AddCert(first.CACertificate.Leaf)
	for _, host := range []string{"localhost", "127.0.0.1", "::1", "alias.local"} {
		if _, err := first.Certificate.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Fatalf("leaf not trusted for %s via CA: %v", host, err)
		}
	}
	if err := first.Certificate.Leaf.VerifyHostname("unrelated.example"); err == nil {
		t.Fatal("leaf unexpectedly covers an unrelated hostname")
	}

	// Verify the leaf chain includes the CA
	if len(first.Certificate.Certificate) != 2 {
		t.Fatalf("expected 2-cert chain (leaf + CA), got %d", len(first.Certificate.Certificate))
	}
}

func TestCAReusedAcrossRestarts(t *testing.T) {
	dir := privateStore(t)
	first, err := Prepare(dir, "alias.local", "127.0.0.1:8099")
	if err != nil {
		t.Fatal(err)
	}
	caIdentity, _ := os.ReadFile(filepath.Join(dir, "ca-identity.pem"))

	// Reuse with different listen port — CA should not change
	reused, err := Prepare(dir, "alias.local", "127.0.0.1:8100")
	if err != nil {
		t.Fatal(err)
	}
	if reused.Action != "reused" {
		t.Fatalf("expected CA reused, got %s", reused.Action)
	}
	if reused.Fingerprint != first.Fingerprint {
		t.Fatal("CA fingerprint changed on restart")
	}
	unchanged, _ := os.ReadFile(filepath.Join(dir, "ca-identity.pem"))
	if !bytes.Equal(caIdentity, unchanged) {
		t.Fatal("CA identity changed on restart")
	}
}

func TestCAReusedWhenExtraAliasesChange(t *testing.T) {
	dir := privateStore(t)
	first, err := Prepare(dir, "alias.local", "127.0.0.1:8099")
	if err != nil {
		t.Fatal(err)
	}

	// Add extra aliases — CA should stay the same, only leaf changes
	withExtra, err := Prepare(dir, "alias.local", "127.0.0.1:8099", "host-abcd.alias.local", "host-ef01.alias.local")
	if err != nil {
		t.Fatal(err)
	}
	if withExtra.Action != "reused" {
		t.Fatalf("expected CA reused when extras change, got %s", withExtra.Action)
	}
	if withExtra.Fingerprint != first.Fingerprint {
		t.Fatal("CA fingerprint changed when extras changed — this should be stable")
	}

	// Verify the new leaf covers the extra aliases
	roots := x509.NewCertPool()
	roots.AddCert(withExtra.CACertificate.Leaf)
	for _, host := range []string{"host-abcd.alias.local", "host-ef01.alias.local"} {
		if _, err := withExtra.Certificate.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Fatalf("leaf not trusted for extra alias %s: %v", host, err)
		}
	}
}

func TestCARenewalNearExpiry(t *testing.T) {
	dir, now := privateStore(t), time.Now()
	old, err := prepare(dir, "alias.local", "127.0.0.1:8099", now)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := prepare(dir, "alias.local", "127.0.0.1:8099", now.Add(84*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Action != "renewed" {
		t.Fatalf("expected CA renewed near expiry, got %s", renewed.Action)
	}
	if renewed.Fingerprint == old.Fingerprint {
		t.Fatal("renewed CA has the same fingerprint")
	}
	archived, err := os.ReadFile(filepath.Join(dir, "previous-ca-"+old.Fingerprint+".pem"))
	if err != nil || !bytes.Equal(archived, publicPEM(old.CACertificate)) {
		t.Fatal("old CA public cert must be preserved for trust removal")
	}
}

func TestCorruptCAIsPreserved(t *testing.T) {
	dir := privateStore(t)
	path := filepath.Join(dir, "ca-identity.pem")
	invalid := []byte("invalid CA: do not silently destroy this")
	if err := os.WriteFile(path, invalid, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(dir, "alias.local", "127.0.0.1:8099"); err == nil {
		t.Fatal("accepted corrupt CA identity")
	}
	actual, _ := os.ReadFile(path)
	if !bytes.Equal(actual, invalid) {
		t.Fatal("corrupt CA identity was overwritten")
	}
}

func TestCAPublicCertificateRepair(t *testing.T) {
	dir := privateStore(t)
	first, err := Prepare(dir, "alias.local", "127.0.0.1:8099")
	if err != nil {
		t.Fatal(err)
	}

	// Remove the public CA cert and verify it's repaired
	os.Remove(first.PublicPath)
	repaired, err := Prepare(dir, "alias.local", "127.0.0.1:8099")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(repaired.PublicPath)
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("repaired public CA cert is invalid")
	}
	if !bytes.Equal(block.Bytes, first.CACertificate.Certificate[0]) {
		t.Fatal("repaired public CA cert doesn't match")
	}
}

func TestStoreRejectsUnsafePathsAndPermissions(t *testing.T) {
	for _, mode := range []string{"directory_permissions", "key_permissions", "ca_symlink", "lock_symlink"} {
		t.Run(mode, func(t *testing.T) {
			dir := privateStore(t)
			if _, err := Prepare(dir, "alias.local", "127.0.0.1:8099"); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "unrelated")
			os.WriteFile(outside, []byte("untouched"), 0600)
			switch mode {
			case "directory_permissions":
				os.Chmod(dir, 0755)
			case "key_permissions":
				os.Chmod(filepath.Join(dir, "ca-identity.pem"), 0644)
			default:
				name := map[string]string{"ca_symlink": "ca-identity.pem", "lock_symlink": ".lock"}[mode]
				os.Remove(filepath.Join(dir, name))
				if err := os.Symlink(outside, filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Prepare(dir, "alias.local", "127.0.0.1:8099"); err == nil {
				t.Fatal("unsafe store accepted")
			}
			data, _ := os.ReadFile(outside)
			if string(data) != "untouched" {
				t.Fatal("unrelated file changed")
			}
		})
	}
}

func TestConcurrentCACreation(t *testing.T) {
	dir := privateStore(t)
	var wg sync.WaitGroup
	results := make(chan string, 8)
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cert, err := Prepare(dir, "alias.local", "127.0.0.1:8099")
			if err != nil {
				t.Error(err)
				return
			}
			results <- cert.Fingerprint
		}()
	}
	wg.Wait()
	close(results)
	var fingerprint string
	for got := range results {
		if fingerprint != "" && got != fingerprint {
			t.Fatal("concurrent startup generated competing CAs")
		}
		fingerprint = got
	}
}

func TestEphemeralModeHasNoCA(t *testing.T) {
	cert, err := Prepare("", "alias.local", "127.0.0.1:8099")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Action != "ephemeral" {
		t.Fatalf("expected ephemeral, got %s", cert.Action)
	}
	if cert.CACertificate.Leaf != nil {
		t.Fatal("ephemeral mode should not have a CA")
	}
	if cert.Certificate.Leaf.IsCA {
		t.Fatal("ephemeral cert should be a self-signed leaf, not a CA")
	}
}

func TestCADirIsStable(t *testing.T) {
	dir1, err := CADir()
	if err != nil {
		t.Fatal(err)
	}
	dir2, err := CADir()
	if err != nil {
		t.Fatal(err)
	}
	if dir1 != dir2 {
		t.Fatal("CADir must return a stable path")
	}
}

func TestUserTrustCommandIsScoped(t *testing.T) {
	// CA trust: no hostname scoping
	caArgs := caTrustArgs("/user/login.keychain-db", "/private/ca.pem")
	for _, arg := range caArgs {
		if arg == "-s" {
			t.Fatal("CA trust must not have hostname scoping")
		}
	}
	// Leaf trust: hostname scoped
	leafArgs := leafTrustArgs("/user/login.keychain-db", "127.0.0.1", "/private/cert.pem")
	foundHost := false
	for i, arg := range leafArgs {
		if arg == "-s" && i+1 < len(leafArgs) && leafArgs[i+1] == "127.0.0.1" {
			foundHost = true
		}
	}
	if !foundHost {
		t.Fatal("leaf trust must be hostname-scoped")
	}
}

func TestCAFilesHaveCorrectPermissions(t *testing.T) {
	dir := privateStore(t)
	if _, err := Prepare(dir, "alias.local", "127.0.0.1:8099"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca-identity.pem", "ca-certificate.pem"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("unsafe permissions on %s: %v", name, err)
		}
	}
}

func privateStore(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "certs")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
