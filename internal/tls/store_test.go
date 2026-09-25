package tls

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPersistentIdentityReuseAndPublicRepair(t *testing.T) {
	dir := privateStore(t)
	first, err := Prepare(dir, "alias.local", "127.0.0.1:8099")
	if err != nil {
		t.Fatal(err)
	}
	if first.Action != "created" || first.Certificate.Leaf.IsCA {
		t.Fatalf("unexpected certificate: %s CA=%v", first.Action, first.Certificate.Leaf.IsCA)
	}
	identity, _ := os.ReadFile(filepath.Join(dir, "identity.pem"))
	for _, brokenPublic := range []string{"missing", "invalid public certificate"} {
		if brokenPublic == "missing" {
			os.Remove(first.PublicPath)
		} else {
			os.WriteFile(first.PublicPath, []byte(brokenPublic), 0600)
		}
		reused, err := Prepare(dir, "alias.local", "127.0.0.1:8100")
		if err != nil {
			t.Fatal(err)
		}
		if reused.Action != "reused" || first.Fingerprint != reused.Fingerprint {
			t.Fatal("certificate identity changed on restart/public export repair")
		}
		data, _ := os.ReadFile(reused.PublicPath)
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 || !bytes.Equal(block.Bytes, first.Certificate.Certificate[0]) {
			t.Fatal("public export must contain exactly the server certificate, without its private key")
		}
		unchanged, _ := os.ReadFile(filepath.Join(dir, "identity.pem"))
		if !bytes.Equal(identity, unchanged) {
			t.Fatal("public repair rewrote the canonical private identity")
		}
	}
	for _, name := range []string{"identity.pem", "certificate.pem"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("unsafe permissions: %s %v", name, err)
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(first.Certificate.Leaf)
	for _, host := range []string{"localhost", "127.0.0.1", "::1", "alias.local"} {
		if _, err := first.Certificate.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Fatalf("explicit client trust did not verify %s: %v", host, err)
		}
	}
	if err := first.Certificate.Leaf.VerifyHostname("unrelated.example"); err == nil {
		t.Fatal("certificate unexpectedly covers an unrelated hostname")
	}
}

func TestCertificateRenewalAndNameChange(t *testing.T) {
	for _, tc := range []struct {
		name, alias, action string
		advance             time.Duration
	}{
		{"near_expiry", "alias.local", "renewed", 84 * 24 * time.Hour},
		{"expired", "alias.local", "renewed", 91 * 24 * time.Hour},
		{"changed_name", "other.local", "reissued for endpoint names", time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, now := privateStore(t), time.Now()
			old, err := prepare(dir, "alias.local", "127.0.0.1:8099", now)
			if err != nil {
				t.Fatal(err)
			}
			current, err := prepare(dir, tc.alias, "127.0.0.1:8099", now.Add(tc.advance))
			if err != nil {
				t.Fatal(err)
			}
			if current.Fingerprint == old.Fingerprint || current.Action != tc.action {
				t.Fatalf("renewal/name correction did not replace identity: %s", current.Action)
			}
			archived, err := os.ReadFile(filepath.Join(dir, "previous-"+old.Fingerprint+".pem"))
			if err != nil || !bytes.Equal(archived, publicPEM(old.Certificate)) {
				t.Fatal("old public certificate must remain available for removal of old trust")
			}
		})
	}
}

func TestCorruptIdentityIsPreserved(t *testing.T) {
	dir := privateStore(t)
	path := filepath.Join(dir, "identity.pem")
	invalid := []byte("invalid identity: do not silently destroy this")
	if err := os.WriteFile(path, invalid, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(dir, "alias.local", "127.0.0.1:8099"); err == nil {
		t.Fatal("accepted corrupt identity")
	}
	actual, _ := os.ReadFile(path)
	if !bytes.Equal(actual, invalid) {
		t.Fatal("corrupt identity was overwritten")
	}
}

func TestStoreRejectsUnsafePathsAndPermissions(t *testing.T) {
	for _, mode := range []string{"directory_permissions", "key_permissions", "identity_symlink", "public_symlink", "lock_symlink"} {
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
				os.Chmod(filepath.Join(dir, "identity.pem"), 0644)
			default:
				name := map[string]string{"identity_symlink": "identity.pem", "public_symlink": "certificate.pem", "lock_symlink": ".lock"}[mode]
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

func TestConcurrentCertificateCreation(t *testing.T) {
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
			t.Fatal("concurrent startup generated competing identities")
		}
		fingerprint = got
	}
}

func TestUserTrustCommandIsScoped(t *testing.T) {
	args := userTrustArgs("/user/login.keychain-db", "127.0.0.1", "/private/cert.pem")
	want := []string{"add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-s", "127.0.0.1", "-k", "/user/login.keychain-db", "/private/cert.pem"}
	if !reflect.DeepEqual(args, want) || strings.Contains(strings.Join(args, " "), "sudo") {
		t.Fatalf("unexpected trust scope: %v", args)
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
