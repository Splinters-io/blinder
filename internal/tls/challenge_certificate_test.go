package tls

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/Splinters-io/blinder/internal/endpoint"
)

func TestChallengeWildcardCertificateCoversOnlyOneLevelAndIsReused(t *testing.T) {
	dir := privateStore(t)
	first, err := Prepare(dir, "target.local", "127.0.0.1:8099", endpoint.ChallengeWildcard)
	if err != nil {
		t.Fatal(err)
	}
	leaf := first.Certificate.Leaf
	if leaf.IsCA {
		t.Fatal("isolated challenge certificate must remain a leaf certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	for _, host := range []string{endpoint.ChallengeExampleHost, "abcdef0123456789abcdef0123456789." + endpoint.ChallengeSuffix} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Fatalf("explicit leaf trust does not cover challenge hostname %s: %v", host, err)
		}
	}
	for _, host := range []string{endpoint.ChallengeSuffix, "nested." + endpoint.ChallengeExampleHost, "other.localhost"} {
		if err := leaf.VerifyHostname(host); err == nil {
			t.Fatalf("challenge wildcard covers unrelated endpoint %s", host)
		}
	}
	identityPath := filepath.Join(dir, "identity.pem")
	before, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	reused, err := Prepare(dir, "target.local", "127.0.0.1:18099", endpoint.ChallengeWildcard)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if reused.Action != "reused" || reused.Fingerprint != first.Fingerprint || !bytes.Equal(before, after) {
		t.Fatalf("wildcard check reissued a valid identity: %s", reused.Action)
	}
}

func TestChallengeWildcardDoesNotAcceptAnExampleOnlyCertificate(t *testing.T) {
	dir := privateStore(t)
	first, err := Prepare(dir, "target.local", "127.0.0.1:8099", endpoint.ChallengeExampleHost)
	if err != nil {
		t.Fatal(err)
	}
	if certificateCoversName(first.Certificate.Leaf, endpoint.ChallengeWildcard) {
		t.Fatal("one concrete example was mistaken for wildcard coverage")
	}
	updated, err := Prepare(dir, "target.local", "127.0.0.1:8099", endpoint.ChallengeWildcard)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Action != "reissued for endpoint names" || updated.Fingerprint == first.Fingerprint {
		t.Fatalf("missing wildcard SAN did not trigger explicit reissue: %s", updated.Action)
	}
	previous, err := os.ReadFile(filepath.Join(dir, "previous-"+first.Fingerprint+".pem"))
	if err != nil || !bytes.Equal(previous, publicPEM(first.Certificate)) {
		t.Fatal("name expansion did not preserve previous public certificate")
	}
}

func TestChallengeWildcardChangesDefaultStoreSelection(t *testing.T) {
	base, err := DefaultDir("target.local", "127.0.0.1:8099")
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := DefaultDir("target.local", "127.0.0.1:8099", endpoint.ChallengeWildcard)
	if err != nil {
		t.Fatal(err)
	}
	if base == challenge {
		t.Fatal("adding challenge names silently selected the old default store")
	}
}
