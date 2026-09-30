package tls

import (
	"crypto/x509"
	"testing"

	"github.com/Splinters-io/blinder/internal/endpoint"
)

func TestChallengeWildcardCertificateCoversOnlyOneLevel(t *testing.T) {
	dir := privateStore(t)
	first, err := Prepare(dir, "target.local", "127.0.0.1:8099", endpoint.ChallengeWildcard)
	if err != nil {
		t.Fatal(err)
	}
	leaf := first.Certificate.Leaf
	if leaf.IsCA {
		t.Fatal("leaf certificate must not be a CA")
	}
	roots := x509.NewCertPool()
	roots.AddCert(first.CACertificate.Leaf)
	for _, host := range []string{endpoint.ChallengeExampleHost, "abcdef0123456789abcdef0123456789." + endpoint.ChallengeSuffix} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Fatalf("CA-signed leaf does not cover challenge hostname %s: %v", host, err)
		}
	}
	for _, host := range []string{endpoint.ChallengeSuffix, "nested." + endpoint.ChallengeExampleHost, "other.localhost"} {
		if err := leaf.VerifyHostname(host); err == nil {
			t.Fatalf("challenge wildcard covers unrelated endpoint %s", host)
		}
	}
}

func TestChallengeWildcardCAIsStable(t *testing.T) {
	dir := privateStore(t)
	first, err := Prepare(dir, "target.local", "127.0.0.1:8099")
	if err != nil {
		t.Fatal(err)
	}
	withChallenge, err := Prepare(dir, "target.local", "127.0.0.1:8099", endpoint.ChallengeWildcard)
	if err != nil {
		t.Fatal(err)
	}
	if withChallenge.Fingerprint != first.Fingerprint {
		t.Fatal("adding challenge wildcard should not change the CA")
	}
}
