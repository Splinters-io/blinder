package tls

import (
	"crypto/x509"
	"testing"
)

func TestGenerateSelfSigned(t *testing.T) {
	cert, err := GenerateSelfSigned("target-001.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate generated")
	}

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	if parsed.Subject.CommonName != "target-001.local" {
		t.Errorf("expected CN target-001.local, got %s", parsed.Subject.CommonName)
	}

	foundAlias := false
	foundLocalhost := false
	for _, name := range parsed.DNSNames {
		if name == "target-001.local" {
			foundAlias = true
		}
		if name == "localhost" {
			foundLocalhost = true
		}
	}
	if !foundAlias {
		t.Error("alias domain not in SAN")
	}
	if !foundLocalhost {
		t.Error("localhost not in SAN")
	}

	foundLoopback := false
	for _, ip := range parsed.IPAddresses {
		if ip.String() == "127.0.0.1" {
			foundLoopback = true
		}
	}
	if !foundLoopback {
		t.Error("127.0.0.1 not in SAN")
	}

	if parsed.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("expected ECDSA, got %v", parsed.PublicKeyAlgorithm)
	}
}
