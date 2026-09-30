package tls

import (
	"crypto/x509"
	"testing"
	"time"
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

func TestGenerateSelfSigned_ExtraSANs(t *testing.T) {
	cert, err := GenerateSelfSigned("target-001.local", "host-abcd1234.target-001.local", "host-ef567890.target-001.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	want := map[string]bool{
		"target-001.local":               false,
		"localhost":                       false,
		"host-abcd1234.target-001.local": false,
		"host-ef567890.target-001.local": false,
	}
	for _, name := range parsed.DNSNames {
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("expected %s in SAN DNS names, got: %v", name, parsed.DNSNames)
		}
	}
}

func TestGenerateCA(t *testing.T) {
	now := time.Now()
	ca, _, err := generateCA(now, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ca.Leaf == nil {
		t.Fatal("CA has no parsed leaf")
	}
	if !ca.Leaf.IsCA {
		t.Fatal("CA cert is not marked as CA")
	}
	if ca.Leaf.MaxPathLen != 0 || !ca.Leaf.MaxPathLenZero {
		t.Fatal("CA must have MaxPathLen 0")
	}
	if ca.Leaf.Subject.CommonName != "Blinder Local CA" {
		t.Fatalf("unexpected CA CN: %s", ca.Leaf.Subject.CommonName)
	}
	if ca.Leaf.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("CA must have KeyUsageCertSign")
	}
}

func TestGenerateLeaf(t *testing.T) {
	now := time.Now()
	ca, _, err := generateCA(now, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := generateLeaf(ca, "target-001.local", "127.0.0.1", now, 24*time.Hour, "host-abcd.target-001.local")
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Leaf == nil {
		t.Fatal("leaf has no parsed cert")
	}
	if leaf.Leaf.IsCA {
		t.Fatal("leaf must not be a CA")
	}

	// Chain includes leaf + CA
	if len(leaf.Certificate) != 2 {
		t.Fatalf("expected 2-cert chain, got %d", len(leaf.Certificate))
	}

	// Verify via CA
	roots := x509.NewCertPool()
	roots.AddCert(ca.Leaf)
	for _, host := range []string{"target-001.local", "localhost", "127.0.0.1", "host-abcd.target-001.local"} {
		if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Fatalf("leaf not trusted for %s: %v", host, err)
		}
	}
	if err := leaf.Leaf.VerifyHostname("unrelated.example"); err == nil {
		t.Fatal("leaf covers unrelated hostname")
	}
}
