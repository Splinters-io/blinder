package scrub

import (
	"testing"
)

func TestGate_ScrubsTargetDomain(t *testing.T) {
	g := NewGate([]string{"example.com"}, nil, "target-001.local")
	result := g.Scrub("Visit https://example.com/login", "test")
	if result == "Visit https://example.com/login" {
		t.Error("target domain should be scrubbed")
	}
	if leaks := g.Leaks(); len(leaks) == 0 {
		t.Error("expected leaks to be recorded")
	}
}

func TestGate_ScrubsIdentityToken(t *testing.T) {
	g := NewGate(nil, []string{"Acme Corp"}, "target-001.local")
	result := g.Scrub("Welcome to Acme Corp portal", "test")
	if result != "Welcome to [REDACTED] portal" {
		t.Errorf("expected identity token scrubbed, got: %s", result)
	}
}

func TestGate_ScrubsEmail(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	result := g.Scrub("Contact admin@evilcorp.com for help", "test")
	if result == "Contact admin@evilcorp.com for help" {
		t.Error("email should be scrubbed")
	}
}

func TestGate_PreservesSafeEmail(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	result := g.Scrub("Load from googleapis.com", "test")
	if result != "Load from googleapis.com" {
		t.Errorf("safe domain should not be scrubbed, got: %s", result)
	}
}

func TestGate_ScrubsPublicIP(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	result := g.Scrub("Server at 93.184.216.34", "test")
	if result != "Server at 203.0.113.1" {
		t.Errorf("public IP should be replaced, got: %s", result)
	}
}

func TestGate_PreservesPrivateIP(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	result := g.Scrub("Local server at 192.168.1.1", "test")
	if result != "Local server at 192.168.1.1" {
		t.Errorf("private IP should be preserved, got: %s", result)
	}
}

func TestGate_PreservesLoopback(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	result := g.Scrub("Connect to 127.0.0.1:8080", "test")
	if result != "Connect to 127.0.0.1:8080" {
		t.Errorf("loopback should be preserved, got: %s", result)
	}
}

func TestGate_CaseInsensitiveDomain(t *testing.T) {
	g := NewGate([]string{"Example.COM"}, nil, "target-001.local")
	result := g.Scrub("Visit EXAMPLE.com now", "test")
	if result == "Visit EXAMPLE.com now" {
		t.Error("domain scrub should be case-insensitive")
	}
}

func TestGate_CaseInsensitiveToken(t *testing.T) {
	g := NewGate(nil, []string{"AcmeCorp"}, "target-001.local")
	result := g.Scrub("Welcome to acmecorp", "test")
	if result != "Welcome to [REDACTED]" {
		t.Errorf("token scrub should be case-insensitive, got: %s", result)
	}
}

func TestAliasDomain_Deterministic(t *testing.T) {
	a1 := AliasDomain("example.com", "target-001.local")
	a2 := AliasDomain("example.com", "target-001.local")
	if a1 != a2 {
		t.Errorf("alias should be deterministic: %s != %s", a1, a2)
	}
}

func TestAliasDomain_DifferentInputs(t *testing.T) {
	a1 := AliasDomain("example.com", "target-001.local")
	a2 := AliasDomain("different.com", "target-001.local")
	if a1 == a2 {
		t.Error("different domains should produce different aliases")
	}
}

func TestIsSafeDomain(t *testing.T) {
	tests := []struct {
		domain string
		safe   bool
	}{
		{"googleapis.com", true},
		{"fonts.googleapis.com", true},
		{"cloudflare.com", true},
		{"w3.org", true},
		{"something.local", true},
		{"test.localhost", true},
		{"foo.test", true},
		{"foo.example.com", true},
		{"evilcorp.com", false},
		{"not-safe.io", false},
	}
	for _, tt := range tests {
		if got := IsSafeDomain(tt.domain); got != tt.safe {
			t.Errorf("IsSafeDomain(%q) = %v, want %v", tt.domain, got, tt.safe)
		}
	}
}
