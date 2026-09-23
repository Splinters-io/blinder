package scrub

import (
	"strings"
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

func TestGate_ScrubsPublicIPv4(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	result := g.Scrub("Server at 93.184.216.34", "test")
	if result != "Server at 203.0.113.1" {
		t.Errorf("public IPv4 should be replaced, got: %s", result)
	}
}

func TestGate_PreservesPrivateIPv4(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	result := g.Scrub("Local server at 192.168.1.1", "test")
	if result != "Local server at 192.168.1.1" {
		t.Errorf("private IPv4 should be preserved, got: %s", result)
	}
}

func TestGate_PreservesLoopback(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	result := g.Scrub("Connect to 127.0.0.1:8080", "test")
	if result != "Connect to 127.0.0.1:8080" {
		t.Errorf("loopback should be preserved, got: %s", result)
	}
}

func TestGate_ScrubsPublicIPv6(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	result := g.Scrub("Server at 2607:f8b0:4004:800::200e", "test")
	if result == "Server at 2607:f8b0:4004:800::200e" {
		t.Error("public IPv6 should be replaced")
	}
	if !strings.Contains(result, "2001:db8::1") {
		t.Errorf("public IPv6 should be replaced with doc prefix, got: %s", result)
	}
}

func TestGate_PreservesLoopbackIPv6(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	result := g.Scrub("Connect to ::1", "test")
	if result != "Connect to ::1" {
		t.Errorf("IPv6 loopback should be preserved, got: %s", result)
	}
}

func TestGate_ScrubsFullIPv6(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	result := g.Scrub("Addr: 2001:0db8:85a3:0000:0000:8a2e:0370:7334", "test")
	if strings.Contains(result, "2001:0db8:85a3") {
		t.Errorf("full IPv6 should be replaced, got: %s", result)
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

func TestGate_ResidualLeakCountZeroAfterScrub(t *testing.T) {
	g := NewGate([]string{"target.com"}, []string{"AcmeCorp"}, "target-001.local")
	scrubbed := g.Scrub("Visit AcmeCorp at target.com", "test")
	if count := g.ResidualLeakCount(scrubbed); count != 0 {
		t.Errorf("scrubbed output should have 0 residual leaks, got %d (output: %q)", count, scrubbed)
	}
}

func TestGate_ResidualLeakCountDetectsUnscrubbed(t *testing.T) {
	g := NewGate([]string{"target.com"}, []string{"AcmeCorp"}, "target-001.local")
	if count := g.ResidualLeakCount("Visit AcmeCorp at target.com"); count != 2 {
		t.Errorf("expected 2 residual leaks, got %d", count)
	}
}

func TestGate_ResidualLeakCountIgnoresAliases(t *testing.T) {
	g := NewGate([]string{"target.com"}, nil, "target-001.local")
	alias := AliasDomain("target.com", "target-001.local")
	if count := g.ResidualLeakCount("Visit " + alias); count != 0 {
		t.Errorf("alias domain should not be counted as leak, got %d", count)
	}
}

func TestGate_CookieValueRoundTrip(t *testing.T) {
	g := NewGate([]string{"target.com"}, []string{"AcmeCorp"}, "target-001.local")
	aliased := g.AliasCookieNameAndRecord("session_id")

	original := "tok-AcmeCorp-abc123"
	scrubbed := g.Scrub(original, "cookie:value")
	g.RecordCookieValue(aliased, original, scrubbed)

	if scrubbed == original {
		t.Fatal("scrub should have replaced identity token in cookie value")
	}
	if !strings.Contains(scrubbed, "[REDACTED]") {
		t.Errorf("identity token should be replaced with [REDACTED], got: %s", scrubbed)
	}

	restored := g.RestoreCookieValue(aliased, scrubbed)
	if restored != original {
		t.Errorf("RestoreCookieValue should return original %q, got %q", original, restored)
	}
}

func TestGate_CookieValueNoMatchPassesThrough(t *testing.T) {
	g := NewGate(nil, []string{"AcmeCorp"}, "target-001.local")
	aliased := g.AliasCookieNameAndRecord("pref")

	g.RecordCookieValue(aliased, "original-val", "scrubbed-val")

	result := g.RestoreCookieValue(aliased, "something-else")
	if result != "something-else" {
		t.Errorf("unmatched value should pass through, got: %s", result)
	}
}

func TestGate_CookieValueChildDelegates(t *testing.T) {
	g := NewGate(nil, []string{"AcmeCorp"}, "target-001.local")
	child := g.ForRequest()

	aliased := child.AliasCookieNameAndRecord("sess")
	child.RecordCookieValue(aliased, "tok-AcmeCorp-1", "tok-[REDACTED]-1")

	restored := child.RestoreCookieValue(aliased, "tok-[REDACTED]-1")
	if restored != "tok-AcmeCorp-1" {
		t.Errorf("child should delegate to parent, got: %s", restored)
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
