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
	if strings.Contains(result, "Acme Corp") {
		t.Errorf("identity token should be scrubbed, got: %s", result)
	}
	if !strings.Contains(result, ValueAliasPrefix) {
		t.Errorf("scrubbed token should use reversible alias format, got: %s", result)
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
	if strings.Contains(result, "acmecorp") {
		t.Errorf("token scrub should be case-insensitive, got: %s", result)
	}
	if !strings.Contains(result, ValueAliasPrefix) {
		t.Errorf("scrubbed token should use reversible alias format, got: %s", result)
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
	g.RecordCookieValue(aliased, original, scrubbed, "target.com")

	if scrubbed == original {
		t.Fatal("scrub should have replaced identity token in cookie value")
	}
	if !strings.Contains(scrubbed, ValueAliasPrefix) {
		t.Errorf("identity token should be replaced with reversible alias, got: %s", scrubbed)
	}

	restored := g.RestoreCookieValue(aliased, scrubbed, "target.com")
	if restored != original {
		t.Errorf("RestoreCookieValue should return original %q, got %q", original, restored)
	}
}

func TestGate_CookieValueNoMatchPassesThrough(t *testing.T) {
	g := NewGate(nil, []string{"AcmeCorp"}, "target-001.local")
	aliased := g.AliasCookieNameAndRecord("pref")

	g.RecordCookieValue(aliased, "original-val", "scrubbed-val", "target.com")

	result := g.RestoreCookieValue(aliased, "something-else", "target.com")
	if result != "something-else" {
		t.Errorf("unmatched value should pass through, got: %s", result)
	}
}

func TestGate_CookieValueChildDelegates(t *testing.T) {
	g := NewGate(nil, []string{"AcmeCorp"}, "target-001.local")
	child := g.ForRequest()

	aliased := child.AliasCookieNameAndRecord("sess")
	child.RecordCookieValue(aliased, "tok-AcmeCorp-1", "tok-[REDACTED]-1", "target.com")

	restored := child.RestoreCookieValue(aliased, "tok-[REDACTED]-1", "target.com")
	if restored != "tok-AcmeCorp-1" {
		t.Errorf("child should delegate to parent, got: %s", restored)
	}
}

func TestCookieValueRestoration_MultipleValues(t *testing.T) {
	g := NewGate(nil, []string{"Alice", "Bobby"}, "alias.local")
	aliased := g.AliasCookieNameAndRecord("sid")

	scrubbed1 := g.Scrub("Alice", "cookie:value")
	actual1 := g.RecordCookieValue(aliased, "Alice", scrubbed1, "target.com")

	scrubbed2 := g.Scrub("Bobby", "cookie:value")
	actual2 := g.RecordCookieValue(aliased, "Bobby", scrubbed2, "target.com")

	if actual1 == actual2 {
		t.Fatalf("disambiguated scrubbed values must differ, both are %q", actual1)
	}

	restored1 := g.RestoreCookieValue(aliased, actual1, "target.com")
	if restored1 != "Alice" {
		t.Errorf("first cookie value should be restored, got %q (scrubbed was %q)", restored1, actual1)
	}

	restored2 := g.RestoreCookieValue(aliased, actual2, "target.com")
	if restored2 != "Bobby" {
		t.Errorf("second cookie value should be restored, got %q (scrubbed was %q)", restored2, actual2)
	}
}

func TestCookieValueRestoration_SameValueIdempotent(t *testing.T) {
	g := NewGate(nil, nil, "alias.local")
	aliased := g.AliasCookieNameAndRecord("sid")

	actual1 := g.RecordCookieValue(aliased, "samevalue", "samevalue", "target.com")
	actual2 := g.RecordCookieValue(aliased, "samevalue", "samevalue", "target.com")
	if actual1 != actual2 {
		t.Errorf("same original should return same scrubbed: %q vs %q", actual1, actual2)
	}

	restored := g.RestoreCookieValue(aliased, actual1, "target.com")
	if restored != "samevalue" {
		t.Errorf("should restore, got %q", restored)
	}
}

func TestCookieValueRestoration_LiteralCollisionWithHash(t *testing.T) {
	g := NewGate(nil, []string{"Alice", "Bobby"}, "alias.local")
	aliased := g.AliasCookieNameAndRecord("sid")

	scrubAlice := g.Scrub("Alice", "cookie:value")
	actualAlice := g.RecordCookieValue(aliased, "Alice", scrubAlice, "target.com")

	scrubBobby := g.Scrub("Bobby", "cookie:value")
	actualBobby := g.RecordCookieValue(aliased, "Bobby", scrubBobby, "target.com")

	// Now record a third value whose scrubbed form is crafted to equal one of
	// the existing scrubbed values (simulating the literal collision).
	actualThird := g.RecordCookieValue(aliased, "Charlie", actualBobby, "target.com")

	if actualThird == actualBobby {
		t.Fatalf("literal collision: third value's handle %q equals Bobby's %q", actualThird, actualBobby)
	}
	if actualThird == actualAlice {
		t.Fatalf("literal collision: third value's handle %q equals Alice's %q", actualThird, actualAlice)
	}

	// All three must restore correctly.
	if r := g.RestoreCookieValue(aliased, actualAlice, "target.com"); r != "Alice" {
		t.Errorf("Alice restore failed: got %q", r)
	}
	if r := g.RestoreCookieValue(aliased, actualBobby, "target.com"); r != "Bobby" {
		t.Errorf("Bobby restore failed: got %q", r)
	}
	if r := g.RestoreCookieValue(aliased, actualThird, "target.com"); r != "Charlie" {
		t.Errorf("Charlie restore failed: got %q", r)
	}
}

func TestCookieValueRestoration_CrossOriginIsolation(t *testing.T) {
	g := NewGate(nil, nil, "alias.local")
	aliased := g.AliasCookieNameAndRecord("session")

	// Two different origins set a cookie with the same name but different values.
	actualA := g.RecordCookieValue(aliased, "secret-A", "secret-A", "origin-a.com")
	actualB := g.RecordCookieValue(aliased, "secret-B", "secret-B", "origin-b.com")

	// Values from one origin must not restore against the other.
	if r := g.RestoreCookieValue(aliased, actualA, "origin-a.com"); r != "secret-A" {
		t.Errorf("origin-a restore: got %q, want %q", r, "secret-A")
	}
	if r := g.RestoreCookieValue(aliased, actualB, "origin-b.com"); r != "secret-B" {
		t.Errorf("origin-b restore: got %q, want %q", r, "secret-B")
	}
	// Cross-origin lookup must not find the other origin's mapping.
	if r := g.RestoreCookieValue(aliased, actualA, "origin-b.com"); r != actualA {
		t.Errorf("cross-origin should pass through, got %q", r)
	}
	if r := g.RestoreCookieValue(aliased, actualB, "origin-a.com"); r != actualB {
		t.Errorf("cross-origin should pass through, got %q", r)
	}
}

func TestCookieValueRestoration_SameValueDifferentOrigins(t *testing.T) {
	g := NewGate(nil, nil, "alias.local")
	aliased := g.AliasCookieNameAndRecord("csrf")

	// Both origins set the same cookie value — should still isolate.
	actualA := g.RecordCookieValue(aliased, "shared-token", "shared-token", "origin-a.com")
	actualB := g.RecordCookieValue(aliased, "shared-token", "shared-token", "origin-b.com")

	// Same value recorded under different origins: scrubbed form should be identical
	// since the original is the same, but restoration must work for each origin.
	if actualA != actualB {
		t.Fatalf("same original should produce same scrubbed: %q vs %q", actualA, actualB)
	}
	if r := g.RestoreCookieValue(aliased, actualA, "origin-a.com"); r != "shared-token" {
		t.Errorf("origin-a restore: got %q", r)
	}
	if r := g.RestoreCookieValue(aliased, actualB, "origin-b.com"); r != "shared-token" {
		t.Errorf("origin-b restore: got %q", r)
	}
}

func TestRestoreCookieHeader_OriginScoped(t *testing.T) {
	g := NewGate(nil, []string{"SecretOrg"}, "alias.local")
	aliased := g.AliasCookieNameAndRecord("sid")
	original := "tok-SecretOrg-abc"
	scrubbed := g.Scrub(original, "cookie:value")
	actual := g.RecordCookieValue(aliased, original, scrubbed, "app.example.com")

	header := aliased + "=" + actual
	restored := g.RestoreCookieHeader(header, "app.example.com")
	if !strings.Contains(restored, original) {
		t.Errorf("RestoreCookieHeader should restore value for correct origin, got %q", restored)
	}

	// Wrong origin: value should pass through un-restored (still scrubbed).
	wrong := g.RestoreCookieHeader(header, "other.example.com")
	if strings.Contains(wrong, original) {
		t.Error("RestoreCookieHeader must not restore cookies scoped to a different origin")
	}
	if !strings.Contains(wrong, ValueAliasPrefix) {
		t.Errorf("wrong-origin restoration should retain the scrubbed alias, got %q", wrong)
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

func TestGate_ScrubNoDomains_PreservesFilenames(t *testing.T) {
	g := NewGate([]string{"example.com"}, []string{"Acme"}, "target-001.local")
	for _, tc := range []struct {
		name, input, mustContain string
	}{
		{
			"webp_extension",
			"/uploads/Hero-Image.webp",
			"Hero-Image.webp",
		},
		{
			"png_mixed_case",
			"/uploads/Overview-Card.png",
			"Overview-Card.png",
		},
		{
			"svg_extension",
			"/uploads/Product-Feature.svg",
			"Product-Feature.svg",
		},
		{
			"still_scrubs_identity_tokens",
			"/uploads/Acme-Hero.webp",
			"-Hero.webp",
		},
		{
			"still_scrubs_target_domains",
			"/api/check?host=example.com",
			"target-001.local",
		},
		{
			"still_scrubs_public_ips",
			"/api?server=93.184.216.34",
			"203.0.113.1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := g.ScrubNoDomains(tc.input, "test")
			if !strings.Contains(result, tc.mustContain) {
				t.Errorf("ScrubNoDomains(%q) = %q, want containing %q", tc.input, result, tc.mustContain)
			}
		})
	}
}

func TestGate_ScrubNoDomains_DoesNotMatchFilenameAsDomain(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	input := "/uploads/Savant-Card-BG.webp"
	result := g.ScrubNoDomains(input, "test")
	if result != input {
		t.Errorf("ScrubNoDomains should not touch filename:\n  input:  %s\n  output: %s", input, result)
	}
}

func TestGate_Scrub_DoesMatchFilenameAsDomain(t *testing.T) {
	g := NewGate(nil, nil, "target-001.local")
	input := "/uploads/Savant-Card-BG.webp"
	result := g.Scrub(input, "test")
	if result == input {
		t.Error("Scrub should match filename as domain (domainRe)")
	}
}
