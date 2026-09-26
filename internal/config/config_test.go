package config

import (
	"testing"
)

func TestNew_ValidHTTPS(t *testing.T) {
	cfg, err := New(
		"https://example.com",
		"127.0.0.1:8099",
		"target-001.local",
		[]string{"ExampleOrg"},
		true, false, false,
		"", "", 0, "", "", 0, 0,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TargetURL.Host != "example.com" {
		t.Errorf("expected host example.com, got %s", cfg.TargetURL.Host)
	}
	if cfg.ListenAddr != "127.0.0.1:8099" {
		t.Errorf("expected listen 127.0.0.1:8099, got %s", cfg.ListenAddr)
	}
}

func TestNew_NoTarget(t *testing.T) {
	_, err := New("", "", "", nil, true, false, false, "", "", 0, "", "", 0, 0)
	if err != ErrNoTarget {
		t.Errorf("expected ErrNoTarget, got %v", err)
	}
}

func TestNew_BadScheme(t *testing.T) {
	_, err := New("file:///etc/passwd", "", "", nil, true, false, false, "", "", 0, "", "", 0, 0)
	if err != ErrBadScheme {
		t.Errorf("expected ErrBadScheme, got %v", err)
	}
}

func TestNew_OnionWithoutTor(t *testing.T) {
	_, err := New(
		"http://facebookwkhpilnemxj7asber7.onion",
		"", "", nil, true, false, false,
		"", "", 0, "", "", 0, 0,
	)
	if err != ErrOnionRequiresTor {
		t.Errorf("expected ErrOnionRequiresTor, got %v", err)
	}
}

func TestNew_OnionWithTor(t *testing.T) {
	cfg, err := New(
		"http://facebookwkhpilnemxj7asber7.onion",
		"", "", nil, true, false, false,
		"127.0.0.1:9050", "", 0, "", "", 0, 0,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IsOnion() {
		t.Error("expected IsOnion() to be true")
	}
	if !cfg.UseTor() {
		t.Error("expected UseTor() to be true")
	}
}

func TestNew_ShortToken(t *testing.T) {
	_, err := New(
		"https://example.com", "", "", []string{"ab"},
		true, false, false, "", "", 0, "", "", 0, 0,
	)
	if err == nil {
		t.Error("expected error for short token")
	}
}

func TestNew_NonLoopbackWithoutBindAll(t *testing.T) {
	_, err := New(
		"https://example.com",
		"0.0.0.0:8099", "", nil,
		true, false, false,
		"", "", 0, "", "", 0, 0,
	)
	if err != ErrNonLoopback {
		t.Errorf("expected ErrNonLoopback, got %v", err)
	}
}

func TestNew_NonLoopbackWithBindAll(t *testing.T) {
	cfg, err := New(
		"https://example.com",
		"0.0.0.0:8099", "", nil,
		true, false, true,
		"", "", 0, "", "", 0, 0,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenAddr != "0.0.0.0:8099" {
		t.Errorf("expected 0.0.0.0:8099, got %s", cfg.ListenAddr)
	}
}

func TestNew_Defaults(t *testing.T) {
	cfg, err := New(
		"https://example.com",
		"", "", nil,
		true, false, false,
		"", "", 0, "", "", 0, 0,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:8099" {
		t.Errorf("expected default listen addr, got %s", cfg.ListenAddr)
	}
	if cfg.AliasDomain != "target-001.local" {
		t.Errorf("expected default alias, got %s", cfg.AliasDomain)
	}
	if cfg.UpstreamTimeout != 30 {
		t.Errorf("expected upstream timeout 30, got %d", cfg.UpstreamTimeout)
	}
	if cfg.ClientTimeout != 60 {
		t.Errorf("expected client timeout 60, got %d", cfg.ClientTimeout)
	}
}

func TestNew_TokensAreCopied(t *testing.T) {
	tokens := []string{"ExampleOrg", "Example Inc"}
	cfg, err := New(
		"https://example.com", "", "", tokens,
		true, false, false, "", "", 0, "", "", 0, 0,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tokens[0] = "MUTATED"
	if cfg.IdentityTokens[0] == "MUTATED" {
		t.Error("tokens should be copied, not shared")
	}
}

func TestNew_HARConfig(t *testing.T) {
	cfg, err := New(
		"https://example.com", "", "", nil,
		true, false, false,
		"", "/tmp/test.har", 0, "", "", 0, 0,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HAR == nil {
		t.Fatal("expected HAR config")
	}
	if cfg.HAR.MaxBodySize != 10*1024*1024 {
		t.Errorf("expected default max body size 10MB, got %d", cfg.HAR.MaxBodySize)
	}
}

func TestOnionValidationNormalizesHost(t *testing.T) {
	for _, target := range []string{"http://EXAMPLE.ONION", "http://example.onion."} {
		if _, err := New(target, "", "", nil, true, false, false, "", "", 0, "", "", 0, 0); err != ErrOnionRequiresTor {
			t.Fatalf("%s: %v", target, err)
		}
	}
}

func TestNew_ExtraOrigins(t *testing.T) {
	cfg, err := New(
		"https://app.example.com", "", "", nil,
		true, false, false, "", "", 0, "", "", 0, 0,
		"https://api.example.com", "https://cdn.example.com",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.ExtraOrigins) != 2 {
		t.Fatalf("expected 2 extra origins, got %d", len(cfg.ExtraOrigins))
	}
	if cfg.ExtraOrigins[0].Host != "api.example.com" {
		t.Errorf("expected api.example.com, got %s", cfg.ExtraOrigins[0].Host)
	}
	if cfg.ExtraOrigins[1].Host != "cdn.example.com" {
		t.Errorf("expected cdn.example.com, got %s", cfg.ExtraOrigins[1].Host)
	}
}

func TestNew_ExtraOriginBadScheme(t *testing.T) {
	_, err := New(
		"https://app.example.com", "", "", nil,
		true, false, false, "", "", 0, "", "", 0, 0,
		"ftp://files.example.com",
	)
	if err == nil {
		t.Error("expected error for ftp scheme extra origin")
	}
}

func TestNew_ExtraOnionRequiresTor(t *testing.T) {
	_, err := New(
		"https://clearnet.example.com", "", "", nil,
		true, false, false,
		"", "", 0, "", "", 0, 0,
		"http://something.onion",
	)
	if err != ErrOnionRequiresTor {
		t.Errorf("expected ErrOnionRequiresTor for .onion extra origin without Tor, got %v", err)
	}
}

func TestNew_ExtraOnionCaseAndDot(t *testing.T) {
	for _, extra := range []string{"http://EXAMPLE.ONION", "http://example.onion."} {
		_, err := New(
			"https://clearnet.example.com", "", "", nil,
			true, false, false,
			"", "", 0, "", "", 0, 0,
			extra,
		)
		if err != ErrOnionRequiresTor {
			t.Errorf("%s: expected ErrOnionRequiresTor, got %v", extra, err)
		}
	}
}

func TestNew_ExtraOnionWithTor(t *testing.T) {
	_, err := New(
		"https://clearnet.example.com", "", "", nil,
		true, false, false,
		"127.0.0.1:9050", "", 0, "", "", 0, 0,
		"http://something.onion",
	)
	if err != nil {
		t.Fatalf("extra .onion with Tor should succeed, got %v", err)
	}
}

func TestNew_ExtraOriginNoHost(t *testing.T) {
	_, err := New(
		"https://app.example.com", "", "", nil,
		true, false, false, "", "", 0, "", "", 0, 0,
		"https://",
	)
	if err == nil {
		t.Error("expected error for extra origin without hostname")
	}
}

func TestIdentityTokenValidationUsesCharacters(t *testing.T) {
	for _, token := range []string{"猫", string([]byte{0xff, 0xff, 0xff})} {
		if _, err := New("https://example.com", "", "", []string{token}, true, false, false, "", "", 0, "", "", 0, 0); err == nil {
			t.Fatalf("accepted token %q", token)
		}
	}
}

func TestNew_ParanoidRoutingIsIndependent(t *testing.T) {
	for _, torAddr := range []string{"", "127.0.0.1:9050"} {
		t.Run(torAddr, func(t *testing.T) {
			cfg, err := New("https://example.com", "", "", nil, true, true, false, torAddr, "", 0, "", "", 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.Paranoid || cfg.UseTor() != (torAddr != "") {
				t.Fatalf("masking changed routing: paranoid=%t tor=%t", cfg.Paranoid, cfg.UseTor())
			}
		})
	}
}

func TestNew_ParanoidOnionStillRequiresTor(t *testing.T) {
	_, err := New("http://example.onion", "", "", nil, true, true, false, "", "", 0, "", "", 0, 0)
	if err != ErrOnionRequiresTor {
		t.Fatalf("onion routing requirement changed: %v", err)
	}
}
