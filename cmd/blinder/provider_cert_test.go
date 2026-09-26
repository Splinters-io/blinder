package main

import (
	"crypto/x509"
	"reflect"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/captcha"
	"github.com/Splinters-io/blinder/internal/config"
	blindertls "github.com/Splinters-io/blinder/internal/tls"
)

func TestProviderCertificateSANsMatchRoutesOnlyInTorMode(t *testing.T) {
	providerConfig, err := captcha.ParseConfig([]byte(`version: 1
captcha:
  custom:
    - name: routed
      resource_origins: ["https://captcha.example", "https://captcha.example:8443"]
    - name: direct
      resource_origins: ["https://direct.example"]
      tor_policy: direct
`))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{ListenAddr: "127.0.0.1:18099", AliasDomain: "target.local", Captcha: providerConfig}
	aliases, err := certificateExtraAliases(cfg)
	if err != nil || len(aliases) != 0 {
		t.Fatalf("non-Tor certificate gained provider names: %v, %v", aliases, err)
	}
	cfg.Tor = &config.TorConfig{SOCKSAddr: "127.0.0.1:9050"}
	aliases, err = certificateExtraAliases(cfg)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := captcha.NewProviderRoutes(providerConfig.Matcher, "https", cfg.ListenAddr)
	if err != nil || !reflect.DeepEqual(aliases, routes.AliasHosts()) || len(aliases) != 2 {
		t.Fatalf("certificate names differ from routing: %v, %v", aliases, err)
	}
	material, err := blindertls.Prepare("", cfg.AliasDomain, cfg.ListenAddr, aliases...)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(material.Certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range aliases {
		if err := leaf.VerifyHostname(name); err != nil {
			t.Fatalf("generated certificate misses provider route %s: %v", name, err)
		}
	}
	for _, name := range leaf.DNSNames {
		if strings.Contains(name, "captcha.example") || strings.Contains(name, "direct.example") {
			t.Fatalf("certificate disclosed real provider origin: %s", name)
		}
	}
	if len(cfg.ExtraOrigins) != 0 {
		t.Fatal("provider routes entered target extra-origin scope")
	}
	cfg.ListenAddr = "127.0.0.1:0"
	ephemeralAliases, err := certificateExtraAliases(cfg)
	if err != nil || !reflect.DeepEqual(ephemeralAliases, aliases) {
		t.Fatalf("certificate-only port-zero aliases differ: %v, %v", ephemeralAliases, err)
	}
}
