package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	blindertls "github.com/Splinters-io/blinder/internal/tls"
)

func TestTrustRequiresExplicitYes(t *testing.T) {
	for _, text := range []string{"", "\n", "y\n", "no\n", "YES\n"} {
		if confirmTrust(strings.NewReader(text)) {
			t.Fatalf("accepted %q as explicit trust approval", text)
		}
	}
	if !confirmTrust(strings.NewReader("yes\n")) {
		t.Fatal("explicit approval rejected")
	}
}

func TestCertificateAdviceMatchesPlatformAndTrustState(t *testing.T) {
	cert := &blindertls.Material{PublicPath: "/tmp/Blinder certs/certificate.pem", Host: "::1"}
	for _, tc := range []struct {
		name       string
		platform   certificatePlatform
		trusted    bool
		want, omit []string
	}{
		{"mac needs trust", certificatePlatform{goos: "darwin"}, false, []string{"login Keychain", "--trust-cert", "--cert-dir", "--alias", "[::1]:18099"}, []string{"update-ca-certificates", "sudo"}},
		{"ubuntu needs trust", certificatePlatform{goos: "linux", id: "ubuntu", version: "24.04"}, false, []string{"Recommended on Ubuntu 24.04", "update-ca-certificates", "server certificate", "curl --cacert"}, []string{"Keychain", "sudo update-ca-certificates"}},
		{"unknown Linux", certificatePlatform{goos: "linux"}, false, []string{"Linux (distribution unknown)", "curl --cacert"}, []string{"Keychain", "update-ca-certificates"}},
		{"already trusted", certificatePlatform{goos: "darwin"}, true, []string{"curl --cacert", "does not install platform or browser trust"}, []string{"Next step", "--trust-cert"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := certificateGuidance{platform: tc.platform, executable: "./blinder", alias: "target.local", listen: "[::]:18099"}
			var out bytes.Buffer
			printCertificateAdvice(&out, cert, g, !tc.trusted)
			for _, want := range append(tc.want, "Do not import this leaf certificate as an issuing CA", "--preflight still exits 2", "identity.pem contains the private key", "client machine") {
				if !strings.Contains(out.String(), want) {
					t.Errorf("missing %q in advice:\n%s", want, out.String())
				}
			}
			for _, omit := range tc.omit {
				if strings.Contains(out.String(), omit) {
					t.Errorf("unexpected %q in advice:\n%s", omit, out.String())
				}
			}
		})
	}
}

func TestEphemeralAdviceDoesNotOfferPersistentTrust(t *testing.T) {
	var out bytes.Buffer
	printCertificateAdvice(&out, &blindertls.Material{}, certificateGuidance{platform: certificatePlatform{goos: "darwin"}}, true)
	if !strings.Contains(out.String(), "Rerun without --ephemeral-cert") || strings.Contains(out.String(), "--trust-cert") || strings.Contains(out.String(), "curl --cacert") {
		t.Fatalf("misleading ephemeral advice: %s", out.String())
	}
}

func TestDisplayedSetupCommandPreservesArguments(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("POSIX shell not available")
	}
	// Harmless shell substitutions must remain literal text, never execute.
	cert := &blindertls.Material{PublicPath: "/tmp/it's $(printf WRONG) `printf WRONG`/certificate.pem"}
	g := certificateGuidance{executable: "/tmp/my blinder", alias: "alias.local", listen: "[::1]:18099"}
	command := g.setupCommand(cert, "--trust-cert")
	got, err := exec.Command(sh, "-c", "printf '%s\\000' "+command).Output()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{g.executable, "--trust-cert", "--cert-dir", filepath.Dir(cert.PublicPath), "--alias", g.alias, "--listen", g.listen, ""}
	if string(got) != strings.Join(want, "\x00") {
		t.Fatalf("displayed command changes arguments: %q", got)
	}
}
