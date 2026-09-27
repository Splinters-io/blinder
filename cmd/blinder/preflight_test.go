package main

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/endpoint"
	blindertls "github.com/Splinters-io/blinder/internal/tls"
)

func TestCertificateStatusDoesNotInferOperatorTrustFromListener(t *testing.T) {
	cert, err := blindertls.Prepare("", "target.local", "127.0.0.1:18099", "extra.alias.local")
	if err != nil {
		t.Fatal(err)
	}
	g := certificateGuidance{
		platform: certificatePlatform{goos: "darwin"}, alias: "target.local",
		listen: "127.0.0.1:18099", extraAliases: []string{"extra.alias.local"}, operator: true,
	}
	var checked []string
	var out bytes.Buffer
	err = printCertificateStatusWithVerifier(&out, cert, g, func(host string) error {
		checked = append(checked, host)
		if host == endpoint.OperatorHost {
			return errors.New("host-scoped platform trust excludes operator")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("primary certificate setup changed exit semantics: %v", err)
	}
	wantHosts := []string{"127.0.0.1", "target.local", "extra.alias.local", endpoint.OperatorHost}
	if !reflect.DeepEqual(checked, wantHosts) {
		t.Fatalf("checked %v; want %v", checked, wantHosts)
	}
	for _, want := range []string{
		"Platform trust: ready for this endpoint.",
		"Platform trust [primary alias]: ready (target.local)",
		"Platform trust [extra origin]: ready (extra.alias.local)",
		"Platform trust [CAPTCHA operator]: setup needed (blinder-operator.localhost)",
		"Preflight exit status and --trust-cert apply to 127.0.0.1 only",
		"verify name resolution and trust in the actual browser/scanner separately",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in status:\n%s", want, out.String())
		}
	}
}

func TestCertificateStatusPreservesListenerFailure(t *testing.T) {
	cert, err := blindertls.Prepare("", "target.local", "127.0.0.1:18099")
	if err != nil {
		t.Fatal(err)
	}
	listenerErr := errors.New("listener trust missing")
	var out bytes.Buffer
	err = printCertificateStatusWithVerifier(&out, cert, certificateGuidance{alias: "target.local", operator: true}, func(host string) error {
		if host == cert.Host {
			return listenerErr
		}
		return nil
	})
	if !errors.Is(err, listenerErr) {
		t.Fatalf("other trusted endpoints hid listening endpoint failure: %v", err)
	}
	if !strings.Contains(out.String(), "Platform trust [CAPTCHA operator]: ready") || !strings.Contains(out.String(), "Platform trust: setup needed for this endpoint.") {
		t.Fatalf("endpoint states conflated:\n%s", out.String())
	}
}

func TestCertificateEndpointChecksAreDistinctAndOperatorIsOptIn(t *testing.T) {
	var checked []string
	var out bytes.Buffer
	printAdditionalCertificateEndpoints(&out, &blindertls.Material{Host: "127.0.0.1"}, certificateGuidance{
		alias: "127.0.0.1", extraAliases: []string{"extra.local", "EXTRA.local", "", "127.0.0.1"},
	}, func(host string) error {
		checked = append(checked, host)
		return nil
	})
	if !reflect.DeepEqual(checked, []string{"extra.local"}) {
		t.Fatalf("unexpected endpoint checks: %v", checked)
	}
	if strings.Contains(out.String(), endpoint.OperatorHost) {
		t.Fatalf("offered unused operator endpoint:\n%s", out.String())
	}
}

func TestChallengeCertificatePreflightChecksConcreteExample(t *testing.T) {
	var checked []string
	var out bytes.Buffer
	printAdditionalCertificateEndpoints(&out, &blindertls.Material{Host: "127.0.0.1"}, certificateGuidance{
		alias: "127.0.0.1", extraAliases: []string{endpoint.ChallengeWildcard}, operator: true,
	}, func(host string) error {
		checked = append(checked, host)
		if host == endpoint.ChallengeExampleHost {
			return errors.New("endpoint-specific challenge trust missing")
		}
		return nil
	})
	if !reflect.DeepEqual(checked, []string{endpoint.ChallengeExampleHost, endpoint.OperatorHost}) {
		t.Fatalf("wildcard plan did not become a concrete endpoint check: %v", checked)
	}
	for _, want := range []string{
		"Platform trust [CAPTCHA challenge example]: setup needed (" + endpoint.ChallengeExampleHost + ")",
		"example check does not establish browser trust for every challenge hostname",
		"verify the actual challenge URL when it opens",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in guidance:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), endpoint.ChallengeWildcard) {
		t.Fatalf("wildcard SAN presented as a browser endpoint:\n%s", out.String())
	}
}

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
