package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/Splinters-io/blinder/internal/endpoint"
	blindertls "github.com/Splinters-io/blinder/internal/tls"
)

type certificateGuidance struct {
	platform     certificatePlatform
	executable   string
	alias        string
	listen       string
	extraAliases []string
	operator     bool
}

func printCertificateStatus(out io.Writer, cert *blindertls.Material, guidance certificateGuidance) error {
	return printCertificateStatusWithVerifier(out, cert, guidance, cert.CheckTrustForHost)
}

func printCertificateStatusWithVerifier(out io.Writer, cert *blindertls.Material, guidance certificateGuidance, verify func(string) error) error {
	fmt.Fprintf(out, "Detected OS: %s\n", guidance.platform.name())
	fmt.Fprintf(out, "Local certificate: %s\nEndpoint host: %s\nSHA-256: %s\nExpires: %s\n",
		cert.Action, cert.Host, cert.Fingerprint, cert.Certificate.Leaf.NotAfter.Format(time.RFC3339))
	if cert.PublicPath != "" {
		fmt.Fprintf(out, "Public certificate: %s\n", cert.PublicPath)
	}
	err := verify(cert.Host)
	if err == nil {
		fmt.Fprintln(out, "Platform trust: ready for this endpoint. Verify your browser/scanner if it uses a separate trust store.")
	} else {
		fmt.Fprintln(out, "Platform trust: setup needed for this endpoint.")
	}
	printAdditionalCertificateEndpoints(out, cert, guidance, verify)
	printCertificateAdvice(out, cert, guidance, err != nil)
	return err
}

// The existing setup command and exit status remain scoped to the listening
// host. Other browser origins must be checked separately: macOS trust can be
// hostname-scoped even when all names are present on the same certificate.
func printAdditionalCertificateEndpoints(out io.Writer, cert *blindertls.Material, guidance certificateGuidance, verify func(string) error) {
	type browserEndpoint struct{ role, host string }
	endpoints := []browserEndpoint{{"primary alias", guidance.alias}}
	for _, alias := range guidance.extraAliases {
		endpoints = append(endpoints, browserEndpoint{"extra origin", alias})
	}
	if guidance.operator {
		endpoints = append(endpoints, browserEndpoint{"CAPTCHA operator", endpoint.OperatorHost})
	}
	seen := map[string]bool{strings.ToLower(cert.Host): true}
	checked := 0
	for _, candidate := range endpoints {
		key := strings.ToLower(candidate.host)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		checked++
		status := "ready"
		if verify(candidate.host) != nil {
			status = "setup needed"
		}
		fmt.Fprintf(out, "Platform trust [%s]: %s (%s)\n", candidate.role, status, candidate.host)
	}
	if checked > 0 {
		fmt.Fprintf(out, "Preflight exit status and --trust-cert apply to %s only. Other browser hostnames above have independent trust results.\n", cert.Host)
		fmt.Fprintln(out, "These are platform certificate checks; verify name resolution and trust in the actual browser/scanner separately.")
	}
}

func printCertificateAdvice(out io.Writer, cert *blindertls.Material, guidance certificateGuidance, needsTrust bool) {
	if cert.PublicPath == "" {
		fmt.Fprintln(out, "Ephemeral certificate: trust changes on restart. Rerun without --ephemeral-cert for persistent client setup.")
		return
	}
	if needsTrust {
		switch guidance.platform.goos {
		case "darwin":
			fmt.Fprintln(out, "Next step: review the fingerprint, then request trust in your macOS login Keychain:")
			fmt.Fprintln(out, "  "+guidance.setupCommand(cert, "--trust-cert"))
			fmt.Fprintln(out, "This trusts this server certificate for SSL to the displayed host. It requires confirmation; it does not install a signing CA.")
		case "linux":
			fmt.Fprintf(out, "Recommended on %s: configure trust for the browser/scanner you will use. For curl, use the public certificate with --cacert below.\n", guidance.platform.name())
			if guidance.platform.debianFamily() {
				fmt.Fprintln(out, "Ubuntu/Debian's system-wide update-ca-certificates procedure is for CA trust. Blinder exports a server certificate, so use client-specific trust first.")
			}
			fmt.Fprintln(out, "--trust-cert does not install Linux trust or invoke sudo.")
		default:
			fmt.Fprintln(out, "Configure the selected client's server-certificate trust or certificate-file option using the public certificate above.")
		}
	}
	if guidance.platform.goos == "darwin" || guidance.platform.goos == "linux" {
		_, port, err := net.SplitHostPort(guidance.listen)
		if err == nil {
			endpoint := (&url.URL{Scheme: "https", Host: net.JoinHostPort(cert.Host, port), Path: "/"}).String()
			fmt.Fprintln(out, "After starting Blinder, verify this endpoint with certificate checking enabled:")
			fmt.Fprintf(out, "  curl --cacert %s %s\n", shellQuote(cert.PublicPath), shellQuote(endpoint))
			fmt.Fprintln(out, "This checks curl's explicit certificate trust; it does not install platform or browser trust.")
		}
	}
	fmt.Fprintln(out, "Browser/scanner: verify the fingerprint and use that client's server-certificate trust flow. Do not import this leaf certificate as an issuing CA. Client support varies.")
	fmt.Fprintln(out, "Client-specific trust can work while --preflight still exits 2. After changing platform trust, rerun --preflight in a new process.")
	fmt.Fprintln(out, "Use certificate.pem for client setup; identity.pem contains the private key. Trust belongs on the client machine, which may differ from this OS.")
}

func (g certificateGuidance) setupCommand(cert *blindertls.Material, action string) string {
	args := []string{g.executable, action, "--cert-dir", filepath.Dir(cert.PublicPath), "--alias", g.alias, "--listen", g.listen}
	for i := range args {
		args[i] = shellQuote(args[i])
	}
	return strings.Join(args, " ")
}

// Commands are displayed, never executed. Quote paths and configured names as
// single shell arguments, including spaces, apostrophes and shell metacharacters.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func requestCertificateTrust(cert *blindertls.Material, trustErr error, input io.Reader, output io.Writer, guidance certificateGuidance) int {
	if trustErr == nil {
		return 0
	}
	if !blindertls.UserTrustSupported() {
		fmt.Fprintf(output, "Automatic trust installation is unavailable on %s. Follow the client-specific advice above; trust settings were not changed.\n", guidance.platform.name())
		return 2
	}
	fmt.Fprintf(output, "Trust this server certificate for SSL to %s in your macOS user Keychain?\nThis does not install a signing CA. macOS may request approval. Type 'yes' to proceed: ", cert.Host)
	if !confirmTrust(input) {
		fmt.Fprintln(output, "Trust installation declined. Certificate files are ready; trust settings were not changed.")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := cert.InstallUserTrust(ctx, output); err != nil {
		fmt.Fprintf(output, "Trust setup failed: %v\n", err)
		return 1
	}
	if err := cert.CheckTrust(); err != nil {
		fmt.Fprintln(output, "Installation completed, but platform verification still fails. Rerun --preflight in a new process and check the selected client's trust store.")
		return 2
	}
	fmt.Fprintf(output, "Platform trust: ready for %s. Certificate retained for the next start; verify the selected browser/scanner and other hostnames separately.\n", cert.Host)
	return 0
}

func confirmTrust(input io.Reader) bool {
	answer, err := bufio.NewReader(input).ReadString('\n')
	return (err == nil || err == io.EOF) && strings.TrimSpace(answer) == "yes"
}
