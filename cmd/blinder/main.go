package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Splinters-io/blinder/internal/captcha"
	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/endpoint"
	"github.com/Splinters-io/blinder/internal/proxy"
	"github.com/Splinters-io/blinder/internal/scrub"
	blindertls "github.com/Splinters-io/blinder/internal/tls"
)

var version = "dev"
var commit = "unknown"

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	os.Exit(run())
}

func run() int {
	var (
		target      string
		listen      string
		alias       string
		identity    stringSlice
		extraOrigin stringSlice
		tor         bool
		torAddr     string
		noVerifyTLS bool
		paranoid        bool
		preserveContent bool
		bindAll     bool
		harPath     string
		harMaxBody  int64
		outputDir   string
		certDir     string
		showVersion bool
		preflight   bool
		trustCert   bool
		ephemeral   bool
		captchaConf string
		configFile  string
	)

	flag.StringVar(&configFile, "config", "", "Path to YAML config file (CLI flags override)")
	flag.StringVar(&configFile, "c", "", "Path to YAML config file (shorthand)")
	flag.StringVar(&target, "target", "", "Real target URL (required unless running certificate setup)")
	flag.StringVar(&target, "t", "", "Real target URL (shorthand)")
	flag.StringVar(&listen, "listen", "", "Listen address (default 127.0.0.1:8099)")
	flag.StringVar(&listen, "l", "", "Listen address (shorthand)")
	flag.StringVar(&alias, "alias", "", "Alias domain the client sees")
	flag.Var(&identity, "identity", "Identity tokens to scrub (repeatable)")
	flag.Var(&identity, "i", "Identity tokens to scrub (shorthand, repeatable)")
	flag.Var(&extraOrigin, "extra-origin", "Additional upstream origin (repeatable)")
	flag.Var(&extraOrigin, "X", "Additional upstream origin (shorthand, repeatable)")
	flag.BoolVar(&tor, "tor", false, "Route upstream through Tor SOCKS5 proxy")
	flag.StringVar(&torAddr, "tor-addr", "", "Tor SOCKS5 address")
	flag.BoolVar(&noVerifyTLS, "no-verify-tls", false, "Skip TLS verification on target")
	flag.BoolVar(&paranoid, "paranoid", true, "Replace display prose with neutral filler (default: on)")
	flag.BoolVar(&preserveContent, "preserve-content", false, "Keep original display text; only scrub identity tokens")
	flag.BoolVar(&bindAll, "bind-all", false, "Allow binding to non-loopback addresses")
	flag.StringVar(&harPath, "har", "", "Write HAR 1.2 file with real (pre-scrub) transactions")
	flag.Int64Var(&harMaxBody, "har-max-body", 10*1024*1024, "Max bytes per request/response body captured in HAR")
	flag.StringVar(&outputDir, "output", "", "Output directory for manifest and reports")
	flag.StringVar(&outputDir, "o", "", "Output directory (shorthand)")
	flag.StringVar(&certDir, "cert-dir", "", "Private certificate directory (default: per-endpoint user configuration directory)")
	flag.BoolVar(&preflight, "preflight", false, "Check certificate trust for listener and browser hostnames, then exit (2 if listener trust is needed)")
	flag.BoolVar(&trustCert, "trust-cert", false, "Prepare certificate, request approval for macOS user trust, then exit")
	flag.BoolVar(&ephemeral, "ephemeral-cert", false, "Use an in-memory certificate for this run; do not save or install trust")
	flag.StringVar(&captchaConf, "captcha-config", "", "Path to CAPTCHA provider YAML config")
	flag.BoolVar(&showVersion, "version", false, "Show version and exit")

	flag.Parse()

	var fileConfig *config.FileConfig
	if configFile != "" {
		fc, err := config.LoadFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fileConfig = fc
		if target == "" && fc.Target != "" {
			target = fc.Target
		}
		if listen == "" && fc.Listen != "" {
			listen = fc.Listen
		}
		if alias == "" && fc.Alias != "" {
			alias = fc.Alias
		}
		if len(identity) == 0 && len(fc.Identity) > 0 {
			identity = fc.Identity
		}
		if len(extraOrigin) == 0 && len(fc.ExtraOrigins) > 0 {
			extraOrigin = fc.ExtraOrigins
		}
		if outputDir == "" && fc.Output != "" {
			outputDir = fc.Output
		}
		if certDir == "" && fc.CertDir != "" {
			certDir = fc.CertDir
		}
		if captchaConf == "" && fc.CaptchaConfig != "" {
			captchaConf = fc.CaptchaConfig
		}
		if !tor && fc.Tor.Enabled {
			tor = true
		}
		if torAddr == "" && fc.Tor.Addr != "" {
			torAddr = fc.Tor.Addr
		}
		if harPath == "" && fc.HAR.Path != "" {
			harPath = fc.HAR.Path
		}
		if harMaxBody == 10*1024*1024 && fc.HAR.MaxBody > 0 {
			harMaxBody = fc.HAR.MaxBody
		}
		if !noVerifyTLS && fc.NoVerifyTLS {
			noVerifyTLS = true
		}
		if fc.PreserveContent {
			paranoid = false
		}
		if !bindAll && fc.BindAll {
			bindAll = true
		}
	}

	if preserveContent {
		paranoid = false
	}

	if listen == "" {
		listen = "127.0.0.1:8099"
	}
	if alias == "" {
		alias = "target-001.localhost"
	}
	if torAddr == "" {
		torAddr = "127.0.0.1:9050"
	}
	if runtime.GOOS == "darwin" && strings.HasSuffix(alias, ".local") {
		log.Printf("[warn] alias %q uses .local which is reserved for mDNS on macOS and will time out; use .localhost instead", alias)
	}

	if showVersion {
		fmt.Printf("blinder %s (%s)\n", version, commit)
		return 0
	}
	if ephemeral && (certDir != "" || trustCert) {
		fmt.Fprintln(os.Stderr, "error: --ephemeral-cert cannot be combined with --cert-dir or --trust-cert")
		return 1
	}
	if target == "" && (preflight || trustCert) {
		// Certificate-only setup does not construct a proxy or contact a target.
		target = "https://localhost"
	}

	effectiveTorAddr := ""
	if tor {
		effectiveTorAddr = torAddr
	}

	cfg, err := config.New(
		target,
		listen,
		alias,
		[]string(identity),
		!noVerifyTLS,
		paranoid,
		bindAll,
		effectiveTorAddr,
		harPath,
		harMaxBody,
		outputDir,
		certDir,
		0, 0,
		[]string(extraOrigin)...,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	if cfg.HAR != nil && fileConfig != nil {
		cfg.HAR.MaxEntries = fileConfig.HAR.MaxEntries
		cfg.HAR.CaptureBudget = fileConfig.HAR.CaptureBudget
	}
	// Provider aliases belong in the same certificate/preflight plan as target
	// aliases. Load the provider file before any certificate is prepared or trusted.
	cfg.CaptchaConfigPath = captchaConf
	if err := cfg.LoadCaptchaConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	// Report an unusable endpoint before certificate generation or platform trust
	// checks. Certificate-only commands do not reserve a listening socket.
	var ln net.Listener
	if !preflight && !trustCert {
		ln, err = net.Listen("tcp", cfg.ListenAddr)
		if err != nil {
			log.Printf("  Listen failed: %v", err)
			return 1
		}
		defer ln.Close()
		if _, port, _ := net.SplitHostPort(cfg.ListenAddr); port == "0" {
			cfg.ListenAddr = ln.Addr().String()
		}
	}

	extraAliases, err := certificateExtraAliases(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	if !ephemeral && cfg.CertDir == "" {
		cfg.CertDir, err = blindertls.CADir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
	}
	localTLS, err := blindertls.Prepare(cfg.CertDir, cfg.AliasDomain, cfg.ListenAddr, extraAliases...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "certificate setup failed: %v\n", err)
		return 1
	}
	guidance := certificateGuidance{
		platform:     detectCertificatePlatform(runtime.GOOS, os.ReadFile),
		executable:   os.Args[0],
		alias:        cfg.AliasDomain,
		listen:       cfg.ListenAddr,
		extraAliases: extraAliases,
		operator:     captchaConf != "",
	}
	trustErr := printCertificateStatus(os.Stdout, localTLS, guidance)
	if trustCert {
		return requestCertificateTrust(localTLS, trustErr, os.Stdin, os.Stdout, guidance)
	}
	if preflight {
		if trustErr != nil {
			return 2
		}
		return 0
	}
	// An ephemeral TLS certificate does not discard ownership of outstanding
	// resource references. Keep a separate random signing key in the endpoint store.
	cfg.VersionKeyDir = cfg.CertDir
	if cfg.VersionKeyDir == "" {
		cfg.VersionKeyDir, err = blindertls.CADir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "version key setup failed: %v\n", err)
			return 1
		}
	}

	printBanner(cfg)
	srv, err := proxy.NewWithCertificate(cfg, localTLS.Certificate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	if token := srv.CaptchaOperatorToken(); token != "" && cfg.Captcha != nil && len(cfg.Captcha.Providers) > 0 {
		masked := token[:8] + "..." + token[len(token)-8:]
		log.Printf("  CAPTCHA operator token: %s", masked)
		log.Printf("  Operator: %s", srv.CaptchaOperatorURL())
		log.Printf("  Browser login: %slogin?token=%s", srv.CaptchaOperatorURL(), token)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	log.Printf("  Proxy listening on https://%s", ln.Addr())
	serverErr := make(chan error, 1)

	go func() {
		serverErr <- srv.ListenAndServeOnListener(ln)
	}()

	exitCode := 0
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
running:
	for {
		select {
		case sig := <-sigCh:
			log.Printf("\n  Received %v, shutting down...", sig)
			break running
		case err := <-serverErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("  Server stopped: %v", err)
				exitCode = 1
			}
			break running
		case <-ticker.C:
			requests, bytes, errors, scrubbed := srv.GetStats()
			log.Printf("  [stats] requests=%d bytes=%d errors=%d scrubbed=%d leaks=%d",
				requests, bytes, errors, scrubbed, len(srv.Gate().Leaks()))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("  Shutdown error: %v", err)
		exitCode = 1
	}

	if err := srv.FlushHAR(); err != nil {
		log.Printf("  HAR flush error: %v", err)
		exitCode = 1
	} else if cfg.HAR != nil {
		log.Printf("  HAR written: %s", cfg.HAR.FilePath)
	}

	if err := srv.FlushManifest(); err != nil {
		log.Printf("  Manifest flush error: %v", err)
		exitCode = 1
	} else if cfg.OutputDir != "" {
		log.Printf("  Manifest written: %s/", cfg.OutputDir)
	}

	requests, bytes, errors, scrubbed := srv.GetStats()
	leaks := srv.Gate().Leaks()
	aliases := srv.Gate().Aliases()

	fmt.Println()
	fmt.Println("  ── Session Summary ──")
	fmt.Printf("  Requests:  %d\n", requests)
	fmt.Printf("  Bytes:     %d\n", bytes)
	fmt.Printf("  Errors:    %d\n", errors)
	fmt.Printf("  Scrubbed:  %d\n", scrubbed)
	fmt.Printf("  Leaks caught: %d\n", len(leaks))
	fmt.Printf("  Aliases:   %d\n", len(aliases))
	fmt.Println()
	return exitCode
}

// certificateExtraAliases is used once for default-store selection, certificate
// preparation, endpoint advice and version-key storage. Provider aliases are
// separate from target ExtraOrigins and are needed only when Tor routes them.
// Isolated challenge origins are needed for CAPTCHA in either routing mode.
func certificateExtraAliases(cfg *config.Config) ([]string, error) {
	var aliases []string
	for _, u := range cfg.ExtraOrigins {
		aliases = append(aliases, scrub.AliasOrigin(u.Scheme, u.Hostname(), u.Port(), cfg.AliasDomain))
	}
	if cfg.Captcha != nil && cfg.Captcha.Matcher != nil {
		aliases = append(aliases, endpoint.ChallengeWildcard)
	}
	if cfg.UseTor() && cfg.Captcha != nil && cfg.Captcha.Matcher != nil {
		listen := cfg.ListenAddr
		if host, port, err := net.SplitHostPort(listen); err == nil && port == "0" {
			// Certificate-only commands do not reserve a port. Alias hostnames
			// depend on upstream origins, so their SANs remain the same after bind.
			listen = net.JoinHostPort(host, "443")
		}
		routes, err := captcha.NewProviderRoutes(cfg.Captcha.Matcher, "https", listen)
		if err != nil {
			return nil, err
		}
		aliases = append(aliases, routes.AliasHosts()...)
	}
	return aliases, nil
}

func printBanner(cfg *config.Config) {
	fmt.Println()
	fmt.Println("  ██████╗ ██╗     ██╗███╗   ██╗██████╗ ███████╗██████╗ ")
	fmt.Println("  ██╔══██╗██║     ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗")
	fmt.Println("  ██████╔╝██║     ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝")
	fmt.Println("  ██╔══██╗██║     ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗")
	fmt.Println("  ██████╔╝███████╗██║██║ ╚████║██████╔╝███████╗██║  ██║")
	fmt.Println("  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝")
	fmt.Println()
	fmt.Printf("  Content-blind reverse proxy v%s\n", version)
	fmt.Println()
	fmt.Printf("  Listen:  https://%s\n", cfg.ListenAddr)
	fmt.Printf("  Alias:   %s\n", cfg.AliasDomain)

	if len(cfg.ExtraOrigins) > 0 {
		fmt.Printf("  Origins: %d extra\n", len(cfg.ExtraOrigins))
		for _, u := range cfg.ExtraOrigins {
			a := scrub.AliasOrigin(u.Scheme, u.Hostname(), u.Port(), cfg.AliasDomain)
			fmt.Printf("           %s -> %s\n", a, u.Host)
		}
	}

	if cfg.UseTor() {
		fmt.Printf("  Tor:     %s\n", cfg.Tor.SOCKSAddr)
	}
	if cfg.IsOnion() {
		fmt.Println("  Target:  [.onion hidden service]")
	}

	if !cfg.Paranoid {
		fmt.Println("  Content: original display text preserved (identity-only scrubbing)")
	}
	if cfg.HAR != nil {
		fmt.Printf("  HAR:     %s\n", cfg.HAR.FilePath)
	}
	if cfg.OutputDir != "" {
		fmt.Printf("  Output:  %s/\n", cfg.OutputDir)
	}
	if len(cfg.IdentityTokens) > 0 {
		fmt.Printf("  Scrub:   %d identity token(s)\n", len(cfg.IdentityTokens))
	}

	if cfg.Captcha != nil && cfg.Captcha.Matcher != nil {
		providers := cfg.Captcha.Matcher.ProviderNames()
		if len(providers) > 0 {
			fmt.Printf("  CAPTCHA: %d provider(s): %s\n", len(providers), strings.Join(providers, ", "))
			if cfg.UseTor() {
				for _, p := range cfg.Captcha.Providers {
					if p.TorPolicy == captcha.TorPolicyDirect {
						fmt.Printf("           %s: direct (bypasses Tor)\n", p.Name)
					}
				}
			}
		}
	}

	if !cfg.VerifyTargetTLS {
		fmt.Println("  Warning: TLS verification disabled for upstream target")
	}

	fmt.Println()
}
