package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Splinters-io/blinder/internal/config"
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
	var (
		target      string
		listen      string
		alias       string
		identity    stringSlice
		tor         bool
		torAddr     string
		noVerifyTLS bool
		paranoid    bool
		bindAll     bool
		harPath     string
		harMaxBody  int64
		outputDir   string
		certDir     string
		showVersion bool
	)

	flag.StringVar(&target, "target", "", "Real target URL (required)")
	flag.StringVar(&target, "t", "", "Real target URL (shorthand)")
	flag.StringVar(&listen, "listen", "127.0.0.1:8099", "Listen address")
	flag.StringVar(&listen, "l", "127.0.0.1:8099", "Listen address (shorthand)")
	flag.StringVar(&alias, "alias", "target-001.local", "Alias domain the client sees")
	flag.Var(&identity, "identity", "Identity tokens to scrub (repeatable)")
	flag.Var(&identity, "i", "Identity tokens to scrub (shorthand, repeatable)")
	flag.BoolVar(&tor, "tor", false, "Route upstream through Tor SOCKS5 proxy")
	flag.StringVar(&torAddr, "tor-addr", "127.0.0.1:9050", "Tor SOCKS5 address")
	flag.BoolVar(&noVerifyTLS, "no-verify-tls", false, "Skip TLS verification on target")
	flag.BoolVar(&paranoid, "paranoid", false, "Maximum scrubbing mode")
	flag.BoolVar(&bindAll, "bind-all", false, "Allow binding to non-loopback addresses")
	flag.StringVar(&harPath, "har", "", "Write HAR 1.2 file with real (pre-scrub) transactions")
	flag.Int64Var(&harMaxBody, "har-max-body", 10*1024*1024, "Max body size to capture in HAR")
	flag.StringVar(&outputDir, "output", "", "Output directory for manifest and reports")
	flag.StringVar(&outputDir, "o", "", "Output directory (shorthand)")
	flag.StringVar(&certDir, "cert-dir", "", "Persist generated cert/key to this directory")
	flag.BoolVar(&showVersion, "version", false, "Show version and exit")

	flag.Parse()

	if showVersion {
		fmt.Printf("blinder %s (%s)\n", version, commit)
		os.Exit(0)
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
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	printBanner(cfg)

	// TODO: start proxy server
	_ = cfg
	fmt.Println("proxy not yet implemented")
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
	fmt.Printf("  Listen:  %s\n", cfg.ListenAddr)
	fmt.Printf("  Alias:   %s\n", cfg.AliasDomain)

	if cfg.UseTor() {
		fmt.Printf("  Tor:     %s\n", cfg.Tor.SOCKSAddr)
	}
	if cfg.IsOnion() {
		fmt.Println("  Target:  [.onion hidden service]")
	}

	if cfg.Paranoid {
		fmt.Println("  Mode:    PARANOID")
	}
	if cfg.HAR != nil {
		fmt.Printf("  HAR:     %s\n", cfg.HAR.FilePath)
	}
	if len(cfg.IdentityTokens) > 0 {
		fmt.Printf("  Scrub:   %d identity token(s)\n", len(cfg.IdentityTokens))
	}
	fmt.Println()
}
