package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Splinters-io/blinder/internal/config"
	"github.com/Splinters-io/blinder/internal/proxy"
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

	srv, err := proxy.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("  Proxy listening on https://%s", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("  Server stopped: %v", err)
		}
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			requests, bytes, errors, scrubbed := srv.GetStats()
			log.Printf("  [stats] requests=%d bytes=%d errors=%d scrubbed=%d leaks=%d",
				requests, bytes, errors, scrubbed, len(srv.Gate().Leaks()))
		}
	}()

	sig := <-sigCh
	log.Printf("\n  Received %v, shutting down...", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("  Shutdown error: %v", err)
	}

	requests, bytes, errors, scrubbed := srv.GetStats()
	leaks := srv.Gate().Leaks()

	fmt.Println()
	fmt.Println("  ── Session Summary ──")
	fmt.Printf("  Requests:  %d\n", requests)
	fmt.Printf("  Bytes:     %d\n", bytes)
	fmt.Printf("  Errors:    %d\n", errors)
	fmt.Printf("  Scrubbed:  %d\n", scrubbed)
	fmt.Printf("  Leaks caught: %d\n", len(leaks))
	fmt.Println()
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

	if !cfg.VerifyTargetTLS {
		fmt.Println("  Warning: TLS verification disabled for upstream target")
	}

	fmt.Println()
}
