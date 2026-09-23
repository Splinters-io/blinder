package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

type TorConfig struct {
	SOCKSAddr string
}

type HARConfig struct {
	FilePath    string
	MaxBodySize int64
}

type Config struct {
	TargetURL       *url.URL
	ListenAddr      string
	AliasDomain     string
	IdentityTokens  []string
	VerifyTargetTLS bool
	Paranoid        bool
	BindAll         bool
	Tor             *TorConfig
	HAR             *HARConfig
	OutputDir       string
	CertDir         string
	UpstreamTimeout int
	ClientTimeout   int
}

var (
	ErrNoTarget        = errors.New("--target is required")
	ErrBadScheme       = errors.New("target must use http or https scheme")
	ErrOnionRequiresTor = errors.New(".onion targets require --tor")
	ErrShortToken      = errors.New("identity tokens must be at least 3 characters")
	ErrTooManyTokens   = errors.New("maximum 100 identity tokens")
	ErrNonLoopback     = errors.New("binding to non-loopback address requires --bind-all")
)

var allowedSchemes = map[string]bool{
	"http":  true,
	"https": true,
}

func New(
	target string,
	listen string,
	alias string,
	tokens []string,
	verifyTLS bool,
	paranoid bool,
	bindAll bool,
	torAddr string,
	harPath string,
	harMaxBody int64,
	outputDir string,
	certDir string,
	upstreamTimeout int,
	clientTimeout int,
) (*Config, error) {
	if target == "" {
		return nil, ErrNoTarget
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	if !allowedSchemes[u.Scheme] {
		return nil, ErrBadScheme
	}

	isOnion := strings.HasSuffix(u.Hostname(), ".onion")
	if isOnion && torAddr == "" {
		return nil, ErrOnionRequiresTor
	}

	if len(tokens) > 100 {
		return nil, ErrTooManyTokens
	}
	for _, t := range tokens {
		if len(t) < 3 {
			return nil, fmt.Errorf("%w: %q", ErrShortToken, t)
		}
	}

	if listen == "" {
		listen = "127.0.0.1:8099"
	}

	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, fmt.Errorf("invalid listen address: %w", err)
	}

	if !bindAll {
		ip := net.ParseIP(host)
		if ip != nil && !ip.IsLoopback() {
			return nil, ErrNonLoopback
		}
		if host != "localhost" && ip == nil {
			return nil, ErrNonLoopback
		}
	}

	if alias == "" {
		alias = "target-001.local"
	}

	tokensCopy := make([]string, len(tokens))
	copy(tokensCopy, tokens)

	var tor *TorConfig
	if torAddr != "" {
		tor = &TorConfig{SOCKSAddr: torAddr}
	}

	var har *HARConfig
	if harPath != "" {
		if harMaxBody <= 0 {
			harMaxBody = 10 * 1024 * 1024
		}
		har = &HARConfig{
			FilePath:    harPath,
			MaxBodySize: harMaxBody,
		}
	}

	if upstreamTimeout <= 0 {
		upstreamTimeout = 30
	}
	if clientTimeout <= 0 {
		clientTimeout = 60
	}

	return &Config{
		TargetURL:       u,
		ListenAddr:      listen,
		AliasDomain:     alias,
		IdentityTokens:  tokensCopy,
		VerifyTargetTLS: verifyTLS,
		Paranoid:        paranoid,
		BindAll:         bindAll,
		Tor:             tor,
		HAR:             har,
		OutputDir:       outputDir,
		CertDir:         certDir,
		UpstreamTimeout: upstreamTimeout,
		ClientTimeout:   clientTimeout,
	}, nil
}

func (c *Config) IsOnion() bool {
	return strings.HasSuffix(c.TargetURL.Hostname(), ".onion")
}

func (c *Config) UseTor() bool {
	return c.Tor != nil
}
