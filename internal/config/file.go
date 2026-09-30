package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type FileConfig struct {
	Listen        string   `yaml:"listen"`
	Target        string   `yaml:"target"`
	Alias         string   `yaml:"alias"`
	Identity      []string `yaml:"identity"`
	ExtraOrigins  []string `yaml:"extra_origins"`
	Output        string   `yaml:"output"`
	CertDir       string   `yaml:"cert_dir"`
	CaptchaConfig string   `yaml:"captcha_config"`
	Tor           struct {
		Enabled bool   `yaml:"enabled"`
		Addr    string `yaml:"addr"`
	} `yaml:"tor"`
	HAR struct {
		Path          string `yaml:"path"`
		MaxBody       int64  `yaml:"max_body"`
		MaxEntries    int    `yaml:"max_entries"`
		CaptureBudget int    `yaml:"capture_budget"`
	} `yaml:"har"`
	NoVerifyTLS     bool `yaml:"no_verify_tls"`
	Paranoid        bool `yaml:"paranoid"`
	PreserveContent bool `yaml:"preserve_content"`
	BindAll         bool `yaml:"bind_all"`
}

func LoadFile(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}

	fc := &FileConfig{}
	if err := yaml.Unmarshal(data, fc); err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}
	har := &HARConfig{MaxEntries: fc.HAR.MaxEntries, CaptureBudget: fc.HAR.CaptureBudget}
	if err := har.Validate(); err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}

	return fc, nil
}
