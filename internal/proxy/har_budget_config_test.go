package proxy

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/Splinters-io/blinder/internal/config"
)

func TestProxyRejectsNegativeEmbeddedHARBudgets(t *testing.T) {
	for _, tc := range []struct {
		field string
		har   config.HARConfig
	}{
		{"max_entries", config.HARConfig{MaxEntries: -1}},
		{"capture_budget", config.HARConfig{CaptureBudget: -1}},
	} {
		t.Run(tc.field, func(t *testing.T) {
			cfg := newTestConfig(t, "https://fixture.invalid")
			cfg.HAR = &tc.har
			srv, err := NewWithCertificate(cfg, tls.Certificate{})
			if srv != nil || err == nil || !strings.Contains(err.Error(), "har."+tc.field) {
				t.Fatalf("invalid embedded budget not rejected: server=%v error=%v", srv != nil, err)
			}
		})
	}
}
