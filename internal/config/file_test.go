package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHARConfigValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		har  *HARConfig
		bad  bool
	}{
		{"disabled", nil, false},
		{"defaults", &HARConfig{}, false},
		{"configured", &HARConfig{MaxEntries: 7, CaptureBudget: 23}, false},
		{"negative_entries", &HARConfig{MaxEntries: -1}, true},
		{"negative_budget", &HARConfig{CaptureBudget: -1}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.har.Validate(); (err != nil) != tc.bad {
				t.Fatalf("HAR validation error=%v wantError=%v", err, tc.bad)
			}
		})
	}
}

func TestLoadFileRejectsNegativeHARBudgets(t *testing.T) {
	for _, field := range []string{"max_entries", "capture_budget"} {
		t.Run(field, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte("har:\n  path: capture.har\n  "+field+": -1\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "har."+field) {
				t.Fatalf("invalid bound did not identify its YAML field: %v", err)
			}
		})
	}
}

func TestLoadFilePreservesHARBudgetsAndDefaults(t *testing.T) {
	for _, tc := range []struct {
		name, yaml      string
		entries, budget int
	}{
		{"configured", "har:\n  path: capture.har\n  max_entries: 7\n  capture_budget: 23\n", 7, 23},
		{"explicit_zero", "har:\n  path: capture.har\n  max_entries: 0\n  capture_budget: 0\n", 0, 0},
		{"omitted", "har:\n  path: capture.har\n", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := LoadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got.HAR.MaxEntries != tc.entries || got.HAR.CaptureBudget != tc.budget {
				t.Fatalf("HAR budgets changed: %+v", got.HAR)
			}
		})
	}
}
