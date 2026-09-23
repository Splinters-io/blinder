package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Splinters-io/blinder/internal/metadata"
)

func TestNewSession(t *testing.T) {
	s := NewSession("target-001.local", "https://example.com")

	if s.AliasDomain() != "target-001.local" {
		t.Errorf("expected alias domain 'target-001.local', got %q", s.AliasDomain())
	}
}

func TestRecordRequest(t *testing.T) {
	s := NewSession("target-001.local", "https://example.com")

	s.RecordRequest("/api/users", 200, 3, 0)

	if len(s.Requests()) != 1 {
		t.Fatalf("expected 1 request, got %d", len(s.Requests()))
	}
	req := s.Requests()[0]
	if req.Path != "/api/users" {
		t.Errorf("expected path '/api/users', got %q", req.Path)
	}
	if req.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", req.StatusCode)
	}
	if req.ScrubCount != 3 {
		t.Errorf("expected 3 scrubs, got %d", req.ScrubCount)
	}
}

func TestRecordDomainAlias(t *testing.T) {
	s := NewSession("target-001.local", "https://example.com")

	s.RecordDomainAlias("example.com", "host-abc12345.target-001.local")
	s.RecordDomainAlias("cdn.example.com", "host-def67890.target-001.local")

	aliases := s.DomainAliases()
	if len(aliases) != 2 {
		t.Fatalf("expected 2 aliases, got %d", len(aliases))
	}
	if aliases["host-abc12345.target-001.local"] != "example.com" {
		t.Error("expected alias→real mapping for example.com")
	}
}

func TestRecordDomainAlias_NoDuplicates(t *testing.T) {
	s := NewSession("target-001.local", "https://example.com")

	s.RecordDomainAlias("example.com", "host-abc12345.target-001.local")
	s.RecordDomainAlias("example.com", "host-abc12345.target-001.local")

	aliases := s.DomainAliases()
	if len(aliases) != 1 {
		t.Errorf("expected 1 unique alias, got %d", len(aliases))
	}
}

func TestRecordLeak(t *testing.T) {
	s := NewSession("target-001.local", "https://example.com")

	s.RecordLeak("domain", "body:html:/", "example.com")
	s.RecordLeak("domain", "body:html:/", "cdn.example.com")
	s.RecordLeak("email", "body:json:/api", "admin@example.com")

	leaks := s.Leaks()
	if len(leaks) != 3 {
		t.Fatalf("expected 3 leaks, got %d", len(leaks))
	}
}

func TestRecordIdentity(t *testing.T) {
	s := NewSession("target-001.local", "https://example.com")

	meta := &metadata.Result{
		Format: "pdf",
		Identity: metadata.IdentityFields{
			Author: "John Smith",
			Title:  "Confidential Report",
		},
	}
	s.RecordIdentity("/doc.pdf", meta)

	vault := s.IdentityVault()
	if len(vault) != 1 {
		t.Fatalf("expected 1 vault entry, got %d", len(vault))
	}
	if vault[0].Path != "/doc.pdf" {
		t.Errorf("expected path '/doc.pdf', got %q", vault[0].Path)
	}
	if vault[0].Author != "John Smith" {
		t.Errorf("expected author 'John Smith', got %q", vault[0].Author)
	}
}

func TestFlush_CreatesThreeFiles(t *testing.T) {
	s := NewSession("target-001.local", "https://example.com")

	s.RecordRequest("/", 200, 2, 0)
	s.RecordDomainAlias("example.com", "host-abc12345.target-001.local")
	s.RecordLeak("domain", "body:html:/", "example.com")

	dir := t.TempDir()

	err := s.Flush(dir)
	if err != nil {
		t.Fatalf("flush: %v", err)
	}

	files := []string{
		"blinder-manifest.json",
		"blinder-dealias.json",
		"blinder-scrub-report.json",
	}
	for _, name := range files {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected file %s: %v", name, err)
		}
	}
}

func TestFlush_ManifestStructure(t *testing.T) {
	s := NewSession("target-001.local", "https://example.com")
	s.RecordRequest("/api", 200, 1, 0)

	dir := t.TempDir()
	s.Flush(dir)

	data, _ := os.ReadFile(filepath.Join(dir, "blinder-manifest.json"))
	var manifest ManifestFile
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}

	if manifest.Version != "2.0.0" {
		t.Errorf("expected version '2.0.0', got %q", manifest.Version)
	}
	if manifest.AliasDomain != "target-001.local" {
		t.Errorf("expected alias domain 'target-001.local', got %q", manifest.AliasDomain)
	}
	if len(manifest.Requests) != 1 {
		t.Errorf("expected 1 request, got %d", len(manifest.Requests))
	}
}

func TestFlush_DealiasMap(t *testing.T) {
	s := NewSession("target-001.local", "https://example.com")
	s.RecordDomainAlias("example.com", "host-abc12345.target-001.local")
	s.RecordDomainAlias("cdn.example.com", "host-def67890.target-001.local")

	dir := t.TempDir()
	s.Flush(dir)

	data, _ := os.ReadFile(filepath.Join(dir, "blinder-dealias.json"))
	var dealias map[string]string
	if err := json.Unmarshal(data, &dealias); err != nil {
		t.Fatalf("parse dealias: %v", err)
	}

	if dealias["host-abc12345.target-001.local"] != "example.com" {
		t.Error("expected dealias entry for example.com")
	}
	if dealias["host-def67890.target-001.local"] != "cdn.example.com" {
		t.Error("expected dealias entry for cdn.example.com")
	}
}

func TestFlush_ScrubReport(t *testing.T) {
	s := NewSession("target-001.local", "https://example.com")
	s.RecordLeak("domain", "body:html:/", "example.com")
	s.RecordLeak("domain", "body:html:/about", "example.com")
	s.RecordLeak("email", "body:json:/api", "admin@example.com")

	dir := t.TempDir()
	s.Flush(dir)

	data, _ := os.ReadFile(filepath.Join(dir, "blinder-scrub-report.json"))
	var report ScrubReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parse scrub report: %v", err)
	}

	if report.TotalLeaks != 3 {
		t.Errorf("expected 3 total leaks, got %d", report.TotalLeaks)
	}
	if report.ByType["domain"] != 2 {
		t.Errorf("expected 2 domain leaks, got %d", report.ByType["domain"])
	}
	if report.ByType["email"] != 1 {
		t.Errorf("expected 1 email leak, got %d", report.ByType["email"])
	}
}

func TestFlush_SessionTiming(t *testing.T) {
	s := NewSession("target-001.local", "https://example.com")

	time.Sleep(10 * time.Millisecond)

	dir := t.TempDir()
	s.Flush(dir)

	data, _ := os.ReadFile(filepath.Join(dir, "blinder-manifest.json"))
	var manifest ManifestFile
	json.Unmarshal(data, &manifest)

	if manifest.StartedAt == "" {
		t.Error("expected non-empty StartedAt")
	}
	if manifest.EndedAt == "" {
		t.Error("expected non-empty EndedAt")
	}
	if manifest.DurationMS <= 0 {
		t.Errorf("expected positive duration, got %f", manifest.DurationMS)
	}
}

func TestFlush_IdentityVaultInManifest(t *testing.T) {
	s := NewSession("target-001.local", "https://example.com")
	meta := &metadata.Result{
		Format: "pdf",
		Identity: metadata.IdentityFields{
			Author:  "Jane Doe",
			Company: "SecretCorp",
		},
	}
	s.RecordIdentity("/report.pdf", meta)

	dir := t.TempDir()
	s.Flush(dir)

	data, _ := os.ReadFile(filepath.Join(dir, "blinder-manifest.json"))
	var manifest ManifestFile
	json.Unmarshal(data, &manifest)

	if len(manifest.IdentityVault) != 1 {
		t.Fatalf("expected 1 identity vault entry, got %d", len(manifest.IdentityVault))
	}
	if manifest.IdentityVault[0].Author != "Jane Doe" {
		t.Error("expected author 'Jane Doe' in identity vault")
	}
	if manifest.IdentityVault[0].Company != "SecretCorp" {
		t.Error("expected company 'SecretCorp' in identity vault")
	}
}
