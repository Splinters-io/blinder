package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Splinters-io/blinder/internal/metadata"
)

type RequestEntry struct {
	Path       string           `json:"path"`
	StatusCode int              `json:"status_code"`
	ScrubCount int              `json:"scrub_count"` // Identity/domain matches replaced for this request.
	LeakCount  int              `json:"leak_count"`  // -1 when residual identity leakage has not been measured.
	Timestamp  string           `json:"timestamp"`
	Response   *ResponseMetrics `json:"response,omitempty"`
}

// BodyRead measures payload bytes, excluding HTTP framing and TLS overhead.
// -1 means unavailable. Incomplete reads report observed bytes, not a total.
type BodyRead struct {
	StatusCode   int    `json:"status_code"`
	EncodedBytes int64  `json:"encoded_bytes"`
	DecodedBytes int64  `json:"decoded_bytes"`
	Complete     bool   `json:"complete"`
	Error        string `json:"error,omitempty"`
}

type ResponseMetrics struct {
	Source             string     `json:"source"`
	Upstream           []BodyRead `json:"upstream"`
	OriginalBodyTag    string     `json:"original_body_tag,omitempty"`
	OriginalBodyBytes  int64      `json:"original_body_bytes"`
	RewrittenBodyBytes int64      `json:"rewritten_body_bytes"`
	DownstreamBytes    int64      `json:"downstream_body_bytes"`
	RewriteDeltaBytes  *int64     `json:"rewrite_delta_bytes"`
}

func cloneResponse(m *ResponseMetrics) *ResponseMetrics {
	if m == nil {
		return nil
	}
	copy := *m
	copy.Upstream = append([]BodyRead{}, m.Upstream...)
	if m.RewriteDeltaBytes != nil {
		n := *m.RewriteDeltaBytes
		copy.RewriteDeltaBytes = &n
	}
	return &copy
}

type LeakEntry struct {
	Type    string `json:"type"`
	Context string `json:"context"`
	Value   string `json:"value"`
}

type IdentityEntry struct {
	Path      string `json:"path"`
	Format    string `json:"format"`
	Author    string `json:"author,omitempty"`
	Title     string `json:"title,omitempty"`
	Company   string `json:"company,omitempty"`
	Copyright string `json:"copyright,omitempty"`
	GPS       string `json:"gps,omitempty"`
	Camera    string `json:"camera,omitempty"`
}

type ManifestFile struct {
	Version       string          `json:"version"`
	AliasDomain   string          `json:"alias_domain"`
	TargetURL     string          `json:"target_url"`
	StartedAt     string          `json:"started_at"`
	EndedAt       string          `json:"ended_at"`
	DurationMS    float64         `json:"duration_ms"`
	Requests      []RequestEntry  `json:"requests"`
	IdentityVault []IdentityEntry `json:"identity_vault"`
}

type SRIFinding struct {
	URL               string `json:"url"`
	UpstreamValid     bool   `json:"upstream_valid"`
	UpstreamError     string `json:"upstream_error,omitempty"`
	OriginalIntegrity string `json:"original_integrity"`
	ReplacementHash   string `json:"replacement_hash,omitempty"`
	Transformed       bool   `json:"transformed"`
}

type ScrubReport struct {
	TotalLeaks int            `json:"total_leaks"`
	ByType     map[string]int `json:"by_type"`
	ByContext  map[string]int `json:"by_context"`
	Entries    []LeakEntry    `json:"entries"`
}

type Session struct {
	aliasDomain string
	targetURL   string
	startedAt   time.Time
	mu          sync.Mutex
	requests    []RequestEntry
	aliases     map[string]string // alias → real
	leaks       []LeakEntry
	identity    []IdentityEntry
	sriFindings []SRIFinding
}

func NewSession(aliasDomain, targetURL string) *Session {
	return &Session{
		aliasDomain: aliasDomain,
		targetURL:   targetURL,
		startedAt:   time.Now(),
		aliases:     make(map[string]string),
	}
}

func (s *Session) AliasDomain() string {
	return s.aliasDomain
}

func (s *Session) RecordRequest(path string, statusCode, scrubCount, leakCount int, response ...ResponseMetrics) {
	entry := RequestEntry{
		Path:       path,
		StatusCode: statusCode,
		ScrubCount: scrubCount,
		LeakCount:  leakCount,
		Timestamp:  time.Now().Format(time.RFC3339Nano),
	}
	if len(response) > 0 {
		entry.Response = cloneResponse(&response[0])
	}

	s.mu.Lock()
	s.requests = append(s.requests, entry)
	s.mu.Unlock()
}

func (s *Session) RecordDomainAlias(real, alias string) {
	s.mu.Lock()
	s.aliases[alias] = real
	s.mu.Unlock()
}

func (s *Session) RecordLeak(leakType, context, value string) {
	entry := LeakEntry{
		Type:    leakType,
		Context: context,
		Value:   value,
	}

	s.mu.Lock()
	s.leaks = append(s.leaks, entry)
	s.mu.Unlock()
}

// ReplaceLeaks installs the current gate snapshot, so repeated flushes do not
// multiply findings that were already written.
func (s *Session) ReplaceLeaks(entries []LeakEntry) {
	s.mu.Lock()
	s.leaks = append([]LeakEntry(nil), entries...)
	s.mu.Unlock()
}

func (s *Session) RecordIdentity(path string, meta *metadata.Result) {
	if meta == nil {
		return
	}

	id := meta.Identity
	if id.Author == "" && id.Title == "" && id.Company == "" && id.Copyright == "" && id.GPS == "" && id.Camera == "" {
		return
	}

	entry := IdentityEntry{
		Path:      path,
		Format:    meta.Format,
		Author:    id.Author,
		Title:     id.Title,
		Company:   id.Company,
		Copyright: id.Copyright,
		GPS:       id.GPS,
		Camera:    id.Camera,
	}

	s.mu.Lock()
	s.identity = append(s.identity, entry)
	s.mu.Unlock()
}

func (s *Session) RecordSRIFinding(url string, valid bool, upstreamErr, originalIntegrity, replacementHash string, transformed bool) {
	entry := SRIFinding{
		URL:               url,
		UpstreamValid:     valid,
		UpstreamError:     upstreamErr,
		OriginalIntegrity: originalIntegrity,
		ReplacementHash:   replacementHash,
		Transformed:       transformed,
	}
	s.mu.Lock()
	s.sriFindings = append(s.sriFindings, entry)
	s.mu.Unlock()
}

func (s *Session) SRIFindings() []SRIFinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]SRIFinding, len(s.sriFindings))
	copy(result, s.sriFindings)
	return result
}

func (s *Session) Requests() []RequestEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]RequestEntry, len(s.requests))
	copy(result, s.requests)
	for i := range result {
		result[i].Response = cloneResponse(result[i].Response)
	}
	return result
}

func (s *Session) DomainAliases() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]string, len(s.aliases))
	for k, v := range s.aliases {
		result[k] = v
	}
	return result
}

func (s *Session) Leaks() []LeakEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]LeakEntry, len(s.leaks))
	copy(result, s.leaks)
	return result
}

func (s *Session) IdentityVault() []IdentityEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]IdentityEntry, len(s.identity))
	copy(result, s.identity)
	return result
}

func (s *Session) Flush(dir string) error {
	now := time.Now()

	s.mu.Lock()
	requests := make([]RequestEntry, len(s.requests))
	copy(requests, s.requests)
	aliases := make(map[string]string, len(s.aliases))
	for k, v := range s.aliases {
		aliases[k] = v
	}
	leaks := make([]LeakEntry, len(s.leaks))
	copy(leaks, s.leaks)
	identity := make([]IdentityEntry, len(s.identity))
	copy(identity, s.identity)
	sriFindings := make([]SRIFinding, len(s.sriFindings))
	copy(sriFindings, s.sriFindings)
	s.mu.Unlock()

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	manifest := ManifestFile{
		Version:       "2.0.0",
		AliasDomain:   s.aliasDomain,
		TargetURL:     s.targetURL,
		StartedAt:     s.startedAt.Format(time.RFC3339Nano),
		EndedAt:       now.Format(time.RFC3339Nano),
		DurationMS:    float64(now.Sub(s.startedAt).Milliseconds()),
		Requests:      requests,
		IdentityVault: identity,
	}

	if err := writeAtomicJSON(filepath.Join(dir, "blinder-manifest.json"), manifest); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	if err := writeAtomicJSON(filepath.Join(dir, "blinder-dealias.json"), aliases); err != nil {
		return fmt.Errorf("write dealias: %w", err)
	}

	report := buildScrubReport(leaks)
	if err := writeAtomicJSON(filepath.Join(dir, "blinder-scrub-report.json"), report); err != nil {
		return fmt.Errorf("write scrub report: %w", err)
	}

	if len(sriFindings) > 0 {
		if err := writeAtomicJSON(filepath.Join(dir, "blinder-sri-findings.json"), sriFindings); err != nil {
			return fmt.Errorf("write SRI findings: %w", err)
		}
	}

	return nil
}

func buildScrubReport(leaks []LeakEntry) ScrubReport {
	byType := make(map[string]int)
	byContext := make(map[string]int)

	for _, leak := range leaks {
		byType[leak.Type]++
		byContext[leak.Context]++
	}

	return ScrubReport{
		TotalLeaks: len(leaks),
		ByType:     byType,
		ByContext:  byContext,
		Entries:    leaks,
	}
}

func writeAtomicJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".blinder-manifest-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}

	return nil
}
