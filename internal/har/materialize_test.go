package har

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type yieldBeforeReadReader struct {
	first, rest []byte
	yielded     *bool
}

func (r *yieldBeforeReadReader) Read(p []byte) (int, error) {
	if len(r.first) > 0 {
		n := copy(p, r.first)
		r.first = r.first[n:]
		return n, nil
	}
	if !*r.yielded {
		return 0, errors.New("read capture remainder before emitting first entry")
	}
	if len(r.rest) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.rest)
	r.rest = r.rest[n:]
	return n, nil
}

func TestHARMaterializationStreamsBeforeReadingRemainder(t *testing.T) {
	for _, journal := range []bool{false, true} {
		t.Run(fmt.Sprint(journal), func(t *testing.T) {
			yielded := false
			reader := &yieldBeforeReadReader{yielded: &yielded}
			first := `{"request":{"url":"https://fixture.invalid/one"}}`
			second := `{"request":{"url":"https://fixture.invalid/two"}}`
			if journal {
				reader.first = []byte(first + "\n")
				reader.rest = []byte(second + "\n")
			} else {
				reader.first = []byte(`{"log":{"creator":{"name":"fixture"},"entries":[` + first + ",")
				reader.rest = []byte(second + `],"extra":{"array":[1,true,null]}}}`)
			}
			var urls []string
			emit := func(e *Entry) error {
				yielded = true
				urls = append(urls, e.Request.URL)
				return nil
			}
			if journal {
				if skipped, err := streamJournalEntries(reader, emit); err != nil || skipped != 0 {
					t.Fatalf("journal buffered remainder: skipped=%d err=%v", skipped, err)
				}
			} else if err := streamHAREntries(reader, emit); err != nil {
				t.Fatalf("HAR buffered remainder: %v", err)
			}
			if len(urls) != 2 || urls[0] != "https://fixture.invalid/one" || urls[1] != "https://fixture.invalid/two" {
				t.Fatalf("entry order/content lost: %v", urls)
			}
		})
	}
}

func TestHARJournalStreamingAllowsLargeIndividualRecords(t *testing.T) {
	want := strings.Repeat("diagnostic ", 16*1024)
	encoded, err := json.Marshal(Entry{Response: Response{Content: Content{Text: want}}})
	if err != nil {
		t.Fatal(err)
	}
	var got string
	skipped, err := streamJournalEntries(bytes.NewReader(append(encoded, '\n')), func(e *Entry) error {
		got = e.Response.Content.Text
		return nil
	})
	if err != nil || skipped != 0 || got != want {
		t.Fatalf("record larger than a scanner buffer lost: skipped=%d err=%v bytes=%d", skipped, err, len(got))
	}
}

func persistenceRecord(w *Writer, id int, body []byte) {
	r := httptest.NewRequest("GET", fmt.Sprintf("https://fixture.invalid/record/%d", id), nil)
	response := &http.Response{StatusCode: 200, Status: "200 OK", Proto: "HTTP/1.1", Header: http.Header{"Content-Type": {"text/plain"}}}
	w.Record(r, nil, response, body, time.Millisecond)
}

func TestHARConcurrentJournalAppendAndMaterializationLoseNoEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.har")
	w := NewWriter(path, 8192, 10000)
	const seedCount, producerCount, perProducer = 64, 3, 40
	for i := 0; i < seedCount; i++ {
		persistenceRecord(w, i, bytes.Repeat([]byte("x"), 4096))
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errCh := make(chan error, producerCount+1)
	var wg sync.WaitGroup
	for producer := 0; producer < producerCount; producer++ {
		wg.Add(1)
		go func(producer int) {
			defer wg.Done()
			<-start
			for i := 0; i < perProducer; i++ {
				persistenceRecord(w, seedCount+producer*perProducer+i, []byte("diagnostic"))
				if err := w.FlushJournal(); err != nil {
					errCh <- err
					return
				}
			}
		}(producer)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 12; i++ {
			if err := w.Flush(); err != nil {
				errCh <- err
				return
			}
		}
	}()
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	if t.Failed() {
		t.FailNow()
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	seen := make(map[string]int)
	if err := streamHAREntries(f, func(e *Entry) error { seen[e.Request.URL]++; return nil }); err != nil {
		t.Fatal(err)
	}
	const total = seedCount + producerCount*perProducer
	if len(seen) != total {
		t.Fatalf("concurrent export lost evidence: unique entries=%d want=%d", len(seen), total)
	}
	for target, count := range seen {
		if count != 1 {
			t.Errorf("export duplicated %s %d times", target, count)
		}
	}
}

func TestHARCorruptTailDoesNotRetainPartiallyStreamedEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.har")
	old := []byte(`{"log":{"entries":[{"request":{"url":"https://fixture.invalid/old"}},`)
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	w := NewWriter(path, 1024, 100)
	persistenceRecord(w, 1, []byte("new"))
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var exported HARFile
	if err := json.Unmarshal(data, &exported); err != nil {
		t.Fatal(err)
	}
	if len(exported.Log.Entries) != 1 || exported.Log.Entries[0].Request.URL != "https://fixture.invalid/record/1" {
		t.Fatalf("tentative entries from corrupt prior capture survived: %+v", exported.Log.Entries)
	}
	backups, err := filepath.Glob(path + ".corrupt.*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("corrupt source backup missing: %v %v", backups, err)
	}
	backup, err := os.ReadFile(backups[0])
	if err != nil || !bytes.Equal(backup, old) {
		t.Fatal("corrupt source evidence not preserved verbatim")
	}
}

func TestHARJournalReadFailureDoesNotCommitExport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.har")
	w := NewWriter(path, 1024, 100)
	persistenceRecord(w, 1, []byte("retained"))
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := os.Mkdir(w.journalPath(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err == nil {
		t.Fatal("journal read error silently accepted as an empty journal")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed journal read replaced the last successful export")
	}
	if _, err := os.Stat(w.journalPath()); err != nil {
		t.Fatalf("failed journal input removed: %v", err)
	}
}

func TestHARJournalAppendAfterPartialTailPreservesNewRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partial.har")
	w := NewWriter(path, 1024, 100)
	broken := []byte(`{"request":{"url":"truncated`)
	if err := os.WriteFile(w.journalPath(), broken, 0600); err != nil {
		t.Fatal(err)
	}
	persistenceRecord(w, 1, []byte("new record"))
	if err := w.Flush(); err == nil || !strings.Contains(err.Error(), "1 record(s) unreadable") {
		t.Fatalf("partial tail should be reported independently: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var exported HARFile
	if err := json.Unmarshal(data, &exported); err != nil {
		t.Fatal(err)
	}
	if len(exported.Log.Entries) != 1 || exported.Log.Entries[0].Request.URL != "https://fixture.invalid/record/1" {
		t.Fatalf("valid new record became part of corrupt tail: %+v", exported.Log.Entries)
	}
	backups, err := filepath.Glob(w.journalPath() + ".corrupt.*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("corrupt journal backup missing: %v %v", backups, err)
	}
	backup, err := os.ReadFile(backups[0])
	if err != nil || !bytes.HasPrefix(backup, append(broken, '\n')) {
		t.Fatal("corrupt tail was not preserved with a distinct record boundary")
	}
}

func TestHARFailedSnapshotAppendRollsBackBeforeRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "retry.har")
	w := NewWriter(path, 1024, 100)
	persistenceRecord(w, 0, []byte("already journaled"))
	if err := w.FlushJournal(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(w.journalPath())
	if err != nil {
		t.Fatal(err)
	}
	persistenceRecord(w, 1, []byte("valid snapshot prefix"))
	persistenceRecord(w, 2, []byte("temporarily unencodable"))
	// Force encoding to fail only after a complete first entry reached disk.
	// The rollback path is shared by encoder, write and close failures.
	w.mu.Lock()
	w.entries[1].Time = math.NaN()
	w.mu.Unlock()
	if err := w.FlushJournal(); err == nil {
		t.Fatal("fixture did not interrupt the snapshot append")
	}
	after, err := os.ReadFile(w.journalPath())
	if err != nil || !bytes.Equal(before, after) || w.Len() != 2 {
		t.Fatalf("failed snapshot prefix remained or memory was cleared: err=%v entries=%d", err, w.Len())
	}
	w.mu.Lock()
	w.entries[1].Time = 1
	w.mu.Unlock()
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	seen := map[string]int{}
	if err := streamHAREntries(f, func(e *Entry) error { seen[e.Request.URL]++; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 {
		t.Fatalf("retry lost entries: %v", seen)
	}
	for target, count := range seen {
		if count != 1 {
			t.Errorf("retry duplicated %s %d times", target, count)
		}
	}
}

func TestCaptureBudgetLimitsOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "budget.har")
	w := NewWriter(path, 1024, 1000)
	w.SetCaptureBudget(3)

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", fmt.Sprintf("https://target.invalid/%d", i), nil)
		resp := &http.Response{StatusCode: 200, Status: "200 OK", Header: http.Header{}, Proto: "HTTP/1.1"}
		w.Record(req, nil, resp, nil, time.Millisecond)
	}

	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file HARFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Log.Entries) != 3 {
		t.Errorf("capture budget should cap at 3 entries, got %d", len(file.Log.Entries))
	}
}

func TestFlushRetryOnTransientFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retry.har")
	w := NewWriter(path, 1024, 1000)
	cleanupCalls := 0
	w.retireJournal = func(path, backup string) error {
		cleanupCalls++
		if cleanupCalls == 1 {
			return os.ErrPermission
		}
		return retireJournalFile(path, backup)
	}

	req := httptest.NewRequest("GET", "https://target.invalid/page", nil)
	resp := &http.Response{StatusCode: 200, Status: "200 OK", Header: http.Header{}, Proto: "HTTP/1.1"}
	w.Record(req, nil, resp, nil, time.Millisecond)

	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file HARFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Log.Entries) != 1 {
		t.Errorf("expected 1 entry after retry-capable flush, got %d", len(file.Log.Entries))
	}
	if cleanupCalls != 2 {
		t.Fatalf("cleanup retry was not exercised: calls=%d", cleanupCalls)
	}
}

func TestNewWriterMaxEntriesDefault(t *testing.T) {
	w := NewWriter("", 1024, 0)
	if w.maxEntries != 50000 {
		t.Errorf("expected default maxEntries 50000, got %d", w.maxEntries)
	}
}

func TestNewWriterMaxEntriesConfigured(t *testing.T) {
	w := NewWriter("", 1024, 500)
	if w.maxEntries != 500 {
		t.Errorf("expected configured maxEntries 500, got %d", w.maxEntries)
	}
}
