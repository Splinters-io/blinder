package har

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func assertRetirementExport(t *testing.T, path string, want int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	seen := map[string]int{}
	if err := streamHAREntries(f, func(e *Entry) error { seen[e.Request.URL]++; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(seen) != want {
		t.Fatalf("exported unique requests=%d want=%d: %v", len(seen), want, seen)
	}
	for target, count := range seen {
		if count != 1 {
			t.Errorf("request %s exported %d times", target, count)
		}
	}
}

func appendBrokenRetirementRecord(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.WriteString("broken journal record\n")
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("append broken fixture: write=%v close=%v", writeErr, closeErr)
	}
}

func TestHARPendingRetirementBlocksReplayAndNewJournalAppend(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		name := "remove"
		if corrupt {
			name = "corrupt_backup"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "capture.har")
			w := NewWriter(path, 1024, 100)
			persistenceRecord(w, 1, []byte("first request"))
			if err := w.FlushJournal(); err != nil {
				t.Fatal(err)
			}
			if corrupt {
				appendBrokenRetirementRecord(t, w.journalPath())
			}
			before, err := os.ReadFile(w.journalPath())
			if err != nil {
				t.Fatal(err)
			}
			failCleanup := true
			w.retireJournal = func(path, backup string) error {
				if failCleanup {
					return os.ErrPermission
				}
				return retireJournalFile(path, backup)
			}
			if err := w.Flush(); !errors.Is(err, os.ErrPermission) {
				t.Fatalf("cleanup failure not surfaced: %v", err)
			}
			assertRetirementExport(t, path, 1)
			persistenceRecord(w, 2, []byte("request arriving after commit"))
			for _, flush := range []func() error{w.FlushJournal, w.Flush, w.Flush} {
				if err := flush(); !errors.Is(err, os.ErrPermission) {
					t.Fatalf("pending cleanup was bypassed: %v", err)
				}
				assertRetirementExport(t, path, 1)
				after, err := os.ReadFile(w.journalPath())
				if err != nil || !bytes.Equal(before, after) || w.Len() != 1 {
					t.Fatalf("new evidence appended to committed journal: err=%v memory=%d", err, w.Len())
				}
			}
			failCleanup = false
			err = w.FlushJournal()
			if corrupt {
				if !errors.Is(err, ErrRecoveryIncomplete) || w.Len() != 0 {
					t.Fatalf("lost recovery warning or failed to journal newer evidence: err=%v memory=%d", err, w.Len())
				}
				backups, err := filepath.Glob(w.journalPath() + ".corrupt.*")
				if err != nil || len(backups) != 1 {
					t.Fatalf("corrupt evidence not backed up: %v %v", backups, err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			freshJournal, err := os.Open(w.journalPath())
			if err != nil {
				t.Fatal(err)
			}
			journalEntries := 0
			skipped, err := streamJournalEntries(freshJournal, func(e *Entry) error { journalEntries++; return nil })
			freshJournal.Close()
			if err != nil || skipped != 0 || journalEntries != 1 {
				t.Fatalf("new request not durably journaled after cleanup: count=%d skipped=%d err=%v", journalEntries, skipped, err)
			}
			for i := 0; i < 2; i++ {
				if err := w.Flush(); err != nil {
					t.Fatal(err)
				}
				assertRetirementExport(t, path, 2)
			}
		})
	}
}

func TestHARCorruptRecoveryRetriesOnlyPendingRetirement(t *testing.T) {
	for _, transientFailure := range []bool{false, true} {
		name := "successful_backup"
		if transientFailure {
			name = "retry_backup"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "capture.har")
			w := NewWriter(path, 1024, 100)
			persistenceRecord(w, 1, []byte("valid evidence"))
			if err := w.FlushJournal(); err != nil {
				t.Fatal(err)
			}
			appendBrokenRetirementRecord(t, w.journalPath())
			calls := 0
			w.retireJournal = func(path, backup string) error {
				calls++
				if transientFailure && calls == 1 {
					return os.ErrPermission
				}
				return retireJournalFile(path, backup)
			}
			if err := w.Flush(); !errors.Is(err, ErrRecoveryIncomplete) {
				t.Fatalf("recovery warning not surfaced: %v", err)
			}
			wantCalls := 1
			if transientFailure {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("unexpected cleanup retries: %d want=%d", calls, wantCalls)
			}
			assertRetirementExport(t, path, 1)
		})
	}
}
