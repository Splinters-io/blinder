package har

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

var errInvalidHAR = errors.New("invalid existing HAR")

// ErrRecoveryIncomplete indicates that HAR data was written successfully but
// some journal records were unreadable and have been preserved as a backup.
var ErrRecoveryIncomplete = errors.New("journal recovery incomplete")

type journalRetirement struct {
	path, backup string
	skipped      int
}

// retireJournalLocked completes an already committed export. Keeping this phase
// separate prevents a failed cleanup from causing replay on a later Flush. The
// checkpoint is in memory: a process crash between HAR rename and retirement
// still requires external recovery to distinguish an already exported journal.
func (w *Writer) retireJournalLocked() error {
	pending := w.pendingJournal
	if pending == nil {
		return nil
	}
	retire := w.retireJournal
	if retire == nil {
		retire = retireJournalFile
	}
	if err := retire(pending.path, pending.backup); err != nil {
		return err
	}
	w.pendingJournal = nil
	if pending.skipped > 0 {
		return fmt.Errorf("%w: %d record(s) unreadable, journal preserved as %s", ErrRecoveryIncomplete, pending.skipped, filepath.Base(pending.backup))
	}
	return nil
}

func retireJournalFile(path, backup string) error {
	if backup != "" {
		if err := os.Rename(path, backup); err != nil {
			return fmt.Errorf("preserve corrupt journal: %w", err)
		}
	} else if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove exported journal: %w", err)
	}
	return nil
}

// materialize requires flushMu. It holds at most one decoded HAR entry or one
// journal record, rather than retaining either full capture file in memory.
func (w *Writer) materialize(path string) error {
	if w.pendingJournal != nil {
		return w.retireJournalLocked()
	}
	w.mu.Lock()
	budget := w.captureBudget
	w.mu.Unlock()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".blinder-har-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpPath)
	}()
	const header = "{\n  \"log\": {\n    \"version\": \"1.2\",\n    \"creator\": { \"name\": \"blinder\", \"version\": \"2.0.0\" },\n    \"entries\": [\n"
	if _, err := tmp.WriteString(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	written := 0
	writeEntry := func(e *Entry) error {
		if budget > 0 && written >= budget {
			return nil
		}
		if written > 0 {
			if _, err := tmp.WriteString(",\n"); err != nil {
				return err
			}
		}
		data, err := json.MarshalIndent(e, "      ", "  ")
		if err != nil {
			return err
		}
		if _, err := tmp.Write(append([]byte("      "), data...)); err != nil {
			return err
		}
		written++
		return nil
	}
	if existing, err := os.Open(path); err == nil {
		readErr := streamHAREntries(existing, writeEntry)
		closeErr := existing.Close()
		if readErr != nil {
			if !errors.Is(readErr, errInvalidHAR) {
				return fmt.Errorf("stream existing: %w", readErr)
			}
			// Match the prior corruption policy: preserve the entire damaged file
			// and discard any entries tentatively streamed from it.
			backup := path + ".corrupt." + time.Now().Format("20060102-150405.000000000")
			if err := os.Rename(path, backup); err != nil {
				return fmt.Errorf("preserve corrupt HAR: %w", err)
			}
			if err := tmp.Truncate(int64(len(header))); err != nil {
				return fmt.Errorf("reset corrupt HAR output: %w", err)
			}
			if _, err := tmp.Seek(int64(len(header)), io.SeekStart); err != nil {
				return fmt.Errorf("reset corrupt HAR position: %w", err)
			}
			written = 0
		} else if closeErr != nil {
			return fmt.Errorf("close existing HAR: %w", closeErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("open existing HAR: %w", err)
	}
	jpath := w.journalPath()
	skipped := 0
	if journal, err := os.Open(jpath); err == nil {
		var readErr error
		skipped, readErr = streamJournalEntries(journal, writeEntry)
		closeErr := journal.Close()
		if readErr != nil {
			return fmt.Errorf("stream journal: %w", readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close journal: %w", closeErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("open journal: %w", err)
	}
	if _, err := tmp.WriteString("\n    ]\n  }\n}\n"); err != nil {
		return fmt.Errorf("write footer: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	w.pendingJournal = &journalRetirement{path: jpath, skipped: skipped}
	if skipped > 0 {
		w.pendingJournal.backup = jpath + ".corrupt." + time.Now().Format("20060102-150405.000000000")
	}
	return w.retireJournalLocked()
}

func streamJournalEntries(input io.Reader, emit func(*Entry) error) (int, error) {
	reader := bufio.NewReader(input)
	skipped := 0
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return skipped, err
		}
		line = bytes.TrimSpace(line)
		if len(line) > 0 {
			var e Entry
			if json.Unmarshal(line, &e) != nil {
				skipped++
			} else if writeErr := emit(&e); writeErr != nil {
				return skipped, writeErr
			}
		}
		if errors.Is(err, io.EOF) {
			return skipped, nil
		}
	}
}

func streamHAREntries(input io.Reader, emit func(*Entry) error) error {
	dec := json.NewDecoder(input)
	dec.UseNumber()
	if err := expectHARDelimiter(dec, '{'); err != nil {
		return err
	}
	seenLog := false
	for dec.More() {
		name, err := dec.Token()
		if err != nil {
			return harDecodeError(err)
		}
		if name == "log" {
			if seenLog {
				return errInvalidHAR
			}
			seenLog = true
			if err := streamHARLog(dec, emit); err != nil {
				return err
			}
		} else if err := skipHARValue(dec); err != nil {
			return err
		}
	}
	if !seenLog {
		return errInvalidHAR
	}
	if err := expectHARDelimiter(dec, '}'); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err != nil {
			return harDecodeError(err)
		}
		return errInvalidHAR
	}
	return nil
}

func streamHARLog(dec *json.Decoder, emit func(*Entry) error) error {
	if err := expectHARDelimiter(dec, '{'); err != nil {
		return err
	}
	seenEntries := false
	for dec.More() {
		name, err := dec.Token()
		if err != nil {
			return harDecodeError(err)
		}
		if name != "entries" {
			if err := skipHARValue(dec); err != nil {
				return err
			}
			continue
		}
		if seenEntries {
			return errInvalidHAR
		}
		seenEntries = true
		if err := expectHARDelimiter(dec, '['); err != nil {
			return err
		}
		for dec.More() {
			var e Entry
			if err := dec.Decode(&e); err != nil {
				return harDecodeError(err)
			}
			if err := emit(&e); err != nil {
				return err
			}
		}
		if err := expectHARDelimiter(dec, ']'); err != nil {
			return err
		}
	}
	if !seenEntries {
		return errInvalidHAR
	}
	return expectHARDelimiter(dec, '}')
}

func expectHARDelimiter(dec *json.Decoder, want json.Delim) error {
	got, err := dec.Token()
	if err != nil {
		return harDecodeError(err)
	}
	if got != want {
		return errInvalidHAR
	}
	return nil
}

func skipHARValue(dec *json.Decoder) error {
	value, err := dec.Token()
	if err != nil {
		return harDecodeError(err)
	}
	delim, nested := value.(json.Delim)
	if !nested {
		return nil
	}
	if delim != '{' && delim != '[' {
		return errInvalidHAR
	}
	for dec.More() {
		if delim == '{' {
			if _, err := dec.Token(); err != nil {
				return harDecodeError(err)
			}
		}
		if err := skipHARValue(dec); err != nil {
			return err
		}
	}
	if delim == '{' {
		return expectHARDelimiter(dec, '}')
	}
	return expectHARDelimiter(dec, ']')
}

func harDecodeError(err error) error {
	var syntax *json.SyntaxError
	var valueType *json.UnmarshalTypeError
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &syntax) || errors.As(err, &valueType) {
		return fmt.Errorf("%w: %v", errInvalidHAR, err)
	}
	return err
}
