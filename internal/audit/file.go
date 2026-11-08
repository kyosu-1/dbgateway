package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	filePrefix      = "audit-"
	fileSuffix      = ".jsonl"
	checkpointsFile = "checkpoints.jsonl"
	maxLine         = 16 << 20
)

// FileSink writes daily files (audit-YYYY-MM-DD.jsonl, UTC) in a directory
// and deletes files older than the retention period. Before deleting a
// file, it records a checkpoint (the hash the next remaining line points
// to) so the remaining log can still be verified.
type FileSink struct {
	mu        sync.Mutex
	dir       string
	retention time.Duration
	fsync     bool
	logger    *slog.Logger

	day  string
	file *os.File
}

// OpenFileSink opens (creating if needed) the audit directory.
func OpenFileSink(dir string, retention time.Duration, fsync bool, logger *slog.Logger) (*FileSink, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &FileSink{dir: dir, retention: retention, fsync: fsync, logger: logger}
	if err := s.applyRetention(time.Now()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileSink) files() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && strings.HasPrefix(n, filePrefix) && strings.HasSuffix(n, fileSuffix) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

// LastHash returns the hash of the last line of the newest file.
func (s *FileSink) LastHash() (string, error) {
	files, err := s.files()
	if err != nil {
		return "", err
	}
	for i := len(files) - 1; i >= 0; i-- {
		last, err := lastLine(filepath.Join(s.dir, files[i]))
		if err != nil {
			return "", err
		}
		if last == nil {
			continue
		}
		hash, _, err := checkLine(last)
		if err != nil {
			return "", fmt.Errorf("%s: last line: %w", files[i], err)
		}
		return hash, nil
	}
	// All files deleted by retention: continue from the last checkpoint.
	cps, err := readCheckpoints(s.dir)
	if err != nil {
		return "", err
	}
	if len(cps) > 0 {
		return cps[len(cps)-1].LastHash, nil
	}
	return GenesisHash, nil
}

func lastLine(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var last []byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxLine)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) > 0 {
			last = append(last[:0], sc.Bytes()...)
		}
	}
	return last, sc.Err()
}

// Append writes a line to today's file.
func (s *FileSink) Append(line []byte, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	day := at.UTC().Format("2006-01-02")
	if s.file == nil || s.day != day {
		if s.file != nil {
			_ = s.file.Close()
			s.file = nil
		}
		f, err := os.OpenFile(filepath.Join(s.dir, filePrefix+day+fileSuffix), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		s.file, s.day = f, day
		if err := s.applyRetention(at); err != nil {
			s.logger.Error("audit retention failed", "err", err)
		}
	}
	if _, err := s.file.Write(append(line, '\n')); err != nil {
		return err
	}
	if s.fsync {
		return s.file.Sync()
	}
	return nil
}

// Close closes the current file.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

// Checkpoint records the chain state at a deleted file's end.
type Checkpoint struct {
	DeletedFile string `json:"deleted_file"`
	LastHash    string `json:"last_hash"`
	DeletedAt   string `json:"deleted_at"`
}

func (s *FileSink) applyRetention(now time.Time) error {
	if s.retention <= 0 {
		return nil
	}
	files, err := s.files()
	if err != nil {
		return err
	}
	cutoff := now.UTC().Add(-s.retention).Format("2006-01-02")
	for _, name := range files {
		day := strings.TrimSuffix(strings.TrimPrefix(name, filePrefix), fileSuffix)
		if day >= cutoff || day == s.day {
			continue
		}
		path := filepath.Join(s.dir, name)
		last, err := lastLine(path)
		if err != nil {
			return err
		}
		if last != nil {
			hash, _, err := checkLine(last)
			if err != nil {
				return fmt.Errorf("%s: refusing to delete a file that fails verification: %w", name, err)
			}
			cp := Checkpoint{DeletedFile: name, LastHash: hash, DeletedAt: now.UTC().Format(time.RFC3339)}
			if err := appendCheckpoint(s.dir, cp); err != nil {
				return err
			}
			// Also emit it to the process log so it lands in an external
			// system, independent of this directory.
			s.logger.Info("audit checkpoint", "deleted_file", cp.DeletedFile, "last_hash", cp.LastHash)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}

func appendCheckpoint(dir string, cp Checkpoint) error {
	f, err := os.OpenFile(filepath.Join(dir, checkpointsFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := json.Marshal(cp)
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func readCheckpoints(dir string) ([]Checkpoint, error) {
	f, err := os.Open(filepath.Join(dir, checkpointsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Checkpoint
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var cp Checkpoint
		if err := json.Unmarshal(sc.Bytes(), &cp); err == nil {
			out = append(out, cp)
		}
	}
	return out, sc.Err()
}

// StdoutSink writes lines to a writer (standard output). The chain starts
// fresh at every process start; use a file sink for verifiable history.
type StdoutSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewStdoutSink returns a sink writing to w.
func NewStdoutSink(w io.Writer) *StdoutSink { return &StdoutSink{w: w} }

func (s *StdoutSink) LastHash() (string, error) { return GenesisHash, nil }
func (s *StdoutSink) Close() error              { return nil }
func (s *StdoutSink) Append(line []byte, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.w.Write(append(line, '\n'))
	return err
}

// VerifyReport summarizes a verification.
type VerifyReport struct {
	Files   int
	Entries int
	// StartedFromCheckpoint is true when the oldest remaining line chains
	// to a recorded checkpoint rather than the genesis hash.
	StartedFromCheckpoint bool
	LastHash              string
}

// VerifyDir verifies every audit file in dir, in order, as one chain.
func VerifyDir(dir string) (*VerifyReport, error) {
	s := &FileSink{dir: dir}
	files, err := s.files()
	if err != nil {
		return nil, err
	}
	cps, err := readCheckpoints(dir)
	if err != nil {
		return nil, err
	}
	rep := &VerifyReport{Files: len(files)}
	prev := ""
	for _, name := range files {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), maxLine)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			line := sc.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			hash, p, err := checkLine(line)
			if err != nil {
				f.Close()
				return rep, fmt.Errorf("%s:%d: %w", name, lineNo, err)
			}
			switch {
			case prev == "" && p == GenesisHash:
			case prev == "" && slices.ContainsFunc(cps, func(c Checkpoint) bool { return c.LastHash == p }):
				rep.StartedFromCheckpoint = true
			case prev == "":
				f.Close()
				return rep, fmt.Errorf("%s:%d: %w: first entry does not chain to genesis or a checkpoint", name, lineNo, errChain)
			case p != prev:
				f.Close()
				return rep, fmt.Errorf("%s:%d: %w: prev_hash does not match the previous entry (entries removed or reordered)", name, lineNo, errChain)
			}
			prev = hash
			rep.Entries++
		}
		err = sc.Err()
		f.Close()
		if err != nil {
			return rep, fmt.Errorf("%s: %w", name, err)
		}
	}
	rep.LastHash = prev
	return rep, nil
}
