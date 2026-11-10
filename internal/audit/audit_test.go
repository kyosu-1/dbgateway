package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func entry(id string) *Entry {
	return &Entry{RequestID: id, Event: "query", Principal: PrincipalInfo{Kind: "agent", Human: "taro@example.com"},
		Database: "prod-main", SQL: "SELECT id FROM users WHERE id = $1", Decision: "allow", ConfigVersion: "abc"}
}

func TestChainAndVerify(t *testing.T) {
	dir := t.TempDir()
	sink, err := OpenFileSink(dir, 0, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(sink)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := l.Write(entry(id)); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()

	rep, err := VerifyDir(dir)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Entries != 3 {
		t.Errorf("entries = %d", rep.Entries)
	}

	// Reopen: the chain continues.
	sink2, _ := OpenFileSink(dir, 0, false, nil)
	l2, err := New(sink2)
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Write(entry("d")); err != nil {
		t.Fatal(err)
	}
	_ = l2.Close()
	if rep, err := VerifyDir(dir); err != nil || rep.Entries != 4 {
		t.Fatalf("verify after reopen: %v %+v", err, rep)
	}
}

func onlyFile(t *testing.T, dir string) string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if len(m) != 1 {
		t.Fatalf("files = %v", m)
	}
	return m[0]
}

func writeN(t *testing.T, dir string, n int) {
	t.Helper()
	sink, _ := OpenFileSink(dir, 0, false, nil)
	l, _ := New(sink)
	for i := range n {
		if err := l.Write(entry(string(rune('a' + i)))); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()
}

func TestTamperDetection(t *testing.T) {
	t.Run("modified", func(t *testing.T) {
		dir := t.TempDir()
		writeN(t, dir, 3)
		f := onlyFile(t, dir)
		b, _ := os.ReadFile(f)
		_ = os.WriteFile(f, []byte(strings.Replace(string(b), `"decision":"allow"`, `"decision":"deny"`, 1)), 0o600)
		if _, err := VerifyDir(dir); err == nil || !strings.Contains(err.Error(), "modified") {
			t.Errorf("expected modification error, got %v", err)
		}
	})
	t.Run("deleted", func(t *testing.T) {
		dir := t.TempDir()
		writeN(t, dir, 3)
		f := onlyFile(t, dir)
		b, _ := os.ReadFile(f)
		lines := strings.SplitAfter(string(b), "\n")
		_ = os.WriteFile(f, []byte(lines[0]+lines[2]), 0o600)
		if _, err := VerifyDir(dir); err == nil || !strings.Contains(err.Error(), "prev_hash") {
			t.Errorf("expected chain error, got %v", err)
		}
	})
	t.Run("first removed", func(t *testing.T) {
		dir := t.TempDir()
		writeN(t, dir, 3)
		f := onlyFile(t, dir)
		b, _ := os.ReadFile(f)
		lines := strings.SplitAfter(string(b), "\n")
		_ = os.WriteFile(f, []byte(lines[1]+lines[2]), 0o600)
		if _, err := VerifyDir(dir); err == nil || !strings.Contains(err.Error(), "genesis") {
			t.Errorf("expected genesis error, got %v", err)
		}
	})
}

func TestRetentionCheckpoint(t *testing.T) {
	dir := t.TempDir()
	sink, _ := OpenFileSink(dir, 48*time.Hour, false, nil)
	l, _ := New(sink)
	old := time.Now().Add(-10 * 24 * time.Hour)
	l.now = func() time.Time { return old }
	_ = l.Write(entry("old1"))
	_ = l.Write(entry("old2"))
	l.now = time.Now
	_ = l.Write(entry("new1")) // rotation applies retention
	_ = l.Close()

	files, _ := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("old file not deleted: %v", files)
	}
	rep, err := VerifyDir(dir)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.StartedFromCheckpoint || rep.Entries != 1 {
		t.Errorf("report = %+v", rep)
	}
}

type failingSink struct{}

func (failingSink) LastHash() (string, error)      { return GenesisHash, nil }
func (failingSink) Append([]byte, time.Time) error { return os.ErrPermission }
func (failingSink) Close() error                   { return nil }

func TestWriteFailureIsReported(t *testing.T) {
	l, _ := New(failingSink{})
	var observed []error
	l.SetErrorObserver(func(err error) { observed = append(observed, err) })
	err := l.Write(entry("x"))
	if err == nil {
		t.Fatal("expected error")
	}
	if len(observed) != 1 || observed[0] != err {
		t.Fatalf("observed = %v, want [%v]", observed, err)
	}
}
