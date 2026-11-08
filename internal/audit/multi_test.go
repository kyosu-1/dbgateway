package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type memSink struct {
	mu    sync.Mutex
	lines [][]byte
	fail  error
}

func (s *memSink) LastHash() (string, error) { return GenesisHash, nil }
func (s *memSink) Close() error              { return nil }
func (s *memSink) Append(line []byte, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	s.lines = append(s.lines, append([]byte(nil), line...))
	return nil
}

type fakeForwarder struct {
	mu       sync.Mutex
	got      []Record
	block    chan struct{} // when non-nil, Forward waits on it
	err      error
	shutdown bool
}

func (f *fakeForwarder) Name() string { return "fake" }
func (f *fakeForwarder) Forward(ctx context.Context, batch []Record) error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.got = append(f.got, batch...)
	return nil
}
func (f *fakeForwarder) Shutdown(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shutdown = true
	return nil
}
func (f *fakeForwarder) records() []Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Record(nil), f.got...)
}

func TestMultiSinkForwards(t *testing.T) {
	primary := &memSink{}
	fwd := &fakeForwarder{}
	ms := NewMultiSink(primary, fwd)
	l, err := New(ms)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := l.Write(entry(id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	got := fwd.records()
	if len(got) != 3 || !fwd.shutdown {
		t.Fatalf("forwarded %d, shutdown %v", len(got), fwd.shutdown)
	}
	for i, r := range got {
		if string(r.Line) != string(primary.lines[i]) {
			t.Errorf("record %d differs from the primary line", i)
		}
		hash, _, err := checkLine(r.Line)
		if err != nil || r.Hash != hash {
			t.Errorf("record %d hash = %q, want %q (%v)", i, r.Hash, hash, err)
		}
	}
	if s := ms.Stats(); len(s) != 1 || s[0].Sent != 3 || s[0].Dropped != 0 || s[0].Failed != 0 {
		t.Errorf("stats = %+v", s)
	}
}

func TestMultiSinkPrimaryFailureFailsClosed(t *testing.T) {
	primary := &memSink{fail: errors.New("disk full")}
	fwd := &fakeForwarder{}
	ms := NewMultiSink(primary, fwd)
	l, _ := New(ms)
	if err := l.Write(entry("a")); err == nil {
		t.Fatal("write succeeded although the primary failed")
	}
	_ = l.Close()
	if n := len(fwd.records()); n != 0 {
		t.Errorf("forwarded %d entries the primary did not store", n)
	}
}

func TestMultiSinkForwarderNeverBlocks(t *testing.T) {
	primary := &memSink{}
	fwd := &fakeForwarder{block: make(chan struct{})}
	ms := NewMultiSink(primary, fwd)
	l, _ := New(ms)

	total := forwardQueueSize + forwardMaxBatch + 100
	done := make(chan error, 1)
	go func() {
		for range total {
			if err := l.Write(entry("x")); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Append blocked on a stuck forwarder")
	}
	if len(primary.lines) != total {
		t.Fatalf("primary has %d lines, want %d", len(primary.lines), total)
	}
	s := ms.Stats()[0]
	if s.Dropped == 0 {
		t.Errorf("expected drops, stats = %+v", s)
	}
	close(fwd.block)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	s = ms.Stats()[0]
	if s.Sent+s.Dropped+s.Failed != uint64(total) {
		t.Errorf("sent %d + dropped %d + failed %d != %d", s.Sent, s.Dropped, s.Failed, total)
	}
}

func TestMultiSinkForwarderErrorIsCounted(t *testing.T) {
	fwd := &fakeForwarder{err: errors.New("collector down")}
	ms := NewMultiSink(&memSink{}, fwd)
	l, _ := New(ms)
	for range 5 {
		if err := l.Write(entry("x")); err != nil {
			t.Fatalf("forwarder error leaked into the request: %v", err)
		}
	}
	_ = l.Close()
	if s := ms.Stats()[0]; s.Failed != 5 || s.Sent != 0 {
		t.Errorf("stats = %+v", s)
	}
}

func TestMultiSinkAppendAfterClose(t *testing.T) {
	fwd := &fakeForwarder{}
	ms := NewMultiSink(&memSink{}, fwd)
	if err := ms.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ms.Close(); err != nil {
		t.Fatal("second close:", err)
	}
	line, _, _ := Encode(entry("late"))
	if err := ms.Append(line, time.Now()); err != nil {
		t.Fatal(err)
	}
	if s := ms.Stats()[0]; s.Dropped != 1 {
		t.Errorf("stats = %+v", s)
	}
}
