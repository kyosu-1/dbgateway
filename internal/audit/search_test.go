package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// writeSearchFixture writes n entries, one per hour starting at base, so
// that they span several daily files. Entry i has request id "r<i>".
func writeSearchFixture(t *testing.T, dir string, base time.Time, n int, mutate func(i int, e *Entry)) {
	t.Helper()
	sink, err := OpenFileSink(dir, 0, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(sink)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		at := base.Add(time.Duration(i) * time.Hour)
		l.now = func() time.Time { return at }
		e := entry(fmt.Sprintf("r%d", i))
		if mutate != nil {
			mutate(i, e)
		}
		if err := l.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func ids(p Page) []string {
	out := make([]string, 0, len(p.Entries))
	for _, e := range p.Entries {
		out = append(out, e.RequestID)
	}
	return out
}

func rangeIDs(from, to int) []string { // descending from..to inclusive
	var out []string
	for i := from; i >= to; i-- {
		out = append(out, fmt.Sprintf("r%d", i))
	}
	return out
}

var searchBase = time.Date(2026, 11, 1, 20, 0, 0, 0, time.UTC)

func TestSearchNewestFirstAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	writeSearchFixture(t, dir, searchBase, 30, nil) // 2026-11-01 20:00 .. 11-03 01:00
	if m, _ := filepath.Glob(filepath.Join(dir, "audit-*.jsonl")); len(m) != 3 {
		t.Fatalf("fixture files = %v", m)
	}
	p, err := Search(dir, Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(p); !slices.Equal(got, rangeIDs(29, 0)) {
		t.Errorf("order = %v", got)
	}
	if p.NextCursor != "" {
		t.Errorf("unexpected cursor on a partial page")
	}
	e := p.Entries[0]
	if e.Hash == "" || e.PrevHash == "" || e.Principal.Human != "taro@example.com" || e.Database != "prod-main" {
		t.Errorf("entry = %+v", e)
	}
	if p.Entries[1].Hash != e.PrevHash {
		t.Error("hash chain not preserved in the read model")
	}
}

func TestSearchPagination(t *testing.T) {
	dir := t.TempDir()
	writeSearchFixture(t, dir, searchBase, 30, nil)
	var all []string
	f := Filter{Limit: 7}
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("pagination does not terminate")
		}
		p, err := Search(dir, f)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, ids(p)...)
		if p.NextCursor == "" {
			break
		}
		f.Cursor = p.NextCursor
	}
	if !slices.Equal(all, rangeIDs(29, 0)) {
		t.Errorf("paged = %v", all)
	}

	// Entries appended after the first page do not shift later pages.
	p1, _ := Search(dir, Filter{Limit: 5})
	writeSearchFixture(t, dir, searchBase.Add(48*time.Hour), 3, func(i int, e *Entry) { e.RequestID = fmt.Sprintf("new%d", i) })
	p2, err := Search(dir, Filter{Limit: 5, Cursor: p1.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(p2); !slices.Equal(got, rangeIDs(24, 20)) {
		t.Errorf("second page after appends = %v", got)
	}
}

func TestSearchFilters(t *testing.T) {
	dir := t.TempDir()
	writeSearchFixture(t, dir, searchBase, 30, func(i int, e *Entry) {
		switch {
		case i%3 == 0:
			e.Principal = PrincipalInfo{Kind: "human", Human: "Hanako@Example.com"}
			e.Database = "analytics"
		case i%3 == 1:
			e.Principal.Agent = "Claude-Code"
		}
		if i%5 == 0 {
			e.Decision, e.Stage = "deny", "policy"
		}
		if i%2 == 0 {
			e.Event = "search"
		}
		if i == 7 {
			e.Analysis = &AnalysisInfo{Kind: "select", Tables: []string{"public.users", "billing.Orders"}}
		}
	})
	tests := []struct {
		name string
		f    Filter
		want func(i int) bool
	}{
		{"principal human substring", Filter{Principal: "hanako"}, func(i int) bool { return i%3 == 0 }},
		{"principal agent substring", Filter{Principal: "CLAUDE"}, func(i int) bool { return i%3 == 1 }},
		{"database", Filter{Database: "analytics"}, func(i int) bool { return i%3 == 0 }},
		{"decision", Filter{Decision: "deny"}, func(i int) bool { return i%5 == 0 }},
		{"event", Filter{Event: "search"}, func(i int) bool { return i%2 == 0 }},
		{"combined", Filter{Decision: "deny", Event: "search", Database: "analytics"}, func(i int) bool { return i%30 == 0 }},
		{"request id", Filter{RequestID: "r13"}, func(i int) bool { return i == 13 }},
		{"table unqualified", Filter{Table: "orders"}, func(i int) bool { return i == 7 }},
		{"table qualified", Filter{Table: "public.users"}, func(i int) bool { return i == 7 }},
		{"table no partial", Filter{Table: "user"}, func(int) bool { return false }},
		{"time range", Filter{Since: searchBase.Add(5 * time.Hour), Until: searchBase.Add(9 * time.Hour)}, func(i int) bool { return i >= 5 && i < 9 }},
		{"since only", Filter{Since: searchBase.Add(27 * time.Hour)}, func(i int) bool { return i >= 27 }},
		{"until only", Filter{Until: searchBase.Add(2*time.Hour + time.Minute)}, func(i int) bool { return i <= 2 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Search(dir, Filter{Limit: 100, Principal: tt.f.Principal, Database: tt.f.Database, Decision: tt.f.Decision,
				Event: tt.f.Event, RequestID: tt.f.RequestID, Table: tt.f.Table, Since: tt.f.Since, Until: tt.f.Until})
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			for i := 29; i >= 0; i-- {
				if tt.want(i) {
					want = append(want, fmt.Sprintf("r%d", i))
				}
			}
			if got := ids(p); !slices.Equal(got, want) {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}

func TestSearchFilteredPagination(t *testing.T) {
	dir := t.TempDir()
	writeSearchFixture(t, dir, searchBase, 30, func(i int, e *Entry) {
		if i%4 == 0 {
			e.Decision = "deny"
		}
	})
	var all []string
	f := Filter{Decision: "deny", Limit: 2}
	for {
		p, err := Search(dir, f)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, ids(p)...)
		if p.NextCursor == "" {
			break
		}
		f.Cursor = p.NextCursor
	}
	want := []string{"r28", "r24", "r20", "r16", "r12", "r8", "r4", "r0"}
	if !slices.Equal(all, want) {
		t.Errorf("got %v", all)
	}
}

func TestSearchLongLinesAcrossChunks(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("x", 3*readChunk+123)
	writeSearchFixture(t, dir, searchBase, 6, func(i int, e *Entry) {
		if i%2 == 1 {
			e.Reason = big
		}
	})
	p, err := Search(dir, Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(p); !slices.Equal(got, rangeIDs(5, 0)) {
		t.Fatalf("got %v", got)
	}
	if p.Entries[0].Reason != big || p.Skipped != 0 {
		t.Errorf("long line not read intact (skipped %d)", p.Skipped)
	}
}

func TestSearchSkipsGarbageAndMissingDir(t *testing.T) {
	dir := t.TempDir()
	writeSearchFixture(t, dir, searchBase, 2, nil)
	name := filepath.Join(dir, "audit-2026-11-01.jsonl")
	fh, err := os.OpenFile(name, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fh.WriteString("not json\n\n")
	_ = fh.Close()
	p, err := Search(dir, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 2 || p.Skipped != 1 {
		t.Errorf("entries %d skipped %d", len(p.Entries), p.Skipped)
	}

	if _, err := Search(filepath.Join(dir, "missing"), Filter{}); err == nil {
		t.Error("expected an error for a missing directory")
	}
}

func TestSearchCursorValidation(t *testing.T) {
	dir := t.TempDir()
	writeSearchFixture(t, dir, searchBase, 2, nil)
	for _, c := range []string{
		"!!!",
		cursor{File: "../etc/passwd", Offset: 0}.encode(),
		cursor{File: "checkpoints.jsonl", Offset: 0}.encode(),
		cursor{File: "audit-2026-11-01.jsonl", Offset: -1}.encode(),
	} {
		if _, err := Search(dir, Filter{Cursor: c}); err != ErrInvalidCursor {
			t.Errorf("cursor %q: err = %v", c, err)
		}
	}
	// A cursor into a file removed by retention continues with older files.
	p, err := Search(dir, Filter{Cursor: cursor{File: "audit-2026-12-31.jsonl", Offset: 10}.encode()})
	if err != nil || len(p.Entries) != 2 {
		t.Errorf("cursor past the newest file: %v %v", err, ids(p))
	}
}

func TestSearchLimitBounds(t *testing.T) {
	dir := t.TempDir()
	writeSearchFixture(t, dir, searchBase, 60, nil)
	p, err := Search(dir, Filter{})
	if err != nil || len(p.Entries) != defaultSearchLimit || p.NextCursor == "" {
		t.Errorf("default limit: %d entries, cursor %q, %v", len(p.Entries), p.NextCursor, err)
	}
	p, _ = Search(dir, Filter{Limit: 1 << 20})
	if len(p.Entries) != 60 {
		t.Errorf("large limit: %d", len(p.Entries))
	}
}
