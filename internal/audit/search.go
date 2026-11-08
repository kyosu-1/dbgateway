package audit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// StoredEntry is the read model of one stored audit line: the entry as
// written plus its chain hash.
type StoredEntry struct {
	Entry
	Hash string `json:"hash"`
}

// Filter selects entries for Search. Empty fields match everything.
type Filter struct {
	// Since and Until bound the entry time: Since <= ts < Until.
	Since, Until time.Time
	// Principal matches a case-insensitive substring of the human or the
	// agent name.
	Principal string
	// Database, Decision, Event and RequestID match exactly.
	Database  string
	Decision  string
	Event     string
	RequestID string
	// Table matches an entry of analysis.tables, case-insensitively. An
	// unqualified name ("users") also matches qualified ones
	// ("public.users").
	Table string
	// Limit is the page size (default 50, at most MaxSearchLimit).
	Limit int
	// Cursor continues from a previous page's NextCursor.
	Cursor string
}

// Page is one page of search results, newest first.
type Page struct {
	Entries []StoredEntry
	// NextCursor is set when the page is full; pass it as Filter.Cursor to
	// get older entries. The next page may be empty.
	NextCursor string
	// Skipped counts lines that could not be parsed.
	Skipped int
}

const (
	defaultSearchLimit = 50
	// MaxSearchLimit is the largest page size.
	MaxSearchLimit = 500
	readChunk      = 64 << 10
)

var (
	auditFileName = regexp.MustCompile(`^audit-[0-9]{4}-[0-9]{2}-[0-9]{2}\.jsonl$`)
	// ErrInvalidCursor is returned for a malformed cursor.
	ErrInvalidCursor = errors.New("audit: invalid cursor")
)

// cursor is the position just before the last returned entry: the file and
// the byte offset where that entry's line starts.
type cursor struct {
	File   string `json:"f"`
	Offset int64  `json:"o"`
}

func (c cursor) encode() string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (cursor, error) {
	var c cursor
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || json.Unmarshal(b, &c) != nil || !auditFileName.MatchString(c.File) || c.Offset < 0 {
		return cursor{}, ErrInvalidCursor
	}
	return c, nil
}

// Search scans the file sink directory from the newest entry to the oldest
// and returns the entries matching f. Files are read backwards in chunks,
// so memory use is bounded by the page size and the longest line,
// regardless of the size of the log.
func Search(dir string, f Filter) (Page, error) {
	var page Page
	limit := f.Limit
	if limit <= 0 {
		limit = defaultSearchLimit
	}
	limit = min(limit, MaxSearchLimit)
	var start *cursor
	if f.Cursor != "" {
		c, err := decodeCursor(f.Cursor)
		if err != nil {
			return page, err
		}
		start = &c
	}
	m := newMatcher(f)

	files, err := (&FileSink{dir: dir}).files()
	if err != nil {
		return page, err
	}
	for i := len(files) - 1; i >= 0; i-- {
		name := files[i]
		if start != nil && name > start.File {
			continue
		}
		if !m.dayMayMatch(name) {
			continue
		}
		end := int64(-1) // whole file
		if start != nil && name == start.File {
			end = start.Offset
		}
		full, err := searchFile(filepath.Join(dir, name), end, func(line []byte, off int64) bool {
			var e StoredEntry
			if err := json.Unmarshal(line, &e); err != nil {
				page.Skipped++
				return true
			}
			if !m.match(&e) {
				return true
			}
			page.Entries = append(page.Entries, e)
			if len(page.Entries) == limit {
				page.NextCursor = cursor{File: name, Offset: off}.encode()
				return false
			}
			return true
		})
		if err != nil {
			return page, fmt.Errorf("%s: %w", name, err)
		}
		if full {
			break
		}
	}
	return page, nil
}

// searchFile calls fn for each non-empty line before byte offset end (or
// the whole file when end < 0), last line first, with the offset where the
// line starts. It returns true if fn stopped the scan.
func searchFile(path string, end int64, fn func(line []byte, off int64) bool) (bool, error) {
	fh, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil // removed by retention meanwhile
	}
	if err != nil {
		return false, err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return false, err
	}
	if end < 0 || end > st.Size() {
		end = st.Size()
	}
	pos := end
	var tail []byte // the start of the line that ends at pos+len(chunk)
	for pos > 0 {
		n := min(int64(readChunk), pos)
		pos -= n
		buf := make([]byte, int(n)+len(tail))
		if _, err := fh.ReadAt(buf[:n], pos); err != nil && !errors.Is(err, io.EOF) {
			return false, err
		}
		copy(buf[n:], tail)
		for {
			i := bytes.LastIndexByte(buf, '\n')
			if i < 0 {
				break
			}
			if line := buf[i+1:]; len(bytes.TrimSpace(line)) > 0 {
				if !fn(line, pos+int64(i)+1) {
					return true, nil
				}
			}
			buf = buf[:i]
		}
		if len(buf) > maxLine {
			return false, errors.New("line too long")
		}
		tail = buf
	}
	if len(bytes.TrimSpace(tail)) > 0 && !fn(tail, 0) {
		return true, nil
	}
	return false, nil
}

type matcher struct {
	f         Filter
	principal string
	table     string
	sinceDay  string
	untilDay  string
}

func newMatcher(f Filter) *matcher {
	m := &matcher{f: f, principal: strings.ToLower(f.Principal), table: strings.ToLower(f.Table)}
	if !f.Since.IsZero() {
		m.sinceDay = f.Since.UTC().Format("2006-01-02")
	}
	if !f.Until.IsZero() {
		m.untilDay = f.Until.UTC().Format("2006-01-02")
	}
	return m
}

// dayMayMatch prunes daily files (named by UTC write date) outside the
// time range.
func (m *matcher) dayMayMatch(name string) bool {
	day := strings.TrimSuffix(strings.TrimPrefix(name, filePrefix), fileSuffix)
	if m.sinceDay != "" && day < m.sinceDay {
		return false
	}
	if m.untilDay != "" && day > m.untilDay {
		return false
	}
	return true
}

func (m *matcher) match(e *StoredEntry) bool {
	f := &m.f
	if f.RequestID != "" && e.RequestID != f.RequestID {
		return false
	}
	if f.Database != "" && e.Database != f.Database {
		return false
	}
	if f.Decision != "" && e.Decision != f.Decision {
		return false
	}
	if f.Event != "" && e.Event != f.Event {
		return false
	}
	if m.principal != "" &&
		!strings.Contains(strings.ToLower(e.Principal.Human), m.principal) &&
		!strings.Contains(strings.ToLower(e.Principal.Agent), m.principal) {
		return false
	}
	if m.table != "" && !m.matchTable(e.Analysis) {
		return false
	}
	if !f.Since.IsZero() || !f.Until.IsZero() {
		ts, err := time.Parse(time.RFC3339Nano, e.TS)
		if err != nil {
			return false
		}
		if !f.Since.IsZero() && ts.Before(f.Since) {
			return false
		}
		if !f.Until.IsZero() && !ts.Before(f.Until) {
			return false
		}
	}
	return true
}

func (m *matcher) matchTable(a *AnalysisInfo) bool {
	if a == nil {
		return false
	}
	for _, t := range a.Tables {
		t = strings.ToLower(t)
		if t == m.table || strings.HasSuffix(t, "."+m.table) {
			return true
		}
	}
	return false
}
