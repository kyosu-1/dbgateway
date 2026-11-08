//go:build integration

// Integration tests of the PostgreSQL audit sink against the development
// PostgreSQL (docker compose -f examples/dev/compose.yaml up -d --wait).
// Each test creates a database with a random name and drops it afterwards.
package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func pgEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func pgTestDSN(db string) string {
	u := url.URL{Scheme: "postgres", Host: pgEnv("DBGW_TEST_PG_HOST", "127.0.0.1") + ":" + pgEnv("DBGW_TEST_PG_PORT", "55432"), Path: "/" + db,
		User: url.UserPassword(pgEnv("DBGW_TEST_PG_SUPERUSER", "postgres"), pgEnv("DBGW_TEST_PG_SUPERPASSWORD", "postgres"))}
	q := url.Values{"sslmode": {pgEnv("DBGW_TEST_PG_SSLMODE", "disable")}}
	if rc := pgEnv("DBGW_TEST_PG_SSLROOTCERT", ""); rc != "" {
		q.Set("sslrootcert", rc)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func pgTempDatabase(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, pgTestDSN(pgEnv("DBGW_TEST_PG_DB", "app")))
	if err != nil {
		t.Fatalf("connect as superuser: %v", err)
	}
	b := make([]byte, 6)
	rand.Read(b)
	name := "dbgw_audit_test_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		defer admin.Close(ctx)
		if _, err := admin.Exec(ctx, `DROP DATABASE `+pgx.Identifier{name}.Sanitize()+` WITH (FORCE)`); err != nil {
			t.Errorf("drop database %s: %v", name, err)
		}
	})
	return pgTestDSN(name)
}

func openPGSink(t *testing.T, dsn string, retention time.Duration) *PostgresSink {
	t.Helper()
	s, err := OpenPostgresSink(context.Background(), dsn, retention, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func pgExec(t *testing.T, dsn, sql string, args ...any) int64 {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	tag, err := c.Exec(ctx, sql, args...)
	if err != nil {
		t.Fatal(err)
	}
	return tag.RowsAffected()
}

func pgLines(t *testing.T, dsn string) [][]byte {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	rows, _ := c.Query(ctx, `SELECT line FROM audit_log ORDER BY seq`)
	lines, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
	if err != nil {
		t.Fatal(err)
	}
	return lines
}

func TestPostgresSinkSingleInstanceStoresLinesVerbatim(t *testing.T) {
	dsn := pgTempDatabase(t)
	mem := &memSink{}
	memLog, _ := New(mem)
	sink := openPGSink(t, dsn, 0)
	l, err := New(sink)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		e1, e2 := entry(id), entry(id)
		e1.TS, e2.TS = "2026-11-08T00:00:00Z", "2026-11-08T00:00:00Z"
		if err := l.Write(e1); err != nil {
			t.Fatal(err)
		}
		if err := memLog.Write(e2); err != nil {
			t.Fatal(err)
		}
	}
	lines := pgLines(t, dsn)
	if len(lines) != 3 {
		t.Fatalf("rows = %d", len(lines))
	}
	for i := range lines {
		if !bytes.Equal(lines[i], mem.lines[i]) {
			t.Fatalf("line %d differs from the file format:\n%s\n%s", i, lines[i], mem.lines[i])
		}
	}
	// The same lines verify as an audit file.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "audit-2026-11-08.jsonl"), append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if rep, err := VerifyDir(dir); err != nil || rep.Entries != 3 {
		t.Fatalf("VerifyDir = %+v, %v", rep, err)
	}
	rep, err := VerifyPostgres(context.Background(), dsn)
	if err != nil || rep.Entries != 3 || rep.StartedFromCheckpoint || rep.LastHash != lineHash(lines[2]) {
		t.Fatalf("VerifyPostgres = %+v, %v", rep, err)
	}
	if h, err := sink.LastHash(); err != nil || h != rep.LastHash {
		t.Fatalf("LastHash = %s, %v", h, err)
	}
}

// Several instances (separate pools and Loggers, each with a stale view of
// the tail) write concurrently and still form one valid chain.
func TestPostgresSinkInstancesShareOneChain(t *testing.T) {
	dsn := pgTempDatabase(t)
	const instances, perInstance = 3, 40
	fwd := &fakeForwarder{}
	var loggers []*Logger
	for i := range instances {
		s := openPGSink(t, dsn, 0)
		if i == 0 {
			s.SetForwarders(nil, fwd)
		}
		l, err := New(s)
		if err != nil {
			t.Fatal(err)
		}
		loggers = append(loggers, l)
	}
	// Interleaved writes: the Loggers of instances 1 and 2 hold stale
	// tails, so their lines are re-chained by the sink.
	for _, l := range []*Logger{loggers[1], loggers[2], loggers[1]} {
		if err := l.Write(entry("seq")); err != nil {
			t.Fatal(err)
		}
	}
	if rep, err := VerifyPostgres(context.Background(), dsn); err != nil || rep.Entries != 3 {
		t.Fatalf("VerifyPostgres = %+v, %v", rep, err)
	}
	var wg sync.WaitGroup
	for i, l := range loggers {
		wg.Go(func() {
			for j := range perInstance {
				e := entry(fmt.Sprintf("i%d-%d", i, j))
				e.Extra = map[string]any{"big": uint64(12345678901234567890), "f": 0.1, "nested": map[string]any{"b": 1, "a": []any{"x", 2.5}}}
				if err := l.Write(e); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
	rep, err := VerifyPostgres(context.Background(), dsn)
	if err != nil || rep.Entries != 3+instances*perInstance {
		t.Fatalf("VerifyPostgres = %+v, %v", rep, err)
	}
	lines := pgLines(t, dsn)
	for _, line := range lines[3:] {
		if !bytes.Contains(line, []byte(`"big":12345678901234567890`)) || !bytes.Contains(line, []byte(`"f":0.1`)) {
			t.Fatalf("re-encoding changed Extra: %s", line)
		}
	}
	// The forwarder of instance 0 got its lines as stored (chained to the
	// shared tail), not as its Logger encoded them.
	if err := loggers[0].Close(); err != nil {
		t.Fatal(err)
	}
	recs := fwd.records()
	if len(recs) != perInstance {
		t.Fatalf("forwarded %d records", len(recs))
	}
	for _, r := range recs {
		if !slices.ContainsFunc(lines, func(l []byte) bool { return bytes.Equal(l, r.Line) }) || r.Hash != lineHash(r.Line) {
			t.Fatalf("forwarded line not stored: %s", r.Line)
		}
	}
}

func TestPostgresSinkTamperDetection(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, sql, want string
	}{
		{"edit", `UPDATE audit_log SET line = replace(line, '"decision":"allow"', '"decision":"deny"') WHERE seq = 2`, "line was modified"},
		{"edit columns", `UPDATE audit_log SET prev_hash = hash WHERE seq = 2`, "hash columns"},
		{"delete middle", `DELETE FROM audit_log WHERE seq = 2`, "entries removed or reordered"},
		{"delete head", `DELETE FROM audit_log WHERE seq = 1`, "first entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dsn := pgTempDatabase(t)
			l, _ := New(openPGSink(t, dsn, 0))
			for _, id := range []string{"a", "b", "c"} {
				if err := l.Write(entry(id)); err != nil {
					t.Fatal(err)
				}
			}
			if n := pgExec(t, dsn, tc.sql); n != 1 {
				t.Fatalf("tampering changed %d rows", n)
			}
			_, err := VerifyPostgres(ctx, dsn)
			if !errors.Is(err, errChain) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPostgresSinkRefusesBadLines(t *testing.T) {
	sink := openPGSink(t, pgTempDatabase(t), 0)
	line, _, _ := Encode(entry("a"))
	bad := bytes.Replace(line, []byte(`"decision":"allow"`), []byte(`"decision":"deny"`), 1)
	if err := sink.Append(bad, time.Now()); err == nil {
		t.Fatal("line with a wrong hash accepted")
	}
	e := entry("a")
	e.PrevHash = GenesisHash
	body, _, _ := Encode(e)
	unknown := bytes.Replace(body, []byte(`{"ts"`), []byte(`{"zzz":1,"ts"`), 1)
	unknown = rehash(unknown)
	if err := sink.Append(unknown, time.Now()); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("line with an unknown field: %v", err)
	}
}

// rehash recomputes the trailing hash of a modified line.
func rehash(line []byte) []byte {
	body := append(append([]byte{}, line[:len(line)-hashSuffixLen]...), '}')
	sum := sha256.Sum256(body)
	return append(body[:len(body)-1], `,"hash":"`+hex.EncodeToString(sum[:])+`"}`...)
}

func TestPostgresSinkRetention(t *testing.T) {
	ctx := context.Background()
	dsn := pgTempDatabase(t)
	sink := openPGSink(t, dsn, 0)
	l, _ := New(sink)
	old := time.Now().Add(-48 * time.Hour)
	for i := range 5 {
		e := entry(fmt.Sprintf("old%d", i))
		e.TS = old.Add(time.Duration(i) * time.Minute).Format(time.RFC3339Nano)
		if err := l.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 3 {
		if err := l.Write(entry(fmt.Sprintf("new%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	oldLines := pgLines(t, dsn)
	lastOld := lineHash(oldLines[4])

	// Reopening with a 24h retention deletes the old prefix after a
	// checkpoint.
	s2 := openPGSink(t, dsn, 24*time.Hour)
	if n := len(pgLines(t, dsn)); n != 3 {
		t.Fatalf("rows after retention = %d", n)
	}
	rep, err := VerifyPostgres(ctx, dsn)
	if err != nil || rep.Entries != 3 || !rep.StartedFromCheckpoint {
		t.Fatalf("VerifyPostgres = %+v, %v", rep, err)
	}
	// Deleting the first remaining row is still detected.
	pgExec(t, dsn, `DELETE FROM audit_log WHERE seq = (SELECT min(seq) FROM audit_log)`)
	if _, err := VerifyPostgres(ctx, dsn); !errors.Is(err, errChain) {
		t.Fatalf("deleted head after retention: %v", err)
	}
	// With every row gone, the chain continues from the checkpoint.
	pgExec(t, dsn, `DELETE FROM audit_log`)
	if h, err := s2.LastHash(); err != nil || h != lastOld {
		t.Fatalf("LastHash = %s, %v", h, err)
	}
	l2, _ := New(s2)
	if err := l2.Write(entry("after")); err != nil {
		t.Fatal(err)
	}
	if rep, err := VerifyPostgres(ctx, dsn); err != nil || rep.Entries != 1 || !rep.StartedFromCheckpoint {
		t.Fatalf("VerifyPostgres = %+v, %v", rep, err)
	}
}

func TestVerifyPostgresWithoutTable(t *testing.T) {
	if _, err := VerifyPostgres(context.Background(), pgTempDatabase(t)); err == nil || !strings.Contains(err.Error(), "no audit_log") {
		t.Fatalf("err = %v", err)
	}
}

// SearchPostgres returns the same pages as Search on the same entries.
func TestSearchPostgresMatchesFileSearch(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dsn := pgTempDatabase(t)
	mutate := func(i int, e *Entry) {
		switch i % 4 {
		case 0:
			e.Principal.Human, e.Principal.Agent = "Hanako@Example.com", "claude-code"
		case 1:
			e.Database, e.Decision = "staging", "deny"
		case 2:
			e.Event = "search"
			e.Analysis = &AnalysisInfo{Kind: "select", Tables: []string{"Public.Users", "orders"}}
		case 3:
			e.Analysis = &AnalysisInfo{Kind: "select", Tables: []string{"users_archive"}}
		}
	}
	writeSearchFixture(t, dir, searchBase, 30, mutate)
	sink := openPGSink(t, dsn, 0)
	l, _ := New(sink)
	for i := range 30 {
		at := searchBase.Add(time.Duration(i) * time.Hour)
		l.now = func() time.Time { return at }
		e := entry(fmt.Sprintf("r%d", i))
		mutate(i, e)
		if err := l.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	filters := []Filter{
		{},
		{Limit: 7},
		{Principal: "hanako"},
		{Principal: "CLAUDE"},
		{Database: "staging"},
		{Decision: "deny", Limit: 3},
		{Event: "search"},
		{Table: "users"},
		{Table: "public.users"},
		{Table: "orders"},
		{RequestID: "r17"},
		{Since: searchBase.Add(5 * time.Hour), Until: searchBase.Add(20 * time.Hour), Limit: 4},
		{Since: searchBase.Add(100 * time.Hour)},
	}
	for i, f := range filters {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var fileIDs, pgIDs []string
			ff, pf := f, f
			for range 20 {
				fp, err := Search(dir, ff)
				if err != nil {
					t.Fatal(err)
				}
				fileIDs = append(fileIDs, ids(fp)...)
				if fp.NextCursor == "" {
					break
				}
				ff.Cursor = fp.NextCursor
			}
			for range 20 {
				pp, err := sink.Search(ctx, pf)
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range pp.Entries {
					if e.Hash == "" {
						t.Fatal("entry without hash")
					}
				}
				pgIDs = append(pgIDs, ids(pp)...)
				if pp.NextCursor == "" {
					break
				}
				pf.Cursor = pp.NextCursor
			}
			if !slices.Equal(fileIDs, pgIDs) {
				t.Fatalf("file %v\npg   %v", fileIDs, pgIDs)
			}
		})
	}
	if _, err := SearchPostgres(ctx, sink.pool, Filter{Cursor: "!!"}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("bad cursor: %v", err)
	}
	fileCursor := cursor{File: "audit-2026-11-01.jsonl", Offset: 10}.encode()
	if _, err := SearchPostgres(ctx, sink.pool, Filter{Cursor: fileCursor}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("file cursor accepted: %v", err)
	}
}
