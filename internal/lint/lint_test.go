package lint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func mustLinter(t *testing.T, d Dialect, cfg *Config) *Linter {
	t.Helper()
	l, err := New(d, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// brief renders findings as "line:col rule" for comparison.
func brief(fs []Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, fmt.Sprintf("%d:%d %s", f.Line, f.Column, f.Rule))
	}
	return strings.Join(out, "\n")
}

func TestPositions(t *testing.T) {
	l := mustLinter(t, Postgres, nil)
	src := "-- Add an index.\n" +
		"SET lock_timeout = '2s';\n" +
		"\n" +
		"/* comment */ CREATE INDEX users_email ON users (email);\n" +
		"ALTER TABLE users\n" +
		"  ADD COLUMN plan text NOT NULL,\n" +
		"  ADD CONSTRAINT fk FOREIGN KEY (org_id) REFERENCES orgs (id);\n" +
		"CREATE TABLE \"ユーザー\" (名前 varchar(10));\n"
	got := brief(l.Lint("m.sql", []byte(src)))
	want := "4:15 pg/create-index-concurrently\n" +
		"6:14 pg/add-column-not-null-without-default\n" +
		"7:7 pg/add-constraint-not-valid\n" +
		"8:14 pg/require-primary-key\n" +
		"8:25 pg/prefer-text"
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestSyntaxError(t *testing.T) {
	for _, tc := range []struct {
		dialect Dialect
		src     string
		want    string
	}{
		{Postgres, "SELECT 1;\nSELEC 2;", "2:1 syntax-error"},
		{Postgres, "-- dbgw-lint-ignore\nCREATE TABLE (;", "2:14 syntax-error"},
		{MySQL, "SELECT 1;\nDROP TABLE;", "2:11 syntax-error"},
		{MySQL, "SELECT 1;\n  SELEC 2;\n" + strings.Repeat("SELECT 'x';\n", 500), "2:3 syntax-error"},
		{MySQL, "SELECT (1", "1:10 syntax-error"},
	} {
		got := mustLinter(t, tc.dialect, nil).Lint("x.sql", []byte(tc.src))
		if brief(got) != tc.want || got[0].Severity != SeverityError || len(got[0].Message) > 120 {
			t.Errorf("%s: got %+v, want %s", tc.src, got, tc.want)
		}
	}
}

func TestSuppression(t *testing.T) {
	l := mustLinter(t, Postgres, nil)
	src := "-- dbgw-lint-ignore pg/drop-table -- the table was unused since v2\n" +
		"DROP TABLE legacy;\n" + // lock-timeout is still reported
		"-- dbgw-lint-ignore\n" +
		"\n" +
		"DROP TABLE legacy2;\n" + // every rule is suppressed
		"-- dbgw-lint-ignore pg/prefer-text, pg/prefer-identity\n" +
		"CREATE TABLE t (\n" +
		"  id serial PRIMARY KEY,\n" +
		"  /* dbgw-lint-ignore pg/prefer-timestamptz */\n" +
		"  a timestamp,\n" +
		"  b timestamp,\n" +
		"  c varchar(3)\n" +
		");\n" +
		"-- dbgw-lint-ignored pg/truncate\n" +
		"TRUNCATE t2;\n" +
		"UPDATE t3 SET x = 1; -- dbgw-lint-ignore pg/dml-without-where -- see docs/x\n" +
		"UPDATE t4 SET x = 1;\n" +
		"CREATE TABLE t5 (\n" +
		"  a timestamp, -- dbgw-lint-ignore pg/prefer-timestamptz\n" +
		"  b timestamp\n" +
		");\n" +
		"UPDATE t6 SET x = 1; /* dbgw-lint-ignore pg/dml-without-where */ UPDATE t7 SET x = 1;\n" +
		"UPDATE t8 SET x = 1 -- dbgw-lint-ignore pg/dml-without-where\n" +
		";UPDATE t9 SET x = 1; -- dbgw-lint-ignore pg/dml-without-where"
	got := brief(l.Lint("m.sql", []byte(src)))
	want := "2:1 pg/lock-timeout\n" +
		"11:5 pg/prefer-timestamptz\n" +
		"15:1 pg/truncate\n" +
		"17:1 pg/dml-without-where\n" +
		"18:14 pg/require-primary-key\n" +
		"20:5 pg/prefer-timestamptz"
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}

	m := mustLinter(t, MySQL, nil)
	src = "# dbgw-lint-ignore mysql/drop-table\nDROP TABLE a;\nDROP TABLE b;\n" +
		"SELECT '-- dbgw-lint-ignore';\nTRUNCATE TABLE c;\n" +
		"/* dbgw-lint-ignore mysql/truncate */ TRUNCATE TABLE d; TRUNCATE TABLE e;\n" +
		"TRUNCATE TABLE f; # dbgw-lint-ignore mysql/truncate\n" +
		"TRUNCATE TABLE g;"
	got = brief(m.Lint("m.sql", []byte(src)))
	want = "3:1 mysql/drop-table\n5:1 mysql/truncate\n6:57 mysql/truncate\n8:1 mysql/truncate"
	if got != want {
		t.Errorf("mysql: got\n%s\nwant\n%s", got, want)
	}
}

func TestConfig(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
dialect: postgres
rules:
  pg/prefer-text: off
  pg/drop-table: error
  pg/dml-without-where: info
ignore:
  - files: ["migrations/legacy/**"]
  - files: ["0001_init.sql"]
    rules: [pg/require-primary-key]
`))
	if err != nil {
		t.Fatal(err)
	}
	l := mustLinter(t, Postgres, cfg)
	src := []byte("SET lock_timeout = '1s';\nDROP TABLE a;\nUPDATE b SET x = 1;\nCREATE TABLE c (name varchar(3));\n")
	got := l.Lint("migrations/0002.sql", src)
	if brief(got) != "2:1 pg/drop-table\n3:1 pg/dml-without-where\n4:14 pg/require-primary-key" {
		t.Fatalf("got %s", brief(got))
	}
	if got[0].Severity != SeverityError || got[1].Severity != SeverityInfo || got[2].Severity != SeverityWarning {
		t.Errorf("severities: %+v", got)
	}
	if got := l.Lint("./migrations/legacy/2019/0001.sql", src); got != nil {
		t.Errorf("ignored file: %+v", got)
	}
	if got := brief(l.Lint("db/migrations/0001_init.sql", src)); got != "2:1 pg/drop-table\n3:1 pg/dml-without-where" {
		t.Errorf("ignored rule: %s", got)
	}

	for _, bad := range []string{
		"unknown: 1",
		"rules:\n  pg/no-such-rule: error",
		"rules:\n  pg/drop-table: fatal",
		"dialect: oracle",
		"ignore:\n  - rules: [pg/drop-table]",
		"ignore:\n  - files: [a.sql]\n    rules: [pg/nope]",
		"ignore:\n  - files: [a.sql]\n    rule: [pg/drop-table]",
	} {
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if cfg, err := ParseConfig(nil); err != nil || cfg.Dialect != "" {
		t.Errorf("empty config: %+v, %v", cfg, err)
	}
}

func TestGlob(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"migrations/*.sql", "migrations/0001.sql", true},
		{"migrations/*.sql", "migrations/old/0001.sql", false},
		{"migrations/**/*.sql", "migrations/0001.sql", true},
		{"migrations/**/*.sql", "migrations/a/b/0001.sql", true},
		{"migrations/**", "migrations/a/b.sql", true},
		{"0001_*.sql", "db/migrations/0001_init.sql", true},
		{"0001_?.sql", "0001_ab.sql", false},
		{"./db/x.sql", "db/x.sql", true},
		{"db/x.sql", "other/db/x.sql", false},
		{"db/[a].sql", "db/[a].sql", true},
	} {
		if got := compileGlob(tc.pattern).match(cleanPath(tc.name)); got != tc.want {
			t.Errorf("%s ~ %s = %v", tc.pattern, tc.name, got)
		}
	}
}

func TestDialectRulesOnly(t *testing.T) {
	cfg, err := ParseConfig([]byte("rules:\n  mysql/drop-table: error\n  pg/drop-table: \"off\""))
	if err != nil {
		t.Fatal(err)
	}
	if got := mustLinter(t, Postgres, cfg).Lint("a.sql", []byte("SET lock_timeout='1s'; DROP TABLE a;")); got != nil {
		t.Errorf("pg: %+v", got)
	}
	got := mustLinter(t, MySQL, cfg).Lint("a.sql", []byte("DROP TABLE a;"))
	if len(got) != 1 || got[0].Severity != SeverityError {
		t.Errorf("mysql: %+v", got)
	}
}

func TestRuleMetadata(t *testing.T) {
	for _, r := range Rules("") {
		prefix := map[Dialect]string{Postgres: "pg/", MySQL: "mysql/"}[r.Dialect]
		if !strings.HasPrefix(r.ID, prefix) || r.Summary == "" || r.Hint == "" || r.Severity == 0 {
			t.Errorf("rule %+v", r)
		}
	}
}

func TestWrite(t *testing.T) {
	fs := []Finding{
		{File: "db/1.sql", Line: 3, Column: 5, Rule: "pg/drop-table", Severity: SeverityWarning, Message: "Drop 100%", Hint: "Be careful."},
		{File: "db/a,b:c.sql", Line: 1, Column: 1, Rule: "pg/prefer-text", Severity: SeverityInfo, Message: "x\ny"},
		{File: "db/1.sql", Line: 9, Column: 1, Rule: "syntax-error", Severity: SeverityError, Message: "bad"},
	}
	var b bytes.Buffer
	if err := Write(&b, FormatText, 2, fs); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.String(), "db/1.sql:3:5: warning pg/drop-table: Drop 100%\n    hint: Be careful.\n") {
		t.Errorf("text:\n%s", b.String())
	}

	b.Reset()
	if err := Write(&b, FormatGitHub, 2, fs); err != nil {
		t.Fatal(err)
	}
	want := "::warning file=db/1.sql,line=3,col=5,title=pg/drop-table::Drop 100%25%0AHint: Be careful.\n" +
		"::notice file=db/a%2Cb%3Ac.sql,line=1,col=1,title=pg/prefer-text::x%0Ay\n" +
		"::error file=db/1.sql,line=9,col=1,title=syntax-error::bad\n"
	if b.String() != want {
		t.Errorf("github:\n%s\nwant\n%s", b.String(), want)
	}

	b.Reset()
	if err := Write(&b, FormatJSON, 2, fs); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Findings []map[string]any `json:"findings"`
		Summary  Summary          `json:"summary"`
	}
	if err := json.Unmarshal(b.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Summary != (Summary{Files: 2, Errors: 1, Warnings: 1, Infos: 1}) || out.Findings[0]["severity"] != "warning" || out.Findings[0]["line"] != 3.0 {
		t.Errorf("json: %s", b.String())
	}

	b.Reset()
	if err := Write(&b, FormatJSON, 0, nil); err != nil || !strings.Contains(b.String(), `"findings": []`) {
		t.Errorf("empty json: %s %v", b.String(), err)
	}
	if err := Write(&b, "xml", 0, nil); err == nil {
		t.Error("unknown format accepted")
	}
	if s := Summarize(1, fs[:1]).String(); s != "0 errors, 1 warning, 0 info in 1 file" {
		t.Errorf("summary %q", s)
	}
}
