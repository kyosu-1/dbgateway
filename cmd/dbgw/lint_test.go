package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runDbgw runs the dbgw command with args and returns stdout, stderr and the
// exit status.
func runDbgw(t *testing.T, stdin string, args ...string) (string, string, int) {
	t.Helper()
	root := newRoot()
	var stdout, stderr bytes.Buffer
	root.SetArgs(args)
	root.SetIn(strings.NewReader(stdin))
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	err := root.Execute()
	code := 0
	var exit exitError
	switch {
	case errors.As(err, &exit):
		code = int(exit)
	case err != nil:
		t.Fatalf("unexpected error: %v", err)
	}
	return stdout.String(), stderr.String(), code
}

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLintCommand(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"migrations/0001_init.sql":  "CREATE TABLE users (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, email text NOT NULL);\n",
		"migrations/0002_index.sql": "SET lock_timeout = '5s';\n\nCREATE INDEX users_email ON users (email);\n",
		"migrations/0003_drop.sql":  "SET lock_timeout = '5s';\nALTER TABLE users DROP COLUMN email;\n",
		"migrations/README.md":      "not SQL",
		"lint.yaml":                 "rules:\n  pg/create-index-concurrently: warning\n  pg/drop-column: \"off\"\n",
		"bad.yaml":                  "rules:\n  pg/create-index-concurrently: warning\nbogus: true\n",
	})
	mig := filepath.Join(dir, "migrations")
	f1 := filepath.Join(mig, "0001_init.sql")
	f2 := filepath.Join(mig, "0002_index.sql")
	f3 := filepath.Join(mig, "0003_drop.sql")

	t.Run("clean", func(t *testing.T) {
		out, errOut, code := runDbgw(t, "", "lint", f1)
		if code != 0 || out != "" || !strings.Contains(errOut, "0 errors, 0 warnings, 0 info in 1 file") {
			t.Errorf("code %d\nstdout %q\nstderr %q", code, out, errOut)
		}
	})

	t.Run("directory", func(t *testing.T) {
		out, errOut, code := runDbgw(t, "", "lint", mig)
		want := f2 + ":3:1: error pg/create-index-concurrently: "
		if code != 1 || !strings.HasPrefix(out, want) || !strings.Contains(out, "\n    hint: Use CREATE INDEX CONCURRENTLY") ||
			!strings.Contains(out, f3+":2:1: warning pg/drop-column") || !strings.Contains(errOut, "1 error, 1 warning, 0 info in 3 files") {
			t.Errorf("code %d\nstdout %s\nstderr %s", code, out, errOut)
		}
	})

	t.Run("glob", func(t *testing.T) {
		_, errOut, code := runDbgw(t, "", "lint", filepath.Join(mig, "000[23]_*.sql"))
		if code != 1 || !strings.Contains(errOut, "in 2 files") {
			t.Errorf("code %d, stderr %s", code, errOut)
		}
	})

	t.Run("config", func(t *testing.T) {
		out, _, code := runDbgw(t, "", "lint", "--config", filepath.Join(dir, "lint.yaml"), f2, f3)
		if code != 0 || !strings.Contains(out, "warning pg/create-index-concurrently") || strings.Contains(out, "drop-column") {
			t.Errorf("code %d\n%s", code, out)
		}
	})

	t.Run("github", func(t *testing.T) {
		out, _, code := runDbgw(t, "", "lint", "--format", "github", f2)
		want := "::error file=" + f2 + ",line=3,col=1,title=pg/create-index-concurrently::CREATE INDEX on users"
		if code != 1 || !strings.HasPrefix(out, want) || !strings.Contains(out, "%0AHint: ") {
			t.Errorf("code %d\n%s", code, out)
		}
	})

	t.Run("json", func(t *testing.T) {
		out, errOut, code := runDbgw(t, "", "lint", "-o", "json", f2, f3)
		var res struct {
			Findings []struct {
				File, Rule, Severity string
				Line, Column         int
			}
			Summary struct{ Files, Errors, Warnings int }
		}
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if code != 1 || errOut != "" || res.Summary.Files != 2 || res.Summary.Errors != 1 || res.Summary.Warnings != 1 ||
			res.Findings[0].File != f2 || res.Findings[0].Line != 3 || res.Findings[0].Severity != "error" {
			t.Errorf("code %d, stderr %q\n%s", code, errOut, out)
		}
	})

	t.Run("stdin mysql", func(t *testing.T) {
		out, _, code := runDbgw(t, "ALTER TABLE users ADD COLUMN plan varchar(20), ALGORITHM=INSTANT;\nDELETE FROM users;\n",
			"lint", "--dialect", "mysql", "-")
		if code != 1 || out == "" || !strings.HasPrefix(out, "<stdin>:2:1: error mysql/dml-without-where") {
			t.Errorf("code %d\n%s", code, out)
		}
	})

	t.Run("syntax error", func(t *testing.T) {
		out, _, code := runDbgw(t, "SELECT 1;\nSELEC 2;\n", "lint", "-")
		if code != 1 || !strings.HasPrefix(out, "<stdin>:2:1: error syntax-error") {
			t.Errorf("code %d\n%s", code, out)
		}
	})

	t.Run("list rules", func(t *testing.T) {
		out, _, code := runDbgw(t, "", "lint", "--list-rules", "--dialect", "mysql")
		if code != 0 || !strings.Contains(out, "mysql/alter-algorithm") || strings.Contains(out, "pg/") {
			t.Errorf("code %d\n%s", code, out)
		}
		out, _, _ = runDbgw(t, "", "lint", "--list-rules", "-o", "json")
		var rules []struct{ ID, Severity string }
		if err := json.Unmarshal([]byte(out), &rules); err != nil || len(rules) < 12 || rules[0].Severity == "" {
			t.Errorf("%v\n%s", err, out)
		}
	})

	for name, args := range map[string][]string{
		"no files":       {"lint"},
		"missing file":   {"lint", filepath.Join(dir, "nope.sql")},
		"no glob match":  {"lint", filepath.Join(dir, "*.nope")},
		"empty dir":      {"lint", t.TempDir()},
		"bad config":     {"lint", "--config", filepath.Join(dir, "bad.yaml"), f1},
		"missing config": {"lint", "--config", filepath.Join(dir, "nope.yaml"), f1},
		"bad dialect":    {"lint", "--dialect", "oracle", f1},
		"bad format":     {"lint", "--format", "xml", f1},
		"bad flag":       {"lint", "--nope", f1},
	} {
		t.Run(name, func(t *testing.T) {
			out, errOut, code := runDbgw(t, "", args...)
			if code != lintUsageExit || out != "" || !strings.HasPrefix(errOut, "error: ") {
				t.Errorf("code %d\nstdout %q\nstderr %q", code, out, errOut)
			}
		})
	}
}
