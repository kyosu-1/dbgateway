//go:build integration

package mysql_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/kyosu-1/dbgateway/internal/adapter/mysql"
	"github.com/kyosu-1/dbgateway/internal/analysis"
)

// ensureWriter creates the dbgw_writer user (idempotently) as root.
func ensureWriter(t *testing.T) {
	t.Helper()
	root, err := sql.Open("mysql", fmt.Sprintf("root:%s@tcp(%s:%d)/app", env("DBGW_TEST_MYSQL_ROOT_PASSWORD", "root"), env("DBGW_TEST_MYSQL_HOST", "127.0.0.1"), port()))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, q := range []string{
		"CREATE USER IF NOT EXISTS 'dbgw_writer'@'%' IDENTIFIED BY 'writer'",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON app.* TO 'dbgw_writer'@'%'",
	} {
		if _, err := root.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func writeConn(t *testing.T) (*mysql.Adapter, analysis.Conn) {
	t.Helper()
	ensureWriter(t)
	db := dbConfig(t, "dbgw_reader", "reader")
	t.Setenv("DBGW_IT_MYSQL_WRITER", "writer")
	db.Primary.WriteUser, db.Primary.WritePasswordEnv = "dbgw_writer", "DBGW_IT_MYSQL_WRITER"
	a := mysql.New(nil)
	c, err := a.Connect(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return a, c
}

func writeOpts(maxAffected int64) analysis.ExecOptions {
	return analysis.ExecOptions{ReadOnly: false, MaxRows: 100, MaxBytes: 1 << 20, StatementTimeout: 2 * time.Second,
		LockTimeout: time.Second, MaxAffectedRows: maxAffected}
}

func planOf(t *testing.T, a *mysql.Adapter, c analysis.Conn) func(string) string {
	return func(q string) string {
		res, err := a.Execute(context.Background(), c, q, readOpts())
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprint(res.Rows[0][0])
	}
}

func TestWriteExecution(t *testing.T) {
	a, c := writeConn(t)
	get := planOf(t, a, c)
	ctx := context.Background()

	orig := get("SELECT plan FROM users WHERE id = 7")
	target := "pro"
	if orig == "pro" {
		target = "free"
	}
	t.Cleanup(func() {
		_, _ = a.Execute(ctx, c, "UPDATE users SET plan = '"+orig+"' WHERE id = 7", writeOpts(1))
	})

	// Estimate a write with the write user (EXPLAIN only).
	est, err := a.Estimate(ctx, c, "UPDATE users SET plan = 'x' WHERE id < 50", writeOpts(1))
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	if est.Rows < 1 {
		t.Errorf("estimate rows = %v", est.Rows)
	}

	res, err := a.Execute(ctx, c, "UPDATE users SET plan = '"+target+"' WHERE id = 7", writeOpts(1))
	if err != nil || res.RowsAffected != 1 {
		t.Fatalf("write: %v %+v", err, res)
	}
	if got := get("SELECT plan FROM users WHERE id = 7"); got != target {
		t.Fatalf("plan = %s, want %s", got, target)
	}

	// Over the limit: rolled back.
	before := get("SELECT count(*) FROM users WHERE plan = 'zzz'")
	_, err = a.Execute(ctx, c, "UPDATE users SET plan = 'zzz' WHERE id <= 5", writeOpts(2))
	var ar *analysis.AffectedRowsError
	if !errors.As(err, &ar) || ar.Affected != 5 {
		t.Fatalf("expected AffectedRowsError, got %v", err)
	}
	if got := get("SELECT count(*) FROM users WHERE plan = 'zzz'"); got != before {
		t.Fatalf("write was not rolled back: %s", got)
	}

	// Unchanged rows still count (CLIENT_FOUND_ROWS).
	_, err = a.Execute(ctx, c, "UPDATE users SET plan = plan WHERE id <= 3", writeOpts(2))
	if !errors.As(err, &ar) || ar.Affected != 3 {
		t.Fatalf("unchanged rows must count towards the limit, got %v", err)
	}
}

func TestWriteRequiresWriteUser(t *testing.T) {
	a, c := connect(t, "dbgw_reader", "reader")
	if _, err := a.Execute(context.Background(), c, "UPDATE users SET plan = plan WHERE id = 1", writeOpts(1)); err == nil {
		t.Fatal("write without write_user must fail")
	}
}
