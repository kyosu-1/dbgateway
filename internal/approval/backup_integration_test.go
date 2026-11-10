//go:build integration

package approval_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

const backupSchema = "dbgw_it_backup"

var taro = &identity.Principal{Kind: identity.KindHuman, Human: "taro@example.com", Groups: []string{"dev"}}

// prepareBackup recreates the backup schema, writable by the write user,
// and a small plain-inheritance hierarchy.
func prepareBackup(t *testing.T, su *pgx.Conn) {
	t.Helper()
	for _, q := range []string{
		`DROP SCHEMA IF EXISTS ` + backupSchema + ` CASCADE`,
		`CREATE SCHEMA ` + backupSchema,
		`GRANT USAGE, CREATE ON SCHEMA ` + backupSchema + ` TO dbgw_writer`,
		`DROP TABLE IF EXISTS dbgw_it_parent CASCADE`,
		`CREATE TABLE dbgw_it_parent (id bigint PRIMARY KEY, plan text NOT NULL)`,
		`CREATE TABLE dbgw_it_child (extra text) INHERITS (dbgw_it_parent)`,
		`INSERT INTO dbgw_it_parent VALUES (1, 'free')`,
		`INSERT INTO dbgw_it_child VALUES (2, 'free', 'x')`,
		`GRANT SELECT ON dbgw_it_parent, dbgw_it_child TO dbgw_reader`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON dbgw_it_parent, dbgw_it_child TO dbgw_writer`,
	} {
		if _, err := su.Exec(context.Background(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func backupRows(t *testing.T, su *pgx.Conn, tbl string) map[int64]string {
	t.Helper()
	rows, err := su.Query(context.Background(), "SELECT id, plan FROM "+pgx.Identifier{backupSchema, tbl}.Sanitize())
	if err != nil {
		t.Fatal(err)
	}
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var plan string
		if err := rows.Scan(&id, &plan); err != nil {
			t.Fatal(err)
		}
		out[id] = plan
	}
	return out
}

// submitAndApprove submits sql as p and has hanako approve it.
func (h *harness) submitAndApprove(t *testing.T, p *identity.Principal, sql string) *approval.Request {
	t.Helper()
	resp := h.exec(t, p, sql)
	if resp.Status != gateway.StatusPending {
		t.Fatalf("submit %q: %+v", sql, resp)
	}
	return h.approve(t, resp.RequestID)
}

func TestBackupAndRestore(t *testing.T) {
	su := prepare(t)
	prepareBackup(t, su)
	h := setupWith(t, "    backup: { schema: "+backupSchema+" }\n")
	ctx := context.Background()

	// UPDATE: the changed rows are saved before the write.
	r := h.submitAndApprove(t, agent, "UPDATE "+table+" SET plan = 'pro' WHERE id IN (3, 4)")
	if r.Status != approval.StatusSucceeded || r.Result.Backup == nil {
		t.Fatalf("update: %+v %+v", r, r.Result)
	}
	b := r.Result.Backup
	if b.Schema != backupSchema || b.Table != r.ID || b.Source != "public."+table || b.Rows != 2 || b.RestoreUnavailable != "" {
		t.Fatalf("backup: %+v", b)
	}
	if got := backupRows(t, su, b.Table); len(got) != 2 || got[3] != "free" || got[4] != "free" {
		t.Fatalf("backup rows: %v", got)
	}
	// Later changes to other columns survive the restore: only the
	// assigned columns are set back.
	if _, err := su.Exec(ctx, "UPDATE "+table+" SET email = 'changed@example.com' WHERE id = 3"); err != nil {
		t.Fatal(err)
	}

	// Statements other than the exact restore cannot use the backup.
	bk := backupSchema + "." + b.Table
	for _, sql := range []string{
		"SELECT * FROM " + bk,
		"SELECT count(*) FROM " + bk + " WHERE plan = 'free'",
		"DELETE FROM " + bk + " WHERE id = 3",
		"UPDATE " + table + " AS t SET plan = b.email FROM " + bk + " AS b WHERE t.id = b.id RETURNING t.plan",
		b.RestoreSQL + " RETURNING t.plan",
		strings.Replace(b.RestoreSQL, "plan", "email", 1),
	} {
		if resp := h.exec(t, hanako, sql); resp.Status != gateway.StatusDenied || resp.Rule != "builtin:backup-protected" {
			t.Errorf("%s: %+v", sql, resp)
		}
	}
	// The backup schema is hidden from exploration.
	if sr, err := h.gw.SearchObjects(ctx, hanako, gateway.SearchRequest{Database: "it", Schema: backupSchema, Detail: "full"}); err != nil || len(sr.Objects) != 0 {
		t.Fatalf("search: %+v %v", sr, err)
	}

	// The restore statement is an ordinary write: it needs approval, and
	// an agent can submit it (backup columns are classified like the
	// columns they were copied from). It is itself backed up.
	if !strings.HasPrefix(b.RestoreSQL, "UPDATE ") {
		t.Fatalf("restore sql: %q", b.RestoreSQL)
	}
	rr := h.submitAndApprove(t, agent, b.RestoreSQL)
	if rr.Status != approval.StatusSucceeded || rr.Result.RowsAffected != 2 || rr.Result.Backup == nil || rr.Result.Backup.Rows != 2 {
		t.Fatalf("restore: %+v %+v", rr, rr.Result)
	}
	if p := plans(t, su); p[3] != "free" || p[4] != "free" {
		t.Fatalf("not restored: %v", p)
	}
	var email string
	if err := su.QueryRow(ctx, "SELECT email FROM "+table+" WHERE id = 3").Scan(&email); err != nil || email != "changed@example.com" {
		t.Fatalf("email = %q, %v", email, err)
	}

	// DELETE: the deleted rows can be inserted again.
	r = h.submitAndApprove(t, agent, "DELETE FROM "+table+" WHERE id = 9")
	if r.Status != approval.StatusSucceeded || r.Result.Backup == nil || r.Result.Backup.Rows != 1 {
		t.Fatalf("delete: %+v %+v", r, r.Result)
	}
	if !strings.HasPrefix(r.Result.Backup.RestoreSQL, "INSERT INTO ") {
		t.Fatalf("restore sql: %q", r.Result.Backup.RestoreSQL)
	}
	rr = h.submitAndApprove(t, agent, r.Result.Backup.RestoreSQL)
	if rr.Status != approval.StatusSucceeded || rr.Result.RowsAffected != 1 {
		t.Fatalf("restore: %+v %+v", rr, rr.Result)
	}
	if plans(t, su)[9] != "free" {
		t.Fatal("not re-inserted")
	}

	// A statement that cannot be backed up still runs (backups are not
	// required here), and says so.
	r = h.submitAndApprove(t, agent, "UPDATE "+table+" SET plan = 'x' FROM (SELECT 5 AS id) s WHERE "+table+".id = s.id")
	if r.Status != approval.StatusSucceeded || r.Result.Backup == nil || r.Result.Backup.Table != "" ||
		r.Result.Backup.RestoreUnavailable != "No backup was taken (UPDATE ... FROM)." {
		t.Fatalf("unsupported: %+v %+v", r, r.Result)
	}

	// Rows deleted through a plain-inheritance parent came from a child:
	// backed up, but no generated restore.
	r = h.submitAndApprove(t, taro, "DELETE FROM dbgw_it_parent WHERE id = 2")
	if r.Status != approval.StatusSucceeded || r.Result.Backup == nil || r.Result.Backup.Rows != 1 ||
		r.Result.Backup.RestoreSQL != "" || !strings.Contains(r.Result.Backup.RestoreUnavailable, "inheritance") {
		t.Fatalf("inheritance: %+v %+v", r, r.Result)
	}
}

// A statement whose WHERE calls a volatile function could select different
// rows for the backup and the write, so it is not backed up.
func TestBackupRefusesVolatileFunctions(t *testing.T) {
	su := prepare(t)
	prepareBackup(t, su)
	h := setupWith(t, "    backup: { schema: "+backupSchema+" }\n")
	sql := "UPDATE " + table + " SET plan = 'rnd' WHERE id = (SELECT id FROM " + table + " ORDER BY random() LIMIT 1)"
	r := h.submitAndApprove(t, taro, sql)
	if r.Status != approval.StatusSucceeded || r.Result.Backup == nil || r.Result.Backup.Table != "" ||
		!strings.Contains(r.Result.Backup.RestoreUnavailable, "volatile function random()") {
		t.Fatalf("volatile: %+v %+v", r, r.Result)
	}
	h = setupWith(t, "    backup: { schema: "+backupSchema+", required: true }\n")
	if resp := h.exec(t, taro, sql); resp.Status != gateway.StatusDenied || resp.Rule != "builtin:backup-unsupported" {
		t.Fatalf("required: %+v", resp)
	}
}

// A failed backup is described like a database error: values quoted by
// the database never reach the result.
func TestBackupErrorWithholdsValues(t *testing.T) {
	su := prepare(t)
	prepareBackup(t, su)
	h := setupWith(t, "    backup: { schema: "+backupSchema+" }\n")
	r := h.submitAndApprove(t, taro, "UPDATE "+table+" SET plan = 'x' WHERE id = (SELECT email FROM "+table+" WHERE id = 1)::bigint")
	if r.Status != approval.StatusFailed || strings.Contains(r.Result.Error, "acct1@example.com") || r.Result.Code != "22P02" {
		t.Fatalf("result: %+v", r.Result)
	}
	if !strings.HasPrefix(r.Result.Error, "Not executed because the backup failed") {
		t.Fatalf("error: %q", r.Result.Error)
	}
	if plans(t, su)[1] != "free" {
		t.Fatal("written")
	}
}

func TestBackupRequired(t *testing.T) {
	su := prepare(t)
	prepareBackup(t, su)
	h := setupWith(t, "    backup: { schema: "+backupSchema+", required: true }\n")
	ctx := context.Background()
	sql := "DELETE FROM " + table + " USING (SELECT 5 AS id) s WHERE " + table + ".id = s.id"
	if resp := h.exec(t, agent, sql); resp.Status != gateway.StatusDenied || resp.Rule != "builtin:backup-unsupported" {
		t.Fatalf("unsupported: %+v", resp)
	}
	if ex, err := h.gw.ExplainPolicy(ctx, agent, gateway.ExplainRequest{Database: "it", SQL: sql}); err != nil ||
		ex.Decision != "deny" || ex.Rule != "builtin:backup-unsupported" {
		t.Fatalf("explain: %+v %v", ex, err)
	}
	// Restores can be backed up, so they run under required backups too.
	r := h.submitAndApprove(t, agent, "UPDATE "+table+" SET plan = 'pro' WHERE id = 6")
	if r.Status != approval.StatusSucceeded || r.Result.Backup == nil || r.Result.Backup.RestoreSQL == "" {
		t.Fatalf("update: %+v %+v", r, r.Result)
	}
	rr := h.submitAndApprove(t, agent, r.Result.Backup.RestoreSQL)
	if rr.Status != approval.StatusSucceeded || plans(t, su)[6] != "free" {
		t.Fatalf("restore: %+v %+v", rr, rr.Result)
	}
}
