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

// prepareBackup recreates the backup schema, writable by the write user.
func prepareBackup(t *testing.T, su *pgx.Conn) {
	t.Helper()
	for _, q := range []string{
		`DROP SCHEMA IF EXISTS ` + backupSchema + ` CASCADE`,
		`CREATE SCHEMA ` + backupSchema,
		`GRANT USAGE, CREATE ON SCHEMA ` + backupSchema + ` TO dbgw_writer`,
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
	if p := plans(t, su); p[3] != "pro" || p[4] != "pro" {
		t.Fatalf("not written: %v", p)
	}
	// Later changes to other columns survive the restore: only the
	// assigned columns are set back.
	if _, err := su.Exec(context.Background(), "UPDATE "+table+" SET email = 'changed@example.com' WHERE id = 3"); err != nil {
		t.Fatal(err)
	}

	// The restore statement is an ordinary write: it needs approval.
	if !strings.HasPrefix(b.RestoreSQL, "UPDATE ") {
		t.Fatalf("restore sql: %q", b.RestoreSQL)
	}
	rr := h.submitAndApprove(t, taro, b.RestoreSQL)
	if rr.Status != approval.StatusSucceeded || rr.Result.RowsAffected != 2 {
		t.Fatalf("restore: %+v %+v", rr, rr.Result)
	}
	if p := plans(t, su); p[3] != "free" || p[4] != "free" {
		t.Fatalf("not restored: %v", p)
	}
	var email string
	if err := su.QueryRow(context.Background(), "SELECT email FROM "+table+" WHERE id = 3").Scan(&email); err != nil || email != "changed@example.com" {
		t.Fatalf("email = %q, %v", email, err)
	}

	// DELETE: the deleted rows can be inserted again.
	r = h.submitAndApprove(t, agent, "DELETE FROM "+table+" WHERE id = 9")
	if r.Status != approval.StatusSucceeded || r.Result.Backup == nil || r.Result.Backup.Rows != 1 {
		t.Fatalf("delete: %+v %+v", r, r.Result)
	}
	if _, ok := plans(t, su)[9]; ok {
		t.Fatal("not deleted")
	}
	if !strings.HasPrefix(r.Result.Backup.RestoreSQL, "INSERT INTO ") {
		t.Fatalf("restore sql: %q", r.Result.Backup.RestoreSQL)
	}
	rr = h.submitAndApprove(t, taro, r.Result.Backup.RestoreSQL)
	if rr.Status != approval.StatusSucceeded || rr.Result.RowsAffected != 1 {
		t.Fatalf("restore: %+v %+v", rr, rr.Result)
	}
	if plans(t, su)[9] != "free" {
		t.Fatal("not re-inserted")
	}

	// Backup tables can only be read by restores, and never changed.
	bk := backupSchema + "." + b.Table
	for _, sql := range []string{
		"SELECT * FROM " + bk,
		"SELECT count(*) FROM " + bk + " WHERE plan = 'free'",
		"DELETE FROM " + bk + " WHERE id = 3",
		"UPDATE " + table + " AS t SET plan = 'x' FROM " + bk + " AS b WHERE t.id = b.id RETURNING b.email",
	} {
		if resp := h.exec(t, hanako, sql); resp.Status != gateway.StatusDenied || resp.Rule != "builtin:backup-protected" {
			t.Errorf("%s: %+v", sql, resp)
		}
	}

	// A statement that cannot be backed up still runs (backups are not
	// required here), and says so.
	r = h.submitAndApprove(t, agent, "UPDATE "+table+" SET plan = 'x' FROM (SELECT 5 AS id) s WHERE "+table+".id = s.id")
	if r.Status != approval.StatusSucceeded || r.Result.Backup == nil || r.Result.Backup.Table != "" ||
		!strings.Contains(r.Result.Backup.RestoreUnavailable, "No backup was taken") {
		t.Fatalf("unsupported: %+v %+v", r, r.Result)
	}
}

func TestBackupRequired(t *testing.T) {
	su := prepare(t)
	prepareBackup(t, su)
	h := setupWith(t, "    backup: { schema: "+backupSchema+", required: true }\n")
	resp := h.exec(t, agent, "DELETE FROM "+table+" USING (SELECT 5 AS id) s WHERE "+table+".id = s.id")
	if resp.Status != gateway.StatusDenied || resp.Rule != "builtin:backup-unsupported" {
		t.Fatalf("unsupported: %+v", resp)
	}
	// A write the backup does not match is rolled back: a WHERE clause
	// with a volatile function selects different rows each time.
	r := h.submitAndApprove(t, agent, "UPDATE "+table+" SET plan = 'rnd' WHERE id = 1 OR random() < 0.5")
	if r.Status == approval.StatusSucceeded {
		// The two evaluations happened to agree; nothing to check.
		t.Skip("random() selected the same rows twice")
	}
	if p := plans(t, su); p[1] != "free" {
		t.Fatalf("written although the backup did not match: %v", p)
	}
}
