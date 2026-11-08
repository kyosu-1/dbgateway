//go:build integration

// Integration tests of the full write flow (submit → approve → execute)
// against a real PostgreSQL started with
//
//	docker compose -f examples/dev/compose.yaml up -d --wait
//
// Run with: go test -tags integration ./internal/approval/
//
// The write user (dbgw_writer) and a dedicated table are created with the
// superuser when missing, since initdb scripts only run on a fresh volume.
package approval_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kyosu-1/dbgateway/internal/adapter/postgres"
	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

const table = "dbgw_it_accounts"

// superuser connects as the PostgreSQL superuser.
func superuser(t *testing.T) *pgx.Conn {
	t.Helper()
	u := url.URL{Scheme: "postgres", Host: env("DBGW_TEST_PG_HOST", "127.0.0.1") + ":" + env("DBGW_TEST_PG_PORT", "55432"), Path: "/app",
		User: url.UserPassword(env("DBGW_TEST_PG_SUPERUSER", "postgres"), env("DBGW_TEST_PG_SUPERPASSWORD", "postgres"))}
	q := url.Values{"sslmode": {env("DBGW_TEST_PG_SSLMODE", "disable")}}
	if rc := env("DBGW_TEST_PG_SSLROOTCERT", ""); rc != "" {
		q.Set("sslrootcert", rc)
	}
	u.RawQuery = q.Encode()
	c, err := pgx.Connect(context.Background(), u.String())
	if err != nil {
		t.Fatalf("connect as superuser: %v", err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

// prepare creates the write user (idempotently) and resets the test table.
func prepare(t *testing.T) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	su := superuser(t)
	for _, q := range []string{
		`DO $$ BEGIN
		   IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbgw_writer') THEN
		     CREATE ROLE dbgw_writer LOGIN PASSWORD 'writer';
		   END IF;
		 END $$`,
		`GRANT CONNECT ON DATABASE app TO dbgw_writer`,
		`GRANT USAGE ON SCHEMA public TO dbgw_writer`,
		`CREATE TABLE IF NOT EXISTS ` + table + ` (id bigint PRIMARY KEY, email text NOT NULL, plan text NOT NULL)`,
		`TRUNCATE ` + table,
		`INSERT INTO ` + table + ` SELECT g, 'acct' || g || '@example.com', 'free' FROM generate_series(1, 20) g`,
		`ANALYZE ` + table,
		`GRANT SELECT ON ` + table + ` TO dbgw_reader`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ` + table + ` TO dbgw_writer`,
	} {
		if _, err := su.Exec(ctx, q); err != nil {
			t.Fatalf("prepare: %s: %v", q, err)
		}
	}
	return su
}

type harness struct {
	gw  *gateway.Gateway
	svc *approval.Service
}

func setup(t *testing.T) *harness {
	t.Helper()
	t.Setenv("DBGW_IT_PASSWORD", env("DBGW_TEST_PG_PASSWORD", "reader"))
	t.Setenv("DBGW_IT_WRITER_PASSWORD", env("DBGW_TEST_PG_WRITER_PASSWORD", "writer"))
	yaml := fmt.Sprintf(`
auth: { dev_login: true }
approvals: { enabled: true }
databases:
  - name: it
    labels: { env: prod }
    primary:
      host: %s
      port: %s
      dbname: app
      read_user: dbgw_reader
      password_env: DBGW_IT_PASSWORD
      write_user: dbgw_writer
      write_password_env: DBGW_IT_WRITER_PASSWORD
      sslmode: %s
      sslrootcert: "%s"
    limits: { max_rows: 50, statement_timeout: 3s }
groups:
  - { name: dev, members: [taro@example.com] }
  - { name: sre, members: [hanako@example.com] }
role_bindings:
  - { group: dev, databases: "*", roles: [querier, writer] }
  - { group: sre, databases: "*", roles: [querier, writer, approver] }
data_classes:
  - { columns: ["public.%[5]s.email"], class: masked }
  - { column_pattern: "public\\.%[5]s\\.(id|plan)", class: public }
approval_rules:
  - name: deletes
    when: stmt.kind == "delete"
    steps: [{ role: approver }]
    max_affected_rows: 2
  - name: default
    when: "true"
    steps: [{ role: approver }]
break_glass:
  databases: "*"
`, env("DBGW_TEST_PG_HOST", "127.0.0.1"), env("DBGW_TEST_PG_PORT", "55432"),
		env("DBGW_TEST_PG_SSLMODE", "disable"), env("DBGW_TEST_PG_SSLROOTCERT", ""), table)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sink, err := audit.OpenFileSink(filepath.Join(dir, "audit"), 0, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	al, _ := audit.New(sink)
	st, err := store.OpenSQLite(context.Background(), filepath.Join(dir, "dbgw.db"))
	if err != nil {
		t.Fatal(err)
	}
	gw, err := gateway.New(gateway.Options{Config: cfg, Adapters: map[string]analysis.Adapter{"postgres": postgres.New(nil)}, Audit: al})
	if err != nil {
		t.Fatal(err)
	}
	svc := approval.New(approval.Options{Config: cfg, Store: st, Executor: gw, Audit: al, Logger: slog.New(slog.DiscardHandler)})
	gw.SetApprovals(svc)
	t.Cleanup(func() { svc.Wait(); gw.Close(); st.Close(); _ = al.Close() })
	return &harness{gw: gw, svc: svc}
}

var (
	agent = &identity.Principal{Kind: identity.KindAgent, Human: "taro@example.com", Agent: "claude-code", Groups: []string{"dev"},
		Scopes: []string{identity.ScopeRead, identity.ScopeWrite}}
	hanako = &identity.Principal{Kind: identity.KindHuman, Human: "hanako@example.com", Groups: []string{"sre"}}
)

func (h *harness) exec(t *testing.T, p *identity.Principal, sql string) *gateway.ExecuteResponse {
	t.Helper()
	return h.gw.ExecuteSQL(context.Background(), p, gateway.ExecuteRequest{Database: "it", SQL: sql, Reason: "integration test: approved write flow"})
}

func (h *harness) approve(t *testing.T, id string) *approval.Request {
	t.Helper()
	if _, err := h.svc.Approve(context.Background(), hanako, id, approval.StepUp{Method: "passkey", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	h.svc.Wait()
	r, err := h.svc.Get(context.Background(), hanako, id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func plans(t *testing.T, su *pgx.Conn) map[int64]string {
	t.Helper()
	rows, err := su.Query(context.Background(), "SELECT id, plan FROM "+table)
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

func TestApprovedWriteFlow(t *testing.T) {
	su := prepare(t)
	h := setup(t)
	resp := h.exec(t, agent, "UPDATE "+table+" SET plan = 'pro' WHERE id = 2 RETURNING id, email, plan")
	if resp.Status != gateway.StatusPending {
		t.Fatalf("submit: %+v", resp)
	}
	// The estimate comes from EXPLAIN by the write user (primary key lookup).
	if resp.MaxAffectedRows != 2 || len(resp.Approvers) != 1 || resp.Approvers[0] != "hanako@example.com" {
		t.Fatalf("pending: %+v", resp)
	}
	if plans(t, su)[2] != "free" {
		t.Fatal("written before approval")
	}
	r := h.approve(t, resp.RequestID)
	if r.Status != approval.StatusSucceeded || r.Result.RowsAffected != 1 || r.Result.RowCount != 1 {
		t.Fatalf("result: %+v %+v", r, r.Result)
	}
	row := r.Result.Rows[0]
	if row[1] == "acct2@example.com" || row[2] != "pro" || !r.Result.Columns[1].Masked {
		t.Fatalf("RETURNING must be masked for the agent: %v %+v", row, r.Result.Columns)
	}
	if p := plans(t, su); p[2] != "pro" || p[3] != "free" {
		t.Fatalf("database: %v", p)
	}
	// The read pool is still read-only and the writer's session state is
	// reset: a read sees the committed change.
	if rr := h.exec(t, agent, "SELECT plan FROM "+table+" WHERE id = 2"); rr.Status != gateway.StatusOK || rr.Rows[0][0] != "pro" {
		t.Fatalf("read after write: %+v", rr)
	}
}

func TestAffectedRowsLimitRollsBack(t *testing.T) {
	su := prepare(t)
	h := setup(t)
	resp := h.exec(t, agent, "DELETE FROM "+table+" WHERE id <= 5")
	if resp.Status != gateway.StatusPending || resp.ApprovalRule != "deletes" || resp.MaxAffectedRows != 2 {
		t.Fatalf("submit: %+v", resp)
	}
	r := h.approve(t, resp.RequestID)
	if r.Status != approval.StatusFailed || !strings.Contains(r.Result.Error, "ロールバック") {
		t.Fatalf("result: %+v %+v", r, r.Result)
	}
	if n := len(plans(t, su)); n != 20 {
		t.Fatalf("rows after rollback = %d, want 20", n)
	}
}

func TestBreakGlassWriteOnRealDB(t *testing.T) {
	su := prepare(t)
	h := setup(t)
	if _, err := h.svc.Elevate(context.Background(), hanako, []string{"it"}, "incident #42", 10*time.Minute,
		approval.StepUp{Method: "passkey", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	r := h.exec(t, hanako, "UPDATE "+table+" SET plan = 'team' WHERE id = 7")
	if r.Status != gateway.StatusOK || !r.BreakGlass || r.RowsAffected == nil || *r.RowsAffected != 1 {
		t.Fatalf("break-glass: %+v", r)
	}
	if plans(t, su)[7] != "team" {
		t.Fatal("not written")
	}
}

func TestWriteUserCannotRunDDL(t *testing.T) {
	prepare(t)
	h := setup(t)
	// DDL never reaches the database (policy), and the writer has no DDL
	// privilege anyway; a write without WHERE is still subject to approval.
	if r := h.exec(t, hanako, "DROP TABLE "+table); r.Status != gateway.StatusDenied {
		t.Fatalf("ddl: %+v", r)
	}
	if r := h.exec(t, hanako, "TRUNCATE "+table); r.Status != gateway.StatusDenied {
		t.Fatalf("truncate: %+v", r)
	}
}
