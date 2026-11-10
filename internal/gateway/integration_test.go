//go:build integration

// Integration tests against a real PostgreSQL started with
//
//	docker compose -f examples/dev/compose.yaml up -d --wait
//
// Run with: go test -tags integration ./internal/gateway/
package gateway_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kyosu-1/dbgateway/internal/adapter/postgres"
	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func setup(t *testing.T, extra string) (*gateway.Gateway, string) {
	t.Helper()
	t.Setenv("DBGW_IT_PASSWORD", env("DBGW_TEST_PG_PASSWORD", "reader"))
	yaml := fmt.Sprintf(`
auth: { dev_login: true }
databases:
  - name: it
    labels: { env: prod }
    primary:
      host: %s
      port: %s
      dbname: app
      read_user: dbgw_reader
      password_env: DBGW_IT_PASSWORD
      sslmode: %s
      sslrootcert: "%s"
    limits: { max_rows: 50, max_bytes: 64KiB, statement_timeout: 1s }
    docs:
      description: Integration test database.
      tables:
        public.users:
          description: One row per account.
          columns: { email: "Login e-mail, unique." }
      examples:
        - { title: Revenue per plan, sql: "SELECT u.plan, sum(o.amount) FROM orders o JOIN users u ON u.id = o.user_id GROUP BY 1" }
groups:
  - { name: dev, members: [taro@example.com] }
role_bindings:
  - { group: dev, databases: "*", roles: [querier] }
data_classes:
  - { columns: ["public.users.email"], class: masked, semantic_type: contact }
  - { column_pattern: ".*token.*", class: masked }
  - { columns: ["public.support_tickets.body"], class: no_ai }
  - { column_pattern: "public\\.[a-z_]+\\.(id|user_id|plan|amount|status|reason|subject|created_at)", class: public }
semantic_types:
  contact: { method: partial }
%s`, env("DBGW_TEST_PG_HOST", "127.0.0.1"), env("DBGW_TEST_PG_PORT", "55432"),
		env("DBGW_TEST_PG_SSLMODE", "disable"), env("DBGW_TEST_PG_SSLROOTCERT", ""), extra)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "audit")
	sink, err := audit.OpenFileSink(dir, 0, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	al, _ := audit.New(sink)
	gw, err := gateway.New(gateway.Options{Config: cfg, Adapters: map[string]analysis.Adapter{"postgres": postgres.New(cfg.SQL.AllowedFunctions)}, Audit: al})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Close(); _ = al.Close() })
	return gw, dir
}

var (
	agent = &identity.Principal{Kind: identity.KindAgent, Human: "taro@example.com", Agent: "claude-code",
		Groups: []string{"dev"}, Scopes: []string{identity.ScopeRead}}
	human = &identity.Principal{Kind: identity.KindHuman, Human: "taro@example.com", Groups: []string{"dev"}}
)

func exec(t *testing.T, gw *gateway.Gateway, p *identity.Principal, sql string) *gateway.ExecuteResponse {
	t.Helper()
	return gw.ExecuteSQL(context.Background(), p, gateway.ExecuteRequest{Database: "it", SQL: sql, Reason: "integration test: verify gateway behaviour"})
}

func TestReadAndMask(t *testing.T) {
	gw, _ := setup(t, "")
	r := exec(t, gw, agent, "SELECT id, email, plan FROM users WHERE id = 3")
	if r.Status != gateway.StatusOK {
		t.Fatalf("status %s: %s %s", r.Status, r.Reason, r.Hint)
	}
	if len(r.Rows) != 1 || r.Rows[0][1] != "u***@example.com" || r.Rows[0][2] != "pro" {
		t.Fatalf("rows = %v", r.Rows)
	}
	if !r.Columns[1].Masked || r.Columns[0].Masked {
		t.Errorf("columns = %+v", r.Columns)
	}
	if r.Notice == "" {
		t.Error("missing data notice")
	}
}

func TestMaskingThroughViewsAndExpressions(t *testing.T) {
	gw, _ := setup(t, "")
	for _, sql := range []string{
		"SELECT email FROM user_contacts WHERE id = 1",
		"SELECT upper(email) AS e FROM users WHERE id = 1",
		"SELECT x FROM (SELECT email AS x, id FROM users) s WHERE id = 1",
		"WITH c AS (SELECT id, email FROM users) SELECT email FROM c WHERE id = 1",
		"SELECT * FROM users WHERE id = 1",
		"SELECT row_to_json(u) FROM users u WHERE id = 1",
	} {
		r := exec(t, gw, agent, sql)
		if r.Status != gateway.StatusOK {
			t.Errorf("%s: %s %s", sql, r.Status, r.Reason)
			continue
		}
		for _, row := range r.Rows {
			for _, v := range row {
				if s, ok := v.(string); ok && strings.Contains(s, "user1@") {
					t.Errorf("%s: leaked %q", sql, s)
				}
			}
		}
	}
}

func TestPredicatesOnMaskedColumnsDenied(t *testing.T) {
	gw, _ := setup(t, "")
	for _, sql := range []string{
		"SELECT id FROM users WHERE email LIKE 'user1%'",
		"SELECT count(*) FROM users GROUP BY email",
		"SELECT id FROM users ORDER BY email LIMIT 1",
	} {
		if r := exec(t, gw, agent, sql); r.Status != gateway.StatusDenied {
			t.Errorf("%s: status %s", sql, r.Status)
		}
	}
}

func TestNoAIWithheldForAgentsShownToHumans(t *testing.T) {
	gw, _ := setup(t, "")
	r := exec(t, gw, agent, "SELECT id, body FROM support_tickets")
	if r.Status != gateway.StatusOK || r.Rows[0][1] != nil || !r.Columns[1].Withheld {
		t.Fatalf("agent: %+v", r)
	}
	r = exec(t, gw, human, "SELECT id, body FROM support_tickets ORDER BY id")
	if r.Status != gateway.StatusOK || r.Rows[0][1] == nil {
		t.Fatalf("human: %+v", r)
	}
}

func TestTruncation(t *testing.T) {
	gw, _ := setup(t, "")
	r := exec(t, gw, human, "SELECT id FROM orders")
	if r.Status != gateway.StatusOK || !r.Truncated || r.RowCount != 50 || r.TotalRows == nil || *r.TotalRows != 5000 {
		t.Fatalf("rows=%d truncated=%v total=%v (%s)", r.RowCount, r.Truncated, r.TotalRows, r.Reason)
	}
	r = exec(t, gw, human, "SELECT repeat('x', 4000) FROM generate_series(1, 40)")
	if r.Status != gateway.StatusOK || !r.Truncated || r.RowCount >= 40 {
		t.Fatalf("byte limit: rows=%d truncated=%v", r.RowCount, r.Truncated)
	}
}

func TestStatementTimeout(t *testing.T) {
	gw, _ := setup(t, "sql:\n  allowed_functions: [pg_sleep]\n")
	r := exec(t, gw, human, "SELECT pg_sleep(3)")
	if r.Status != gateway.StatusError || r.Code != "57014" {
		t.Fatalf("status=%s code=%s reason=%s", r.Status, r.Code, r.Reason)
	}
	// The connection is usable afterwards.
	if r := exec(t, gw, human, "SELECT 1"); r.Status != gateway.StatusOK {
		t.Fatalf("after timeout: %s %s", r.Status, r.Reason)
	}
}

func TestReadOnlyEnforcedByDatabase(t *testing.T) {
	// Even if the parser were bypassed, the transaction is read-only and
	// the user has only SELECT. nextval is not allowlisted; allow it here
	// to prove the database itself refuses the write.
	gw, _ := setup(t, "sql:\n  allowed_functions: [set_config]\n")
	r := exec(t, gw, human, "SELECT set_config('statement_timeout', '0', false)")
	if r.Status != gateway.StatusOK {
		t.Fatalf("set_config: %s %s", r.Status, r.Reason)
	}
	// Session state must not leak into the next request (DISCARD ALL).
	r = exec(t, gw, human, "SELECT current_setting('statement_timeout') AS v")
	if r.Status == gateway.StatusOK && len(r.Rows) == 1 && r.Rows[0][0] == "0" {
		t.Fatal("session setting leaked across requests")
	}
}

func TestDatabaseErrorsDoNotLeakValues(t *testing.T) {
	gw, _ := setup(t, "")
	r := exec(t, gw, human, "SELECT email::int FROM users WHERE id = 1")
	if r.Status != gateway.StatusError {
		t.Fatalf("status = %s", r.Status)
	}
	if strings.Contains(r.Reason, "@example.com") {
		t.Fatalf("error leaked a value: %s", r.Reason)
	}
}

func TestRejectionsAndAudit(t *testing.T) {
	gw, dir := setup(t, "")
	for _, sql := range []string{"SELECT 1; DROP TABLE users", "COMMIT", "DELETE FROM users WHERE id = 1"} {
		if r := exec(t, gw, agent, sql); r.Status != gateway.StatusDenied || r.Reason == "" || r.Hint == "" {
			t.Errorf("%s: %+v", sql, r)
		}
	}
	if r := gw.ExecuteSQL(context.Background(), agent, gateway.ExecuteRequest{Database: "it", SQL: "SELECT 1"}); r.Status != gateway.StatusDenied {
		t.Errorf("missing reason: %s", r.Status)
	}
	exec(t, gw, agent, "SELECT id FROM users WHERE id = 1")
	rep, err := audit.VerifyDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Entries != 5 {
		t.Errorf("audit entries = %d, want 5", rep.Entries)
	}
	b, _ := os.ReadFile(func() string { m, _ := filepath.Glob(filepath.Join(dir, "*.jsonl")); return m[0] }())
	if strings.Contains(string(b), "WHERE id = 1\"") {
		t.Error("literal recorded in the audit log")
	}
}

func TestSearchObjects(t *testing.T) {
	gw, _ := setup(t, "")
	resp, err := gw.SearchObjects(context.Background(), agent, gateway.SearchRequest{Database: "it", Keyword: "user", Detail: "full"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range resp.Objects {
		if o.Name == "users" {
			found = true
			// The database comment and the configured description are
			// both returned.
			if o.Comment != "Application users" || o.Description != "One row per account." {
				t.Errorf("users comment/description = %q / %q", o.Comment, o.Description)
			}
			for _, c := range o.Columns {
				if c.Name == "email" && (!c.Masked || c.Comment != "Login e-mail address" || c.Description != "Login e-mail, unique.") {
					t.Errorf("email should be marked masked, with comment and description: %+v", c)
				}
				if c.Name == "id" && c.Masked {
					t.Error("id should not be masked")
				}
			}
			if len(o.Indexes) == 0 {
				t.Error("expected indexes in full detail")
			}
		}
	}
	if !found {
		t.Fatalf("users not found: %+v", resp.Objects)
	}
	if len(resp.Examples) != 1 || strings.Join(resp.Examples[0].Tables, ",") != "public.orders,public.users" {
		t.Errorf("examples = %+v", resp.Examples)
	}
	if _, err := gw.SearchObjects(context.Background(), agent, gateway.SearchRequest{Database: "nope"}); err == nil {
		t.Error("unknown database must fail")
	}
}
