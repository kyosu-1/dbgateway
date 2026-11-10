package postgres

import (
	"errors"
	"slices"
	"testing"

	pg "github.com/pganalyze/pg_query_go/v6"

	"github.com/kyosu-1/dbgateway/internal/analysis"
)

func TestPlanBackup(t *testing.T) {
	a := NewAnalyzer(NewFunctionAllowlist(nil))
	for _, tt := range []struct {
		sql    string
		kind   analysis.StmtKind
		target string
		sel    string
		set    []string
	}{
		{"UPDATE users SET plan = 'pro', name = 'x' WHERE id = 1", analysis.KindUpdate, "public.users",
			"SELECT users.*, users.tableoid AS _dbgw_tableoid, users.ctid AS _dbgw_ctid FROM users WHERE id = 1", []string{"plan", "name"}},
		{"update public.users u set plan = 'free' where u.created_at < now() - interval '1 year' returning u.id", analysis.KindUpdate, "public.users",
			"SELECT u.*, u.tableoid AS _dbgw_tableoid, u.ctid AS _dbgw_ctid FROM public.users u WHERE u.created_at < (now() - '1 year'::interval)", []string{"plan"}},
		{"DELETE FROM ONLY orders WHERE user_id IN (SELECT id FROM users WHERE plan = 'x')", analysis.KindDelete, "public.orders",
			"SELECT orders.*, orders.tableoid AS _dbgw_tableoid, orders.ctid AS _dbgw_ctid FROM ONLY orders WHERE user_id IN (SELECT id FROM users WHERE plan = 'x')", nil},
		{"DELETE FROM orders", analysis.KindDelete, "public.orders", "SELECT orders.*, orders.tableoid AS _dbgw_tableoid, orders.ctid AS _dbgw_ctid FROM orders", nil},
	} {
		p, err := a.PlanBackup(tt.sql, testCatalog())
		if err != nil {
			t.Errorf("%s: %v", tt.sql, err)
			continue
		}
		if p.Kind != tt.kind || p.Target.FQN() != tt.target || p.Select != tt.sel || !slices.Equal(p.SetColumns, tt.set) {
			t.Errorf("%s:\n got  %s %s %q %v\n want %s %s %q %v", tt.sql, p.Kind, p.Target.FQN(), p.Select, p.SetColumns,
				tt.kind, tt.target, tt.sel, tt.set)
		}
		// The backup query must parse as a single SELECT.
		if tree, err := pg.Parse(p.Select); err != nil || len(tree.Stmts) != 1 || tree.Stmts[0].Stmt.GetSelectStmt() == nil {
			t.Errorf("%s: backup query %q: %v", tt.sql, p.Select, err)
		}
	}
	for _, sql := range []string{
		"UPDATE users SET plan = 'x' FROM orders WHERE orders.user_id = users.id",
		"DELETE FROM users USING orders WHERE orders.user_id = users.id",
		"WITH x AS (SELECT 1) UPDATE users SET plan = 'x' WHERE id IN (SELECT * FROM x)",
		"UPDATE user_emails SET email = 'x' WHERE id = 1",
		"UPDATE missing SET a = 1 WHERE b = 2",
		"INSERT INTO users (id) VALUES (1)",
		"MERGE INTO users u USING orders o ON u.id = o.user_id WHEN MATCHED THEN DELETE",
		"SELECT 1",
		"UPDATE users SET plan = 'x' WHERE id = (SELECT id FROM users ORDER BY random() LIMIT 1)",
		"DELETE FROM orders WHERE note = gen_random_uuid()::text",
		"DELETE FROM orders WHERE created_at < clock_timestamp()",
	} {
		if _, err := a.PlanBackup(sql, testCatalog()); !errors.Is(err, analysis.ErrBackupUnsupported) {
			t.Errorf("%s: err = %v, want unsupported", sql, err)
		}
	}
}
