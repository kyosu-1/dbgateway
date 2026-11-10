package postgres

import (
	"errors"
	"slices"
	"testing"

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
			"SELECT users.* FROM users WHERE id = 1", []string{"plan", "name"}},
		{"update public.users u set plan = 'free' where u.created_at < now() - interval '1 year' returning u.id", analysis.KindUpdate, "public.users",
			"SELECT u.* FROM public.users u WHERE u.created_at < (now() - '1 year'::interval)", []string{"plan"}},
		{"DELETE FROM ONLY orders WHERE user_id IN (SELECT id FROM users WHERE plan = 'x')", analysis.KindDelete, "public.orders",
			"SELECT orders.* FROM ONLY orders WHERE user_id IN (SELECT id FROM users WHERE plan = 'x')", nil},
		{"DELETE FROM orders", analysis.KindDelete, "public.orders", "SELECT orders.* FROM orders", nil},
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
		// The backup query must itself be a plain, fully analyzable read.
		qa, err := a.Analyze(t.Context(), p.Select, testCatalog())
		if err != nil || qa.Statement.Kind != analysis.KindSelect || qa.Statement.IsWrite || qa.Statement.Unknown {
			t.Errorf("%s: backup query %q does not analyze as a plain SELECT: %v", tt.sql, p.Select, err)
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
	} {
		if _, err := a.PlanBackup(sql, testCatalog()); !errors.Is(err, errBackupUnsupported) {
			t.Errorf("%s: err = %v, want unsupported", sql, err)
		}
	}
}
