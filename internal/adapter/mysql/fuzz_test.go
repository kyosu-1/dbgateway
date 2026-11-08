package mysql

import (
	"context"
	"testing"
)

// FuzzAnalyze checks that analysis never panics and that a statement it
// accepts as a read never writes. Run longer with:
//
//	go test -run '^$' -fuzz FuzzAnalyze -fuzztime 5m ./internal/adapter/mysql/
func FuzzAnalyze(f *testing.F) {
	for _, s := range []string{
		"SELECT id, email FROM users WHERE id = 1",
		"SELECT * FROM users u JOIN orders o ON o.user_id = u.id",
		"WITH x AS (DELETE FROM users RETURNING *) SELECT * FROM x",
		"UPDATE users SET plan = 'pro' WHERE id = 1",
		"SELECT 1; DROP TABLE users",
		"SELECT (SELECT max(id) FROM orders) AS m, count(*) FROM users GROUP BY plan",
		"/* comment */ select lower(email) from users where id in (1, 2) order by 1 limit 10",
	} {
		f.Add(s)
	}
	a := NewAnalyzer(NewFunctionAllowlist(nil))
	cat := testCatalog()
	f.Fuzz(func(t *testing.T, sql string) {
		qa, err := a.Analyze(context.Background(), sql, cat)
		if err != nil || qa == nil {
			return
		}
		if qa.Statement.IsWrite {
			return
		}
		for _, tbl := range qa.Statement.Tables {
			if tbl.Write {
				t.Fatalf("read statement writes %s: %q", tbl.FQN(), sql)
			}
		}
	})
}
