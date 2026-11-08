package mysql

import (
	"context"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kyosu-1/dbgateway/internal/analysis"
)

func testCatalog() *analysis.Catalog {
	cat := analysis.NewCatalog([]string{"app"}, nil)
	add := func(schema, name string, kind analysis.RelKind, def string, cols ...string) {
		rel := &analysis.Relation{Schema: schema, Name: name, Kind: kind, Definition: def}
		for _, c := range cols {
			rel.Columns = append(rel.Columns, analysis.Column{Name: c, Type: "varchar(255)"})
		}
		cat.Add(rel)
	}
	add("app", "users", analysis.RelTable, "", "id", "email", "name", "plan", "created_at")
	add("app", "orders", analysis.RelTable, "", "id", "user_id", "amount", "note")
	add("app", "support_tickets", analysis.RelTable, "", "id", "user_id", "body")
	add("other", "accounts", analysis.RelTable, "", "id", "secret")
	// Definitions as MySQL renders them in information_schema.VIEWS.
	add("app", "user_emails", analysis.RelView,
		"select `app`.`users`.`id` AS `id`,lower(`app`.`users`.`email`) AS `email` from `app`.`users` where (`app`.`users`.`plan` = 'pro')",
		"id", "email")
	add("app", "nested_view", analysis.RelView,
		"select `app`.`user_emails`.`id` AS `id`,`app`.`user_emails`.`email` AS `addr` from `app`.`user_emails`",
		"id", "addr")
	add("app", "escaped_view", analysis.RelView,
		"select 'it\\'s a \\\\ test' AS `s`,`u`.`email` AS `e` from `app`.`users` `u`",
		"s", "e")
	add("app", "hidden_view", analysis.RelView, "", "id", "email")
	add("information_schema", "TABLES", analysis.RelView, "", "TABLE_SCHEMA", "TABLE_NAME")
	return cat
}

func analyze(t *testing.T, sql string) (*analysis.QueryAnalysis, error) {
	t.Helper()
	a := NewAnalyzer(NewFunctionAllowlist(nil))
	return a.Analyze(context.Background(), sql, testCatalog())
}

// sources returns, per output column, the sorted source FQNs.
func sources(qa *analysis.QueryAnalysis) []string {
	var out []string
	for _, o := range qa.Output {
		var s []string
		for _, c := range o.Sources {
			s = append(s, c.FQN())
		}
		sort.Strings(s)
		out = append(out, strings.Join(s, ","))
	}
	return out
}

func usagesOf(qa *analysis.QueryAnalysis, fqn string) []analysis.Usage {
	for _, c := range qa.Statement.Columns {
		if c.FQN() == fqn {
			return c.Usages
		}
	}
	return nil
}

const allUsers = "app.users.created_at,app.users.email,app.users.id,app.users.name,app.users.plan"

func TestLineage(t *testing.T) {
	tests := []struct {
		sql  string
		want []string // per output column sources
	}{
		{"SELECT id, email FROM users WHERE id = 42", []string{"app.users.id", "app.users.email"}},
		{"SELECT * FROM users", []string{"app.users.id", "app.users.email", "app.users.name", "app.users.plan", "app.users.created_at"}},
		{"SELECT u.email AS e FROM users AS u", []string{"app.users.email"}},
		{"SELECT U.EMAIL FROM users u", []string{"app.users.email"}},
		{"SELECT `email`, \"id\" FROM `app`.`users`", []string{"app.users.email", "app.users.id"}},
		{"SELECT app.users.email FROM app.users", []string{"app.users.email"}},
		{"SELECT users.email FROM USERS", []string{"app.users.email"}},
		{"SELECT u.* FROM users u", []string{"app.users.id", "app.users.email", "app.users.name", "app.users.plan", "app.users.created_at"}},
		{"SELECT app.users.* FROM users", []string{"app.users.id", "app.users.email", "app.users.name", "app.users.plan", "app.users.created_at"}},
		{"SELECT lower(email) FROM users", []string{"app.users.email"}},
		{"SELECT x FROM (SELECT email AS x FROM users) s", []string{"app.users.email"}},
		{"WITH c AS (SELECT email FROM users) SELECT * FROM c", []string{"app.users.email"}},
		{"WITH c (addr) AS (SELECT email FROM users) SELECT addr FROM c", []string{"app.users.email"}},
		{"SELECT * FROM user_emails", []string{"app.users.id", "app.users.email"}},
		{"SELECT addr FROM nested_view", []string{"app.users.email"}},
		{"SELECT s, e FROM escaped_view", []string{"", "app.users.email"}},
		{"SELECT (SELECT email FROM users LIMIT 1)", []string{"app.users.email"}},
		{"SELECT id FROM users UNION SELECT user_id FROM orders", []string{"app.orders.user_id,app.users.id"}},
		{"(SELECT id FROM users) UNION ALL (SELECT user_id FROM orders) ORDER BY 1", []string{"app.orders.user_id,app.users.id"}},
		{"SELECT id FROM users EXCEPT SELECT user_id FROM orders", []string{"app.orders.user_id,app.users.id"}},
		{"SELECT u.id, o.amount FROM users u JOIN orders o ON o.user_id = u.id", []string{"app.users.id", "app.orders.amount"}},
		{"SELECT u.id, o.amount FROM users u, orders o WHERE o.user_id = u.id", []string{"app.users.id", "app.orders.amount"}},
		{"SELECT * FROM users JOIN orders USING (id)", []string{"app.orders.id,app.users.id", "app.users.email", "app.users.name", "app.users.plan", "app.users.created_at", "app.orders.user_id", "app.orders.amount", "app.orders.note"}},
		{"SELECT * FROM users NATURAL JOIN orders", []string{"app.orders.id,app.users.id", "app.users.email", "app.users.name", "app.users.plan", "app.users.created_at", "app.orders.user_id", "app.orders.amount", "app.orders.note"}},
		{"SELECT * FROM users RIGHT JOIN orders USING (id)", []string{"app.orders.id,app.users.id", "app.orders.user_id", "app.orders.amount", "app.orders.note", "app.users.email", "app.users.name", "app.users.plan", "app.users.created_at"}},
		{"SELECT * FROM users u LEFT JOIN orders o ON o.user_id = u.id", []string{"app.users.id", "app.users.email", "app.users.name", "app.users.plan", "app.users.created_at", "app.orders.id", "app.orders.user_id", "app.orders.amount", "app.orders.note"}},
		{"SELECT count(*) FROM users", []string{""}},
		{"SELECT CASE WHEN email LIKE '%@x' THEN 1 ELSE 0 END FROM users", []string{"app.users.email"}},
		{"SELECT x.e FROM users u, LATERAL (SELECT u.email AS e) x", []string{"app.users.email"}},
		{"WITH RECURSIVE t (n) AS (SELECT id FROM users UNION ALL SELECT n FROM t) SELECT n FROM t", []string{"app.users.id"}},
		{"WITH RECURSIVE t (a, b) AS (SELECT id, email FROM users UNION ALL SELECT b, a FROM t) SELECT a FROM t", []string{"app.users.email,app.users.id"}},
		{"VALUES ROW(1, 'a')", []string{"", ""}},
		{"TABLE users", []string{"app.users.id", "app.users.email", "app.users.name", "app.users.plan", "app.users.created_at"}},
		{"SELECT TABLE_NAME FROM information_schema.TABLES", []string{"information_schema.TABLES.TABLE_NAME"}},
		{"SELECT secret FROM other.accounts", []string{"other.accounts.secret"}},
		{"SELECT GROUP_CONCAT(email ORDER BY id SEPARATOR ',') FROM users", []string{"app.users.email"}},
		{"SELECT CONCAT_WS(',', name, email) FROM users", []string{"app.users.email,app.users.name"}},
		{"SELECT email->>'$.a' FROM users", []string{"app.users.email"}},
		{"SELECT CAST(id AS CHAR), CONVERT(email USING utf8mb4) FROM users", []string{"app.users.id", "app.users.email"}},
		{"SELECT IF(plan = 'pro', email, NULL) FROM users", []string{"app.users.email,app.users.plan"}},
		{"SELECT ROW_NUMBER() OVER (PARTITION BY plan ORDER BY id) FROM users", []string{""}},
		{"SELECT (email) FROM users", []string{"app.users.email"}},
		{"SELECT 1 FROM DUAL", []string{""}},
		{"SELECT DATE '2024-01-01', NOW() + INTERVAL 1 DAY", []string{"", ""}},
		{"SELECT id FROM users WHERE MATCH(name) AGAINST ('x')", []string{"app.users.id"}},
		{"SELECT u.email FROM users u WHERE u.id IN (SELECT user_id FROM orders WHERE amount > 1)", []string{"app.users.email"}},
		{"SELECT * FROM (SELECT * FROM users) AS s", []string{"app.users.id", "app.users.email", "app.users.name", "app.users.plan", "app.users.created_at"}},
		{"SELECT s.* FROM (SELECT id, email FROM users UNION SELECT id, note FROM orders) s", []string{"app.orders.id,app.users.id", "app.orders.note,app.users.email"}},
		{"SELECT EXTRACT(YEAR FROM created_at), TRIM(BOTH 'x' FROM email), POSITION('a' IN name) FROM users", []string{"app.users.created_at", "app.users.email", "app.users.name"}},
		{"SELECT CHAR(65 USING utf8mb4), GET_FORMAT(DATE, 'ISO'), SUBSTRING(email FROM 2 FOR 3) FROM users", []string{"", "", "app.users.email"}},
		{"SELECT DATE_ADD(created_at, INTERVAL 1 DAY), TIMESTAMPDIFF(DAY, created_at, NOW()) FROM users", []string{"app.users.created_at", "app.users.created_at"}},
		{"SELECT email COLLATE utf8mb4_bin, BINARY email, email IS NULL, email BETWEEN 'a' AND 'b' FROM users", []string{"app.users.email", "app.users.email", "app.users.email", "app.users.email"}},
		{"SELECT plan, COUNT(*), GROUPING(plan) FROM users GROUP BY plan WITH ROLLUP", []string{"app.users.plan", "", "app.users.plan"}},
		{"SELECT JSON_ARRAYAGG(email), JSON_OBJECTAGG(id, email) FROM users", []string{"app.users.email", "app.users.email,app.users.id"}},
		{"SELECT email MEMBER OF ('[]'), email REGEXP 'a', NOT (id > 1), -id FROM users", []string{"app.users.email", "app.users.email", "app.users.id", "app.users.id"}},
		{"SELECT LAG(email, 1) OVER w, FIRST_VALUE(id) OVER (PARTITION BY plan ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM users WINDOW w AS (ORDER BY id)", []string{"app.users.email", "app.users.id"}},
		{"SELECT (id, plan) IN ((1, 'a')), id = ALL (SELECT user_id FROM orders) FROM users", []string{"app.users.id,app.users.plan", "app.orders.user_id,app.users.id"}},
		{"SELECT EXISTS (SELECT 1 FROM orders WHERE orders.user_id = users.id) FROM users", []string{""}},
		{"SELECT DISTINCT plan FROM users ORDER BY plan DESC LIMIT 10 OFFSET 5", []string{"app.users.plan"}},
	}
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			qa, err := analyze(t, tt.sql)
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if qa.Statement.Unknown {
				t.Fatalf("unexpected unknown: %v", qa.Statement.UnknownReasons)
			}
			if got := sources(qa); !slices.Equal(got, tt.want) {
				t.Errorf("sources\n got %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestDirect(t *testing.T) {
	qa, err := analyze(t, "SELECT email, lower(email), CAST(email AS CHAR), (email), u.email FROM users u")
	if err != nil {
		t.Fatal(err)
	}
	var got []bool
	for _, o := range qa.Output {
		got = append(got, o.Direct)
	}
	if !slices.Equal(got, []bool{true, false, false, true, true}) {
		t.Errorf("direct = %v", got)
	}
}

func TestOutputNames(t *testing.T) {
	qa, err := analyze(t, "SELECT id, email AS e, lower(name) FROM users")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, o := range qa.Output {
		names = append(names, o.Name)
	}
	if !slices.Equal(names, []string{"id", "e", "lower(name)"}) {
		t.Errorf("names = %q", names)
	}
}

func TestUsages(t *testing.T) {
	tests := []struct {
		sql  string
		col  string
		want analysis.Usage
	}{
		{"SELECT id FROM users WHERE email LIKE 'a%'", "app.users.email", analysis.UsageFilter},
		{"SELECT count(*) FROM users GROUP BY email", "app.users.email", analysis.UsageGroup},
		{"SELECT email AS e, count(*) FROM users GROUP BY e", "app.users.email", analysis.UsageGroup},
		{"SELECT email, count(*) FROM users GROUP BY 1", "app.users.email", analysis.UsageGroup},
		{"SELECT id FROM users ORDER BY email", "app.users.email", analysis.UsageOrder},
		{"SELECT email AS e FROM users ORDER BY e", "app.users.email", analysis.UsageOrder},
		{"SELECT email AS e FROM users ORDER BY lower(e)", "app.users.email", analysis.UsageOrder},
		{"SELECT id, email FROM users ORDER BY 2", "app.users.email", analysis.UsageOrder},
		{"SELECT u.id FROM users u JOIN orders o ON o.note = u.email", "app.users.email", analysis.UsageFilter},
		{"SELECT * FROM users JOIN orders USING (id)", "app.orders.id", analysis.UsageFilter},
		{"SELECT x FROM (SELECT email AS x FROM users) s WHERE x = 'a'", "app.users.email", analysis.UsageFilter},
		{"SELECT id FROM users WHERE EXISTS (SELECT 1 FROM orders o WHERE o.note = users.email)", "app.users.email", analysis.UsageFilter},
		{"SELECT id FROM users WHERE id IN (SELECT user_id FROM orders)", "app.orders.user_id", analysis.UsageFilter},
		{"SELECT id FROM users WHERE id = ANY (SELECT user_id FROM orders)", "app.orders.user_id", analysis.UsageFilter},
		{"SELECT id FROM users WHERE id = (SELECT max(user_id) FROM orders)", "app.orders.user_id", analysis.UsageFilter},
		{"SELECT row_number() OVER (ORDER BY email) FROM users", "app.users.email", analysis.UsageOrder},
		{"SELECT row_number() OVER (PARTITION BY email) FROM users", "app.users.email", analysis.UsageGroup},
		{"SELECT row_number() OVER w FROM users WINDOW w AS (ORDER BY email)", "app.users.email", analysis.UsageOrder},
		{"SELECT id FROM user_emails WHERE email = 'x'", "app.users.email", analysis.UsageFilter},
		{"SELECT id FROM users HAVING max(email) > 'a'", "app.users.email", analysis.UsageFilter},
		{"SELECT email AS e FROM users HAVING e > 'a'", "app.users.email", analysis.UsageFilter},
		{"SELECT GROUP_CONCAT(id ORDER BY email) FROM users", "app.users.email", analysis.UsageOrder},
		{"SELECT id FROM users LIMIT 1", "app.users.id", analysis.UsageOutput},
		{"SELECT id FROM users WHERE MATCH(email) AGAINST ('x')", "app.users.email", analysis.UsageFilter},
	}
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			qa, err := analyze(t, tt.sql)
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if u := usagesOf(qa, tt.col); !slices.Contains(u, tt.want) {
				t.Errorf("usages of %s = %v, want %s", tt.col, u, tt.want)
			}
		})
	}
}

func TestViewInternalsNotRecorded(t *testing.T) {
	// user_emails filters on users.plan internally; the caller did not
	// choose that predicate, so it must not count as a filter usage.
	qa, err := analyze(t, "SELECT id FROM user_emails")
	if err != nil {
		t.Fatal(err)
	}
	if u := usagesOf(qa, "app.users.plan"); len(u) != 0 {
		t.Errorf("plan usages = %v, want none", u)
	}
	var tables []string
	for _, tr := range qa.Statement.Tables {
		tables = append(tables, tr.FQN())
	}
	sort.Strings(tables)
	if !slices.Equal(tables, []string{"app.user_emails", "app.users"}) {
		t.Errorf("tables = %v", tables)
	}
}

func TestStatementKinds(t *testing.T) {
	tests := []struct {
		sql      string
		kind     analysis.StmtKind
		write    bool
		hasWhere bool
		tables   string // sorted "fqn:rw" list
	}{
		{"SELECT 1", analysis.KindSelect, false, false, ""},
		{"UPDATE users SET plan = 'pro' WHERE id = 1", analysis.KindUpdate, true, true, "app.users:w"},
		{"UPDATE users SET plan = 'pro'", analysis.KindUpdate, true, false, "app.users:w"},
		{"UPDATE users u JOIN orders o ON o.user_id = u.id SET u.plan = 'pro' WHERE o.amount > 10", analysis.KindUpdate, true, true, "app.orders:r,app.users:rw"},
		{"DELETE FROM users WHERE id = 1", analysis.KindDelete, true, true, "app.users:w"},
		{"DELETE FROM users", analysis.KindDelete, true, false, "app.users:w"},
		{"DELETE u FROM users u JOIN orders o ON o.user_id = u.id WHERE o.amount = 0", analysis.KindDelete, true, true, "app.orders:r,app.users:rw"},
		{"DELETE FROM u USING users u JOIN orders o ON o.user_id = u.id", analysis.KindDelete, true, false, "app.orders:r,app.users:rw"},
		{"INSERT INTO orders (user_id, amount) VALUES (1, 2)", analysis.KindInsert, true, false, "app.orders:w"},
		{"INSERT INTO orders SET user_id = 1, amount = 2", analysis.KindInsert, true, false, "app.orders:w"},
		{"INSERT INTO orders (id, user_id) SELECT id, id FROM users", analysis.KindInsert, true, false, "app.orders:w,app.users:r"},
		{"INSERT INTO orders (id, amount) VALUES (1, 2) ON DUPLICATE KEY UPDATE amount = VALUES(amount)", analysis.KindInsert, true, false, "app.orders:w"},
		{"REPLACE INTO orders (id, amount) VALUES (1, 2)", analysis.KindInsert, true, false, "app.orders:w"},
		{"TRUNCATE users", analysis.KindTruncate, true, false, "app.users:w"},
		{"TRUNCATE TABLE app.users", analysis.KindTruncate, true, false, "app.users:w"},
		{"CREATE TABLE x (id int)", analysis.KindDDL, false, false, ""},
		{"CREATE TEMPORARY TABLE x (id int)", analysis.KindDDL, false, false, ""},
		{"DROP TABLE users", analysis.KindDDL, false, false, ""},
		{"ALTER TABLE users ADD COLUMN x int", analysis.KindDDL, false, false, ""},
		{"RENAME TABLE users TO u2", analysis.KindDDL, false, false, ""},
		{"CREATE VIEW v AS SELECT 1", analysis.KindDDL, false, false, ""},
		{"GRANT SELECT ON app.* TO bob", analysis.KindDDL, false, false, ""},
		{"REVOKE SELECT ON app.* FROM bob", analysis.KindDDL, false, false, ""},
		{"CREATE USER bob IDENTIFIED BY 'x'", analysis.KindDDL, false, false, ""},
		{"ANALYZE TABLE users", analysis.KindDDL, false, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			qa, err := analyze(t, tt.sql)
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			st := qa.Statement
			if st.Kind != tt.kind || st.IsWrite != tt.write || st.HasWhere != tt.hasWhere {
				t.Errorf("got kind=%s write=%v where=%v", st.Kind, st.IsWrite, st.HasWhere)
			}
			var tables []string
			for _, tr := range st.Tables {
				rw := ""
				if tr.Read {
					rw += "r"
				}
				if tr.Write {
					rw += "w"
				}
				tables = append(tables, tr.FQN()+":"+rw)
			}
			sort.Strings(tables)
			if got := strings.Join(tables, ","); got != tt.tables {
				t.Errorf("tables = %s, want %s", got, tt.tables)
			}
			if tt.kind != analysis.KindDDL && st.Unknown {
				t.Errorf("unexpected unknown: %v", st.UnknownReasons)
			}
		})
	}
}

func TestWriteUsages(t *testing.T) {
	qa, err := analyze(t, "UPDATE users SET email = lower(name) WHERE plan = 'x'")
	if err != nil {
		t.Fatal(err)
	}
	if u := usagesOf(qa, "app.users.email"); !slices.Contains(u, analysis.UsageWrite) {
		t.Errorf("email usages = %v", u)
	}
	if u := usagesOf(qa, "app.users.plan"); !slices.Contains(u, analysis.UsageFilter) {
		t.Errorf("plan usages = %v", u)
	}
	if u := usagesOf(qa, "app.users.name"); !slices.Contains(u, analysis.UsageOther) {
		t.Errorf("name usages = %v", u)
	}
}

func TestUnknown(t *testing.T) {
	for _, sql := range []string{
		"SELECT * FROM missing_table",
		"SELECT nope FROM users",
		"SELECT x.id FROM users",
		"SELECT * FROM hidden_view",
		"SELECT * FROM users JOIN missing_table USING (id)",
		"SELECT * FROM users NATURAL JOIN missing_table",
		"SELECT A.id FROM users a, orders a",
		"SELECT id FROM users ORDER BY 5",
	} {
		t.Run(sql, func(t *testing.T) {
			qa, err := analyze(t, sql)
			if err != nil {
				return // rejected outright is also fine
			}
			if !qa.Statement.Unknown {
				t.Errorf("expected Unknown")
			}
		})
	}
}

func TestUnknownOutputs(t *testing.T) {
	qa, err := analyze(t, "SELECT * FROM missing_table")
	if err != nil {
		t.Fatal(err)
	}
	if len(qa.Output) == 0 || !slices.ContainsFunc(qa.Output, func(o analysis.OutputColumn) bool { return o.Unknown }) {
		t.Errorf("expected an unknown output column: %+v", qa.Output)
	}
}

func TestFunctions(t *testing.T) {
	qa, err := analyze(t, "SELECT lower(email), count(*), row_number() OVER () FROM users")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"lower", "count", "row_number"} {
		if !slices.Contains(qa.Statement.Functions, f) {
			t.Errorf("functions = %v, missing %s", qa.Statement.Functions, f)
		}
	}
	a := NewAnalyzer(NewFunctionAllowlist([]string{"SLEEP", "app.my_func"}))
	for _, sql := range []string{"SELECT sleep(1)", "SELECT app.my_func(1)", "SELECT APP.MY_FUNC(1)"} {
		if _, err := a.Analyze(context.Background(), sql, testCatalog()); err != nil {
			t.Errorf("%s: %v", sql, err)
		}
	}
	if _, err := a.Analyze(context.Background(), "SELECT my_func(1)", testCatalog()); err == nil {
		t.Error("unqualified my_func must not match app.my_func")
	}
}

func TestNormalized(t *testing.T) {
	tests := []struct{ sql, want string }{
		{"SELECT id FROM users WHERE email = 'taro@example.com' AND id = 42", "SELECT id FROM users WHERE email = ? AND id = ?"},
		{"SELECT \"email\", `id` FROM users WHERE x = -1.5e3 /* secret */ AND y = x'0A'", "SELECT \"email\", `id` FROM users WHERE x = -?  AND y = ?"},
		{"SELECT a/*c*/FROM t", "SELECT a FROM t"},
		{"SELECT 'it''s', 'a\\' , N'x', _utf8mb4'y', 0x1F, 0b101, .5 FROM t1", "SELECT ?, ? , ?, ?, ?, ?, ? FROM t1"},
		{"SELECT 1abc FROM t -- tail", "SELECT 1abc FROM t"},
	}
	a := NewAnalyzer(NewFunctionAllowlist(nil))
	for _, tt := range tests {
		if got := normalizeText(tt.sql); got != tt.want {
			t.Errorf("normalize(%q)\n got %q\nwant %q", tt.sql, got, tt.want)
		}
	}
	qa, err := analyze(t, "SELECT id FROM users WHERE email = 'taro@example.com' AND id = 42")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(qa.Normalized, "taro") || strings.Contains(qa.Normalized, "42") {
		t.Errorf("literals not removed: %s", qa.Normalized)
	}
	if got := a.Normalize("SELEC garbage 'secret'"); got != "" {
		t.Errorf("unparseable SQL normalized to %q", got)
	}
	if got := a.Normalize("SELECT /*!99999 'secret' */ 1"); got != "" {
		t.Errorf("executable comment normalized to %q", got)
	}
}

// TestNoBackslashEscapes checks that the parser lexes strings the way the
// session does (NO_BACKSLASH_ESCAPES): a backslash does not escape the
// closing quote, so this is one complete statement with two literals.
func TestNoBackslashEscapes(t *testing.T) {
	qa, err := analyze(t, `SELECT 'a\', email FROM users`)
	if err != nil {
		t.Fatal(err)
	}
	if got := sources(qa); !slices.Equal(got, []string{"", "app.users.email"}) {
		t.Errorf("sources = %q", got)
	}
	// With backslash escapes this would hide "; DELETE ..." inside a string.
	if _, err := analyze(t, `SELECT 'a\'; DELETE FROM users; -- '`); err == nil {
		t.Error("expected rejection")
	}
}

// TestAnsiQuotes checks that double quotes are identifiers.
func TestAnsiQuotes(t *testing.T) {
	qa, err := analyze(t, `SELECT "email" FROM "users"`)
	if err != nil {
		t.Fatal(err)
	}
	if got := sources(qa); !slices.Equal(got, []string{"app.users.email"}) {
		t.Errorf("sources = %q", got)
	}
}

func TestCaseCollision(t *testing.T) {
	cat := testCatalog()
	addRelations(cat, []*analysis.Relation{
		cat.Lookup("app", "users"),
		{Schema: "app", Name: "Users", Kind: analysis.RelTable, Columns: []analysis.Column{{Name: "secret"}}},
	})
	a := NewAnalyzer(NewFunctionAllowlist(nil))
	for _, sql := range []string{"SELECT * FROM users", "SELECT * FROM Users"} {
		qa, err := a.Analyze(context.Background(), sql, cat)
		if err != nil {
			t.Fatal(err)
		}
		if !qa.Statement.Unknown {
			t.Errorf("%s: expected Unknown for case-colliding table names", sql)
		}
	}
}

// TestRejectionCodes checks that statements are rejected for the intended
// reason, not incidentally.
func TestRejectionCodes(t *testing.T) {
	tests := []struct{ sql, code string }{
		{"SELECT 1; SELECT 2", "multiple_statements"},
		{"   ", "empty"},
		{"SELECT '\xff'", "invalid_text"},
		{"SELECT 1\x00", "invalid_text"},
		{"SELECT /*!99999 email AS id, */ id FROM users", "executable_comment"},
		{"SELECT /*!50000 email, */ id FROM users", "executable_comment"},
		{"SELECT 1 /*T![clustered_index] , 2 */", "executable_comment"},
		{"SELECT /*+ MAX_EXECUTION_TIME(1) */ 1", "optimizer_hint"},
		{"BEGIN", "transaction_control"},
		{"START TRANSACTION", "transaction_control"},
		{"COMMIT", "transaction_control"},
		{"ROLLBACK", "transaction_control"},
		{"SAVEPOINT a", "transaction_control"},
		{"SET @x = 1", "set"},
		{"SET ROLE ALL", "set"},
		{"SET PASSWORD = 'x'", "set"},
		{"SET SESSION sql_mode = ''", "set"},
		{"SET TRANSACTION READ WRITE", "set"},
		{"SELECT @x", "user_variable"},
		{"SELECT @x := email FROM users", "user_variable"},
		{"SELECT @@version", "system_variable"},
		{"SELECT LOAD_FILE('/etc/passwd')", "function_not_allowed"},
		{"SELECT SLEEP(1)", "function_not_allowed"},
		{"SELECT BENCHMARK(1, 1)", "function_not_allowed"},
		{"SELECT GET_LOCK('a', 1)", "function_not_allowed"},
		{"SELECT app.evil()", "function_not_allowed"},
		{"SELECT ROW_NUMBER() OVER (ORDER BY SLEEP(1)) FROM users", "function_not_allowed"},
		{"SELECT ROW_NUMBER() OVER w FROM users WINDOW w AS (PARTITION BY SLEEP(1))", "function_not_allowed"},
		{"SELECT plan FROM users GROUP BY plan HAVING SLEEP(1) = 0", "function_not_allowed"},
		{"SELECT 1 FROM users u JOIN orders o ON SLEEP(1) = 0", "function_not_allowed"},
		{"SELECT 1 UNION SELECT SLEEP(1)", "function_not_allowed"},
		{"SELECT GROUP_CONCAT(email ORDER BY SLEEP(1)) FROM users", "function_not_allowed"},
		{"UPDATE users SET plan = SLEEP(1)", "function_not_allowed"},
		{"DELETE FROM users WHERE SLEEP(1) = 0", "function_not_allowed"},
		{"INSERT INTO orders (id) VALUES (LOAD_FILE('/etc/passwd'))", "function_not_allowed"},
		{"INSERT INTO orders (id) VALUES (1) ON DUPLICATE KEY UPDATE amount = SLEEP(1)", "function_not_allowed"},
		{"INSERT INTO orders (id) SELECT SLEEP(1)", "function_not_allowed"},
		{"UPDATE users SET plan = @x", "user_variable"},
		{"UPDATE users SET plan = 'x' WHERE id = 1 FOR UPDATE", "parse_error"},
		{"SELECT * FROM users FOR UPDATE", "locking_clause"},
		{"SELECT * FROM users FOR SHARE", "locking_clause"},
		{"SELECT * FROM users LOCK IN SHARE MODE", "locking_clause"},
		{"SELECT * FROM users INTO OUTFILE '/tmp/x'", "select_into"},
		{"SELECT email FROM users INTO DUMPFILE '/tmp/x'", "parse_error"}, // not supported by the parser
		{"SELECT SQL_CALC_FOUND_ROWS * FROM users", "calc_found_rows"},
		{"SELECT * FROM users WHERE id = ?", "parameters"},
		{"SHOW TABLES", "show"},
		{"EXPLAIN ANALYZE SELECT 1", "explain_analyze"},
		{"EXPLAIN SELECT 1", "explain"},
		{"DESCRIBE users", "explain"},
		{"LOAD DATA INFILE '/x' INTO TABLE users", "load_data"},
		{"CALL p()", "call"},
		{"DO 1", "do"},
		{"LOCK TABLES users READ", "lock"},
		{"UNLOCK TABLES", "lock"},
		{"PREPARE s FROM 'SELECT 1'", "prepare"},
		{"EXECUTE s", "prepare"},
		{"DEALLOCATE PREPARE s", "prepare"},
		{"USE app", "use"},
		{"KILL 1", "kill"},
		{"FLUSH PRIVILEGES", "utility"},
		{"XA START 'x'", "parse_error"},
		{"HANDLER users OPEN", "parse_error"},
	}
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			_, err := analyze(t, tt.sql)
			r, ok := analysis.AsRejection(err)
			if !ok {
				t.Fatalf("expected rejection %s, got %v", tt.code, err)
			}
			if r.Code != tt.code {
				t.Errorf("code = %s (%s), want %s", r.Code, r.Reason, tt.code)
			}
			if r.Reason == "" || r.Hint == "" {
				t.Errorf("missing reason or hint: %+v", r)
			}
		})
	}
}

// TestParseErrorDoesNotEchoSQL checks that parse errors do not repeat the
// statement text (which may contain literal values).
func TestParseErrorDoesNotEchoSQL(t *testing.T) {
	_, err := analyze(t, "SELEC 'taro@example.com'")
	r, ok := analysis.AsRejection(err)
	if !ok || strings.Contains(r.Reason, "taro") {
		t.Fatalf("rejection = %+v", r)
	}
}

func loadCorpus(t *testing.T) []struct {
	Name string `yaml:"name"`
	SQL  string `yaml:"sql"`
} {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/bypass/mysql.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name string `yaml:"name"`
			SQL  string `yaml:"sql"`
		} `yaml:"cases"`
	}
	if err := yaml.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	return corpus.Cases
}

// TestBypassCorpus checks that every statement in testdata/bypass/mysql.yaml
// is rejected at parse time (or, for writes and DDL, classified so that the
// policy can never auto-allow them).
func TestBypassCorpus(t *testing.T) {
	cases := loadCorpus(t)
	if len(cases) < 80 {
		t.Fatalf("corpus too small: %d", len(cases))
	}
	names := map[string]bool{}
	for _, c := range cases {
		if names[c.Name] {
			t.Errorf("duplicate case name %s", c.Name)
		}
		names[c.Name] = true
		t.Run(c.Name, func(t *testing.T) {
			qa, err := analyze(t, c.SQL)
			if err != nil {
				if _, ok := analysis.AsRejection(err); !ok {
					t.Fatalf("non-rejection error: %v", err)
				}
				return
			}
			st := qa.Statement
			if st.Kind == analysis.KindSelect && !st.IsWrite && !st.Unknown {
				t.Errorf("not rejected: classified as a plain read (%s)", c.SQL)
			}
		})
	}
}
