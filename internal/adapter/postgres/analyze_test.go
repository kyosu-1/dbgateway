package postgres

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
	cat := analysis.NewCatalog([]string{"public"}, []string{"pg_catalog"})
	add := func(schema, name string, kind analysis.RelKind, def string, cols ...string) {
		rel := &analysis.Relation{Schema: schema, Name: name, Kind: kind, Definition: def}
		for _, c := range cols {
			rel.Columns = append(rel.Columns, analysis.Column{Name: c, Type: "text"})
		}
		cat.Add(rel)
	}
	add("public", "users", analysis.RelTable, "", "id", "email", "name", "plan", "created_at")
	add("public", "orders", analysis.RelTable, "", "id", "user_id", "amount", "note")
	add("public", "support_tickets", analysis.RelTable, "", "id", "user_id", "body")
	add("public", "user_emails", analysis.RelView, "SELECT u.id, lower(u.email) AS email FROM users u WHERE u.plan = 'pro'", "id", "email")
	add("public", "nested_view", analysis.RelView, "SELECT id, email AS addr FROM user_emails", "id", "addr")
	add("pg_catalog", "pg_tables", analysis.RelView, "", "schemaname", "tablename")
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

func TestLineage(t *testing.T) {
	tests := []struct {
		sql  string
		want []string // per output column sources
	}{
		{"SELECT id, email FROM users WHERE id = 42", []string{"public.users.id", "public.users.email"}},
		{"SELECT * FROM users", []string{"public.users.id", "public.users.email", "public.users.name", "public.users.plan", "public.users.created_at"}},
		{"SELECT u.email AS e FROM users AS u", []string{"public.users.email"}},
		{"SELECT lower(email) FROM users", []string{"public.users.email"}},
		{"SELECT x FROM (SELECT email AS x FROM users) s", []string{"public.users.email"}},
		{"WITH c AS (SELECT email FROM users) SELECT * FROM c", []string{"public.users.email"}},
		{"WITH c(addr) AS (SELECT email FROM users) SELECT addr FROM c", []string{"public.users.email"}},
		{"SELECT * FROM user_emails", []string{"public.users.id", "public.users.email"}},
		{"SELECT addr FROM nested_view", []string{"public.users.email"}},
		{"SELECT (SELECT email FROM users LIMIT 1)", []string{"public.users.email"}},
		{"SELECT u FROM users u", []string{"public.users.created_at,public.users.email,public.users.id,public.users.name,public.users.plan"}},
		{"SELECT row_to_json(u) FROM users u", []string{"public.users.created_at,public.users.email,public.users.id,public.users.name,public.users.plan"}},
		{"SELECT id FROM users UNION SELECT user_id FROM orders", []string{"public.orders.user_id,public.users.id"}},
		{"SELECT u.id, o.amount FROM users u JOIN orders o ON o.user_id = u.id", []string{"public.users.id", "public.orders.amount"}},
		{"SELECT * FROM users JOIN orders USING (id)", []string{"public.orders.id,public.users.id", "public.users.email", "public.users.name", "public.users.plan", "public.users.created_at", "public.orders.user_id", "public.orders.amount", "public.orders.note"}},
		{"SELECT count(*) FROM users", []string{""}},
		{"SELECT CASE WHEN email LIKE '%@x' THEN 1 ELSE 0 END FROM users", []string{"public.users.email"}},
		{"SELECT g FROM generate_series(1, 3) g", []string{""}},
		{"SELECT e FROM users, unnest(ARRAY[email]) AS e", []string{"public.users.email"}},
		{"SELECT key, value FROM users, jsonb_each(to_jsonb(users)) ", []string{"public.users.created_at,public.users.email,public.users.id,public.users.name,public.users.plan", "public.users.created_at,public.users.email,public.users.id,public.users.name,public.users.plan"}},
		{"SELECT x.e FROM users u, LATERAL (SELECT u.email AS e) x", []string{"public.users.email"}},
		{"WITH RECURSIVE t(n) AS (SELECT id FROM users UNION ALL SELECT n FROM t) SELECT n FROM t", []string{"public.users.id"}},
		{"VALUES (1, 'a')", []string{"", ""}},
		{"SELECT tablename FROM pg_tables", []string{"pg_catalog.pg_tables.tablename"}},
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
	qa, err := analyze(t, "SELECT email, lower(email), email::text FROM users")
	if err != nil {
		t.Fatal(err)
	}
	got := []bool{qa.Output[0].Direct, qa.Output[1].Direct, qa.Output[2].Direct}
	if !slices.Equal(got, []bool{true, false, false}) {
		t.Errorf("direct = %v", got)
	}
}

func TestUsages(t *testing.T) {
	tests := []struct {
		sql  string
		col  string
		want analysis.Usage
	}{
		{"SELECT id FROM users WHERE email LIKE 'a%'", "public.users.email", analysis.UsageFilter},
		{"SELECT count(*) FROM users GROUP BY email", "public.users.email", analysis.UsageGroup},
		{"SELECT id FROM users ORDER BY email", "public.users.email", analysis.UsageOrder},
		{"SELECT email AS e FROM users ORDER BY e", "public.users.email", analysis.UsageOrder},
		{"SELECT id, email FROM users ORDER BY 2", "public.users.email", analysis.UsageOrder},
		{"SELECT u.id FROM users u JOIN orders o ON o.note = u.email", "public.users.email", analysis.UsageFilter},
		{"SELECT x FROM (SELECT email AS x FROM users) s WHERE x = 'a'", "public.users.email", analysis.UsageFilter},
		{"SELECT id FROM users WHERE EXISTS (SELECT 1 FROM orders o WHERE o.note = users.email)", "public.users.email", analysis.UsageFilter},
		{"SELECT id FROM users WHERE id IN (SELECT user_id FROM orders)", "public.orders.user_id", analysis.UsageFilter},
		{"SELECT count(*) FILTER (WHERE email LIKE 'a%') FROM users", "public.users.email", analysis.UsageFilter},
		{"SELECT row_number() OVER (ORDER BY email) FROM users", "public.users.email", analysis.UsageOrder},
		{"SELECT DISTINCT ON (email) id FROM users", "public.users.email", analysis.UsageGroup},
		{"SELECT id FROM user_emails WHERE email = 'x'", "public.users.email", analysis.UsageFilter},
		{"SELECT id FROM users HAVING max(email) > 'a'", "public.users.email", analysis.UsageFilter},
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
	if u := usagesOf(qa, "public.users.plan"); len(u) != 0 {
		t.Errorf("plan usages = %v, want none", u)
	}
	var tables []string
	for _, tr := range qa.Statement.Tables {
		tables = append(tables, tr.FQN())
	}
	sort.Strings(tables)
	if !slices.Equal(tables, []string{"public.user_emails", "public.users"}) {
		t.Errorf("tables = %v", tables)
	}
}

func TestStatementKinds(t *testing.T) {
	tests := []struct {
		sql      string
		kind     analysis.StmtKind
		write    bool
		hasWhere bool
	}{
		{"SELECT 1", analysis.KindSelect, false, false},
		{"UPDATE users SET plan = 'pro' WHERE id = 1", analysis.KindUpdate, true, true},
		{"UPDATE users SET plan = 'pro'", analysis.KindUpdate, true, false},
		{"DELETE FROM users WHERE id = 1", analysis.KindDelete, true, true},
		{"INSERT INTO orders (user_id, amount) VALUES (1, 2)", analysis.KindInsert, true, false},
		{"TRUNCATE users", analysis.KindTruncate, true, false},
		{"MERGE INTO users u USING orders o ON u.id = o.user_id WHEN MATCHED THEN UPDATE SET plan = 'x'", analysis.KindMerge, true, true},
		{"WITH d AS (DELETE FROM users WHERE id = 1 RETURNING id) SELECT * FROM d", analysis.KindSelect, true, false},
		{"CREATE TABLE x (id int)", analysis.KindDDL, false, false},
		{"DROP TABLE users", analysis.KindDDL, false, false},
		{"GRANT SELECT ON users TO bob", analysis.KindDDL, false, false},
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
		})
	}
}

func TestUnknown(t *testing.T) {
	for _, sql := range []string{
		"SELECT * FROM missing_table",
		"SELECT nope FROM users",
		"SELECT * FROM XMLTABLE('/r' PASSING '<r/>' COLUMNS a int)",
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

func TestNormalized(t *testing.T) {
	qa, err := analyze(t, "SELECT id FROM users WHERE email = 'taro@example.com' AND id = 42")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(qa.Normalized, "taro") || strings.Contains(qa.Normalized, "42") {
		t.Errorf("literals not removed: %s", qa.Normalized)
	}
}

// TestBypassCorpus checks that every statement in testdata/bypass is
// rejected at parse time (or, for writes and DDL, classified so that the
// policy can never auto-allow them).
func TestBypassCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/bypass/bypass.yaml")
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
	if len(corpus.Cases) < 50 {
		t.Fatalf("corpus too small: %d", len(corpus.Cases))
	}
	for _, c := range corpus.Cases {
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
