//go:build integration

// Integration tests against a real MySQL started with
//
//	docker compose -f examples/dev/mysql/compose.yaml up -d --wait
//
// Run with: go test -tags integration ./internal/adapter/mysql/
package mysql_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	gomysql "github.com/go-sql-driver/mysql"

	"github.com/kyosu-1/dbgateway/internal/adapter/mysql"
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

func port() int {
	p, _ := strconv.Atoi(env("DBGW_TEST_MYSQL_PORT", "53306"))
	return p
}

// dbConfig returns a database configuration for the dev MySQL.
func dbConfig(t *testing.T, user, password string) *config.Database {
	t.Helper()
	t.Setenv("DBGW_IT_MYSQL_PASSWORD_"+strings.ToUpper(user), password)
	cfg, err := config.Parse(fmt.Appendf(nil, `
auth: { dev_login: true }
databases:
  - name: it
    type: mysql
    primary:
      host: %s
      port: %d
      dbname: app
      read_user: %s
      password_env: DBGW_IT_MYSQL_PASSWORD_%s
      sslmode: disable
    limits: { max_rows: 50, max_bytes: 64KiB, statement_timeout: 1s }
`, env("DBGW_TEST_MYSQL_HOST", "127.0.0.1"), port(), user, strings.ToUpper(user)))
	if err != nil {
		t.Fatal(err)
	}
	return &cfg.Databases[0]
}

func connect(t *testing.T, user, password string) (*mysql.Adapter, analysis.Conn) {
	t.Helper()
	a := mysql.New(nil)
	c, err := a.Connect(context.Background(), dbConfig(t, user, password))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return a, c
}

func readOpts() analysis.ExecOptions {
	return analysis.ExecOptions{ReadOnly: true, MaxRows: 100, MaxBytes: 1 << 20, StatementTimeout: time.Second, LockTimeout: time.Second}
}

func setup(t *testing.T, extra string) (*gateway.Gateway, string) {
	t.Helper()
	t.Setenv("DBGW_IT_PASSWORD", env("DBGW_TEST_MYSQL_PASSWORD", "reader"))
	yaml := fmt.Sprintf(`
auth: { dev_login: true }
databases:
  - name: it
    type: mysql
    labels: { env: prod }
    primary:
      host: %s
      port: %d
      dbname: app
      read_user: dbgw_reader
      password_env: DBGW_IT_PASSWORD
      sslmode: disable
    limits: { max_rows: 50, max_bytes: 64KiB, statement_timeout: 1s }
groups:
  - { name: dev, members: [taro@example.com] }
role_bindings:
  - { group: dev, databases: "*", roles: [querier] }
data_classes:
  - { columns: ["app.users.email"], class: masked, semantic_type: contact }
  - { column_pattern: ".*token.*", class: masked }
  - { columns: ["app.support_tickets.body"], class: no_ai }
  - { column_pattern: "app\\.[a-z_]+\\.(id|user_id|plan|amount|status|reason|subject|created_at|name)", class: public }
semantic_types:
  contact: { method: partial }
%s`, env("DBGW_TEST_MYSQL_HOST", "127.0.0.1"), port(), extra)
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
	gw, err := gateway.New(gateway.Options{Config: cfg, Adapters: map[string]analysis.Adapter{"mysql": mysql.New(cfg.SQL.AllowedFunctions)}, Audit: al})
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
}

func TestMaskingThroughViewsAndExpressions(t *testing.T) {
	gw, _ := setup(t, "")
	for _, sql := range []string{
		"SELECT email FROM user_contacts WHERE id = 1",
		"SELECT * FROM user_contacts WHERE id = 1",
		"SELECT upper(email) AS e FROM users WHERE id = 1",
		"SELECT x FROM (SELECT email AS x, id FROM users) s WHERE id = 1",
		"WITH c AS (SELECT id, email FROM users) SELECT email FROM c WHERE id = 1",
		"SELECT * FROM users WHERE id = 1",
		"SELECT * FROM users u JOIN subscriptions s USING (id) WHERE u.id = 1",
		"SELECT * FROM subscriptions s RIGHT JOIN users u USING (id) WHERE u.id = 1",
		"SELECT CONCAT(name, ':', email) FROM users WHERE id = 1",
		"SELECT JSON_OBJECT('e', email) FROM users WHERE id = 1",
		"SELECT id, email FROM users WHERE id = 1 UNION ALL SELECT id, plan FROM users WHERE id = 2",
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
				if m, ok := v.(map[string]any); ok && strings.Contains(fmt.Sprint(m), "user1@") {
					t.Errorf("%s: leaked %v", sql, m)
				}
			}
		}
	}
}

// TestOutputLineageMatchesResultColumns checks that the analyzer's output
// columns line up with the columns MySQL actually returns, in particular
// the column order of "*" over NATURAL / USING / RIGHT joins and views.
func TestOutputLineageMatchesResultColumns(t *testing.T) {
	a, c := connect(t, "dbgw_reader", "reader")
	ctx := context.Background()
	cat, err := a.Catalog(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		"SELECT * FROM users",
		"SELECT * FROM user_contacts",
		"SELECT * FROM users JOIN subscriptions USING (id)",
		"SELECT * FROM users JOIN subscriptions USING (id, plan)",
		"SELECT * FROM users NATURAL JOIN subscriptions",
		"SELECT * FROM users NATURAL LEFT JOIN subscriptions",
		"SELECT * FROM users NATURAL RIGHT JOIN subscriptions",
		"SELECT * FROM subscriptions RIGHT JOIN users USING (id)",
		"SELECT * FROM users LEFT JOIN subscriptions USING (plan, id)",
		"SELECT * FROM users u JOIN orders o ON o.user_id = u.id",
		"SELECT o.*, u.email FROM users u JOIN orders o ON o.user_id = u.id",
		"SELECT * FROM (SELECT * FROM users NATURAL JOIN subscriptions) x",
		"WITH c AS (SELECT * FROM users) SELECT * FROM c JOIN orders USING (id)",
		"TABLE users",
		"SELECT * FROM users NATURAL JOIN user_contacts",
	} {
		t.Run(sql, func(t *testing.T) {
			qa, err := a.Analyze(ctx, sql, cat)
			if err != nil {
				t.Fatal(err)
			}
			if qa.Statement.Unknown {
				t.Fatalf("unknown: %v", qa.Statement.UnknownReasons)
			}
			res, err := a.Execute(ctx, c, sql, readOpts())
			if err != nil {
				t.Fatal(err)
			}
			var got, want []string
			for _, rc := range res.Columns {
				got = append(got, strings.ToLower(rc.Name))
			}
			for _, o := range qa.Output {
				want = append(want, strings.ToLower(o.Name))
				// Every direct column must come from a column of that name.
				if o.Direct && !strings.EqualFold(o.Sources[0].Column, o.Name) && !strings.Contains(sql, "user_contacts") {
					t.Errorf("output %s is direct from %s", o.Name, o.Sources[0].FQN())
				}
			}
			if !slices.Equal(got, want) {
				t.Errorf("result columns %q, analysis %q", got, want)
			}
		})
	}
}

func TestPredicatesOnMaskedColumnsDenied(t *testing.T) {
	gw, _ := setup(t, "")
	for _, sql := range []string{
		"SELECT id FROM users WHERE email LIKE 'user1%'",
		"SELECT count(*) FROM users GROUP BY email",
		"SELECT id FROM users ORDER BY email LIMIT 1",
		"SELECT id FROM users u JOIN user_contacts c USING (id) WHERE c.email = 'x'",
		// NATURAL JOIN compares every common column, including email.
		"SELECT id FROM users NATURAL JOIN user_contacts",
		"SELECT email AS e FROM users HAVING e LIKE 'user1%'",
	} {
		if r := exec(t, gw, agent, sql); r.Status != gateway.StatusDenied {
			t.Errorf("%s: status %s", sql, r.Status)
		}
	}
}

func TestNoAIWithheldForAgentsShownToHumans(t *testing.T) {
	gw, _ := setup(t, "")
	r := exec(t, gw, agent, "SELECT id, body FROM support_tickets ORDER BY id")
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
	r = exec(t, gw, human, "WITH RECURSIVE g (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM g WHERE n < 40) SELECT REPEAT('x', 4000) FROM g")
	if r.Status != gateway.StatusOK || !r.Truncated || r.RowCount >= 40 {
		t.Fatalf("byte limit: rows=%d truncated=%v (%s)", r.RowCount, r.Truncated, r.Reason)
	}
}

// slowQuery takes far longer than the 1s statement timeout. (A plain
// COUNT(*) over a cross join is answered without scanning.)
const slowQuery = "SELECT COUNT(*) FROM orders a, orders b, orders c WHERE a.amount + b.amount + c.amount > 0"

func TestStatementTimeout(t *testing.T) {
	a, c := connect(t, "dbgw_reader", "reader")
	ctx := context.Background()
	start := time.Now()
	_, err := a.Execute(ctx, c, slowQuery, readOpts())
	if err == nil {
		t.Fatal("expected a timeout")
	}
	if _, code, ok := mysql.DescribeError(err); !ok || code != "mysql:3024" {
		t.Fatalf("error = %v (code %s)", err, code)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("timeout took %s", d)
	}
	// The pool is usable afterwards.
	if _, err := a.Execute(ctx, c, "SELECT 1", readOpts()); err != nil {
		t.Fatalf("after timeout: %v", err)
	}

	gw, _ := setup(t, "")
	if r := exec(t, gw, human, slowQuery); r.Status != gateway.StatusError {
		t.Fatalf("gateway: status=%s reason=%s", r.Status, r.Reason)
	}
	if r := exec(t, gw, human, "SELECT 1"); r.Status != gateway.StatusOK {
		t.Fatalf("after timeout: %s %s", r.Status, r.Reason)
	}
}

func TestSessionSettings(t *testing.T) {
	a, c := connect(t, "dbgw_reader", "reader")
	res, err := a.Execute(context.Background(), c,
		"SELECT @@session.sql_mode, @@session.max_execution_time, @@session.lock_wait_timeout, @@session.time_zone, DATABASE()", readOpts())
	if err != nil {
		t.Fatal(err)
	}
	row := res.Rows[0]
	gotMode := strings.Split(fmt.Sprint(row[0]), ",")
	wantMode := strings.Split(mysql.SQLMode, ",")
	slices.Sort(gotMode)
	slices.Sort(wantMode)
	if !slices.Equal(gotMode, wantMode) || fmt.Sprint(row[1]) != "1000" || fmt.Sprint(row[2]) != "1" || row[3] != "+00:00" || row[4] != "app" {
		t.Errorf("session = %v", row)
	}
}

// TestReadOnlyEnforcedByDatabase sends statements directly to Execute,
// bypassing the analyzer, to prove the database-side defenses.
func TestReadOnlyEnforcedByDatabase(t *testing.T) {
	ctx := context.Background()
	a, c := connect(t, "dbgw_reader", "reader")

	// Writes are not executed in phase 1.
	if _, err := a.Execute(ctx, c, "SELECT 1", analysis.ExecOptions{}); err == nil {
		t.Error("write execution must be refused")
	}
	// The server refuses several statements in one request.
	if _, err := a.Execute(ctx, c, "SELECT 1; SELECT 2", readOpts()); err == nil {
		t.Error("multiple statements must be refused by the server")
	}
	// The read user has SELECT only.
	if _, err := a.Execute(ctx, c, "INSERT INTO orders (id, user_id, amount) VALUES (999999, 1, 1)", readOpts()); err == nil {
		t.Error("insert must fail")
	}
	// Even a user with write privileges cannot write: the transaction is
	// READ ONLY.
	ra, rc := connect(t, "root", env("DBGW_TEST_MYSQL_ROOT_PASSWORD", "root"))
	_, err := ra.Execute(ctx, rc, "INSERT INTO orders (id, user_id, amount) VALUES (999999, 1, 1)", readOpts())
	var me *gomysql.MySQLError
	if !errors.As(err, &me) || me.Number != mysql.ErrReadOnlyTx {
		t.Errorf("insert as root: %v", err)
	}

	// Session state does not leak into the next request: the connection
	// is discarded after every request.
	if _, err := a.Execute(ctx, c, "SELECT @leak := 42", readOpts()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Execute(ctx, c, "SET SESSION max_execution_time = 0", readOpts()); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		res, err := a.Execute(ctx, c, "SELECT @leak, @@session.max_execution_time", readOpts())
		if err != nil {
			t.Fatal(err)
		}
		if res.Rows[0][0] != nil || fmt.Sprint(res.Rows[0][1]) != "1000" {
			t.Fatalf("session state leaked: %v", res.Rows[0])
		}
	}
}

func TestLocalInfileRefused(t *testing.T) {
	a, c := connect(t, "root", env("DBGW_TEST_MYSQL_ROOT_PASSWORD", "root"))
	if _, err := a.Execute(context.Background(), c, "LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE orders", readOpts()); err == nil {
		t.Fatal("LOAD DATA LOCAL must fail")
	}
}

func TestDatabaseErrorsDoNotLeakValues(t *testing.T) {
	gw, _ := setup(t, "")
	r := exec(t, gw, human, "SELECT id FROM users WHERE id = 1 AND JSON_EXTRACT(email, '$') IS NULL")
	if r.Status != gateway.StatusError {
		t.Fatalf("status = %s", r.Status)
	}
	if strings.Contains(r.Reason, "@example.com") {
		t.Fatalf("error leaked a value: %s", r.Reason)
	}
	msg, code, ok := mysql.DescribeError(&gomysql.MySQLError{Number: 1292, Message: "Truncated incorrect DOUBLE value: 'user1@example.com'"})
	if !ok || code != "mysql:1292" || strings.Contains(msg, "user1") {
		t.Errorf("DescribeError = %q %q %v", msg, code, ok)
	}
	msg, _, _ = mysql.DescribeError(&gomysql.MySQLError{Number: 1054, Message: "Unknown column 'nope' in 'field list'"})
	if !strings.Contains(msg, "nope") {
		t.Errorf("identifier errors should be passed through: %q", msg)
	}
}

func TestRejectionsAndAudit(t *testing.T) {
	gw, dir := setup(t, "")
	for _, sql := range []string{"SELECT 1; DROP TABLE users", "COMMIT", "DELETE FROM users WHERE id = 1", "SELECT /*!99999 email AS id, */ id FROM users"} {
		if r := exec(t, gw, agent, sql); r.Status != gateway.StatusDenied || r.Reason == "" || r.Hint == "" {
			t.Errorf("%s: %+v", sql, r)
		}
	}
	exec(t, gw, agent, "SELECT id FROM users WHERE id = 1")
	rep, err := audit.VerifyDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Entries != 5 {
		t.Errorf("audit entries = %d, want 5", rep.Entries)
	}
	m, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	b, _ := os.ReadFile(m[0])
	if strings.Contains(string(b), "id = 1\"") || strings.Contains(string(b), "99999") {
		t.Error("literal recorded in the audit log")
	}
}

func TestCatalog(t *testing.T) {
	a, c := connect(t, "dbgw_reader", "reader")
	cat, err := a.Catalog(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cat.SearchPath, []string{"app"}) {
		t.Errorf("search path = %v", cat.SearchPath)
	}
	users := cat.Lookup("", "users")
	if users == nil || users.Kind != analysis.RelTable || len(users.Columns) != 7 || users.Columns[2].Name != "email" {
		t.Fatalf("users = %+v", users)
	}
	if users.Columns[2].Comment != "Login e-mail address" || users.Columns[3].Nullable != true || users.Columns[0].Type != "bigint" {
		t.Errorf("columns = %+v", users.Columns)
	}
	v := cat.Lookup("app", "user_contacts")
	if v == nil || v.Kind != analysis.RelView || !strings.Contains(v.Definition, "lower(`app`.`users`.`email`)") {
		t.Fatalf("view = %+v", v)
	}
	if cat.Lookup("information_schema", "TABLES") == nil {
		t.Error("information_schema relations should be in the catalog")
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
		if o.Schema != "app" {
			t.Errorf("system schema object listed: %s.%s", o.Schema, o.Name)
		}
		if o.Name == "users" {
			found = true
			for _, c := range o.Columns {
				if c.Name == "email" && !c.Masked {
					t.Error("email should be marked masked")
				}
				if c.Name == "id" && c.Masked {
					t.Error("id should not be masked")
				}
			}
			var defs []string
			for _, ix := range o.Indexes {
				defs = append(defs, ix.Definition)
			}
			if !slices.Contains(defs, "PRIMARY KEY (`id`)") || !slices.Contains(defs, "INDEX `users_email_idx` (`email`)") {
				t.Errorf("indexes = %v", defs)
			}
			if o.Comment != "Application users" || o.RowEstimate == nil {
				t.Errorf("comment=%q rows=%v", o.Comment, o.RowEstimate)
			}
		}
	}
	if !found {
		t.Fatalf("users not found: %+v", resp.Objects)
	}
}

func TestEstimate(t *testing.T) {
	a, c := connect(t, "dbgw_reader", "reader")
	ctx := context.Background()
	est, err := a.Estimate(ctx, c, "SELECT * FROM orders", readOpts())
	if err != nil {
		t.Fatal(err)
	}
	if est.Rows < 1000 || est.Cost <= 0 {
		t.Errorf("estimate = %+v", est)
	}
	est, err = a.Estimate(ctx, c, "SELECT * FROM users u JOIN orders o ON o.user_id = u.id WHERE u.id = 1", readOpts())
	if err != nil {
		t.Fatal(err)
	}
	if est.Rows < 1 || est.Rows > 1000 {
		t.Errorf("join estimate = %+v", est)
	}
	est, err = a.Estimate(ctx, c, "SELECT 1", readOpts())
	if err != nil || est.Rows != 1 {
		t.Errorf("SELECT 1 estimate = %+v, %v", est, err)
	}
}

func TestValues(t *testing.T) {
	a, c := connect(t, "dbgw_reader", "reader")
	res, err := a.Execute(context.Background(), c, `SELECT
		CAST(1.50 AS DECIMAL(10,2)), TIMESTAMP '2024-01-02 03:04:05.123456', DATE '2024-01-02', TIME '10:11:12',
		x'0102', CAST('{"a": [1, "b"]}' AS JSON), 1.5e0, CAST(18446744073709551615 AS UNSIGNED), b'101',
		NULL, 'テキスト', 42, CAST(-1 AS SIGNED), created_at
		FROM users WHERE id = 1`, readOpts())
	if err != nil {
		t.Fatal(err)
	}
	row := res.Rows[0]
	want := []any{"1.50", "2024-01-02T03:04:05.123456Z", "2024-01-02", "10:11:12", `\x0102`,
		map[string]any{"a": []any{float64(1), "b"}}, 1.5, "18446744073709551615", `\x05`, nil, "テキスト", int64(42), int64(-1)}
	for i, w := range want {
		if fmt.Sprintf("%#v", row[i]) != fmt.Sprintf("%#v", w) {
			t.Errorf("column %d (%s) = %#v, want %#v", i, res.Columns[i].Type, row[i], w)
		}
	}
	if s, ok := row[13].(string); !ok || !strings.HasSuffix(s, "Z") || !strings.Contains(s, "T") {
		t.Errorf("created_at = %#v", row[13])
	}
}

// rootDB returns a plain connection as root for test fixtures.
func rootDB(t *testing.T) *sql.DB {
	t.Helper()
	mc := gomysql.NewConfig()
	mc.User, mc.Passwd = "root", env("DBGW_TEST_MYSQL_ROOT_PASSWORD", "root")
	mc.Net, mc.Addr, mc.DBName = "tcp", fmt.Sprintf("%s:%d", env("DBGW_TEST_MYSQL_HOST", "127.0.0.1"), port()), "app"
	connector, err := gomysql.NewConnector(mc)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(connector)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestInvisibleColumns checks that INVISIBLE columns, which "SELECT *"
// does not return, are left out of star expansion, and that naming one
// explicitly is unknown.
func TestInvisibleColumns(t *testing.T) {
	ctx := context.Background()
	root := rootDB(t)
	for _, q := range []string{
		"DROP TABLE IF EXISTS it_invisible",
		"CREATE TABLE it_invisible (id INT PRIMARY KEY, secret VARCHAR(16) INVISIBLE, note VARCHAR(16))",
		"INSERT INTO it_invisible (id, secret, note) VALUES (1, 's3cret', 'n')",
	} {
		if _, err := root.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = root.ExecContext(context.Background(), "DROP TABLE IF EXISTS it_invisible") })

	a, c := connect(t, "dbgw_reader", "reader")
	cat, err := a.Catalog(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	qa, err := a.Analyze(ctx, "SELECT * FROM it_invisible", cat)
	if err != nil || qa.Statement.Unknown {
		t.Fatalf("analyze: %v %+v", err, qa)
	}
	res, err := a.Execute(ctx, c, "SELECT * FROM it_invisible", readOpts())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Columns) != len(qa.Output) || len(qa.Output) != 2 || qa.Output[1].Sources[0].Column != "note" {
		t.Fatalf("result %+v, analysis %+v", res.Columns, qa.Output)
	}
	qa, err = a.Analyze(ctx, "SELECT secret FROM it_invisible", cat)
	if err == nil && !qa.Statement.Unknown {
		t.Error("explicit reference to an invisible column must be unknown")
	}
}

func TestTrailingSemicolon(t *testing.T) {
	gw, _ := setup(t, "")
	if r := exec(t, gw, human, "SELECT id FROM users WHERE id = 1;"); r.Status != gateway.StatusOK || len(r.Rows) != 1 {
		t.Fatalf("status=%s reason=%s", r.Status, r.Reason)
	}
}
