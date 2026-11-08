//go:build integration

// Integration tests: real clients (pgx, and psql in Docker when available)
// talk to the proxy, which runs a real gateway against PostgreSQL started
// with
//
//	docker compose -f examples/dev/compose.yaml up -d --wait
//
// Run with: go test -tags integration ./internal/pgproxy/
package pgproxy_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/kyosu-1/dbgateway/internal/adapter/postgres"
	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/pgproxy"
)

const (
	humanToken = "dbgw_at_integration_human"
	agentToken = "dbgw_at_integration_agent"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// startStack wires a real gateway (PostgreSQL adapter, file audit log) and
// the proxy with a stub authenticator. It returns the proxy address and the
// audit directory.
func startStack(t *testing.T) (string, string) {
	t.Helper()
	t.Setenv("DBGW_IT_PASSWORD", env("DBGW_TEST_PG_PASSWORD", "reader"))
	yaml := fmt.Sprintf(`
auth: { dev_login: true }
databases:
  - name: dev-main
    labels: { env: prod }
    primary:
      host: %s
      port: %s
      dbname: app
      read_user: dbgw_reader
      password_env: DBGW_IT_PASSWORD
      sslmode: %s
      sslrootcert: "%s"
    limits: { max_rows: 50, max_bytes: 64KiB, statement_timeout: 2s }
groups:
  - { name: dev, members: [taro@example.com] }
role_bindings:
  - { group: dev, databases: "*", roles: [querier] }
data_classes:
  - { columns: ["public.users.email"], class: masked, semantic_type: contact }
  - { column_pattern: ".*token.*", class: masked }
  - { columns: ["public.support_tickets.body"], class: no_ai }
  - { column_pattern: "public\\.[a-z_]+\\.(id|user_id|name|plan|amount|status|reason|subject|created_at)", class: public }
semantic_types:
  contact: { method: partial }
pgproxy: { listen: 127.0.0.1:0 }
`, env("DBGW_TEST_PG_HOST", "127.0.0.1"), env("DBGW_TEST_PG_PORT", "55432"),
		env("DBGW_TEST_PG_SSLMODE", "disable"), env("DBGW_TEST_PG_SSLROOTCERT", ""))
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
	gw, err := gateway.New(gateway.Options{Config: cfg, Adapters: map[string]analysis.Adapter{"postgres": postgres.New(nil)}, Audit: al})
	if err != nil {
		t.Fatal(err)
	}
	authn := func(_ context.Context, token string) (*identity.Principal, error) {
		switch token {
		case humanToken:
			return &identity.Principal{Kind: identity.KindHuman, Human: "taro@example.com", Groups: []string{"dev"}, Scopes: []string{identity.ScopeRead}}, nil
		case agentToken:
			return &identity.Principal{Kind: identity.KindAgent, Human: "taro@example.com", Agent: "claude-code", Groups: []string{"dev"},
				Scopes: []string{identity.ScopeRead}, Databases: []string{"dev-main"}}, nil
		}
		return nil, errors.New("invalid token")
	}
	srv, err := pgproxy.New(pgproxy.Options{Config: cfg, Gateway: gw, Authenticate: authn, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-done
		gw.Close()
		_ = al.Close()
	})
	return ln.Addr().String(), dir
}

type notices struct {
	mu   sync.Mutex
	msgs []string
}

func (n *notices) add(_ *pgconn.PgConn, x *pgconn.Notice) {
	n.mu.Lock()
	n.msgs = append(n.msgs, x.Message)
	n.mu.Unlock()
}

func (n *notices) all() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return strings.Join(n.msgs, "\n")
}

func dial(t *testing.T, addr, token, mode, app string) (*pgx.Conn, *notices) {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	cs := fmt.Sprintf("host=%s port=%s dbname=dev-main user=taro password=%s sslmode=disable default_query_exec_mode=%s", host, port, token, mode)
	if app != "" {
		cs += " application_name='" + app + "'"
	}
	cc, err := pgx.ParseConfig(cs)
	if err != nil {
		t.Fatal(err)
	}
	n := &notices{}
	cc.OnNotice = n.add
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		t.Fatalf("connect (%s): %v", mode, err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn, n
}

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func TestPgxQueryModes(t *testing.T) {
	addr, auditDir := startStack(t)
	ctx := context.Background()
	for _, mode := range []string{"simple_protocol", "describe_exec", "cache_describe", "cache_statement", "exec"} {
		t.Run(mode, func(t *testing.T) {
			conn, n := dial(t, addr, humanToken, mode, "")

			// No reason yet.
			_, err := conn.Exec(ctx, "SELECT id FROM users WHERE id = 1")
			if pgCode(err) != "42501" {
				t.Fatalf("query without reason: %v", err)
			}
			if _, err := conn.Exec(ctx, "SET dbgw.reason = 'integration test: check plan of user 3'"); err != nil {
				t.Fatal(err)
			}

			var (
				id      int64
				email   string
				plan    string
				created time.Time
				amount  pgtype.Numeric
			)
			err = conn.QueryRow(ctx, "SELECT u.id, u.email, u.plan, u.created_at, o.amount FROM users u JOIN orders o ON o.user_id = u.id WHERE u.id = 3 ORDER BY o.id LIMIT 1").
				Scan(&id, &email, &plan, &created, &amount)
			if err != nil {
				t.Fatal(err)
			}
			if id != 3 || email != "u***@example.com" || plan != "pro" || created.IsZero() || !amount.Valid {
				t.Errorf("row = %d %q %q %v %+v", id, email, plan, created, amount)
			}
			if !strings.Contains(n.all(), "email") || !strings.Contains(n.all(), gateway.DataNotice) {
				t.Errorf("notices = %q", n.all())
			}

			rows, err := conn.Query(ctx, "SELECT id, plan FROM users ORDER BY id")
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for rows.Next() {
				count++
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if count != 50 {
				t.Errorf("rows = %d, want the max_rows limit 50", count)
			}
			if !strings.Contains(n.all(), "50") {
				t.Errorf("no truncation notice: %q", n.all())
			}

			_, err = conn.Exec(ctx, "DROP TABLE users")
			if pgCode(err) != "42501" {
				t.Errorf("DROP TABLE: %v", err)
			}
			_, err = conn.Exec(ctx, "SELECT * FROM no_such_table")
			if err == nil {
				t.Error("unknown table must fail")
			}
			_, err = conn.Exec(ctx, "SET search_path = public")
			if pgCode(err) != "42501" {
				t.Errorf("SET search_path: %v", err)
			}
			var v string
			if err := conn.QueryRow(ctx, "SELECT version()").Scan(&v); err != nil || !strings.Contains(v, "dbgateway") {
				t.Errorf("version() = %q, %v", v, err)
			}
			if mode != "simple_protocol" {
				_, err := conn.Exec(ctx, "SELECT id FROM users WHERE id = $1", 1)
				if pgCode(err) != "0A000" {
					t.Errorf("parameterized query: %v", err)
				}
			}
			// Transactions are accepted (each statement still runs alone).
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, "SELECT 1"); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}

	entries, err := os.ReadDir(auditDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no audit log written: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(auditDir, entries[0].Name()))
	if !strings.Contains(string(b), "pgproxy_") || !strings.Contains(string(b), "integration test: check plan of user 3") {
		t.Errorf("audit log lacks the session trace id or reason")
	}
}

func TestAgentTokenThroughProxy(t *testing.T) {
	addr, _ := startStack(t)
	ctx := context.Background()
	conn, n := dial(t, addr, agentToken, "simple_protocol", "agent: summarize ticket 1 for the user")
	var subject string
	var body *string
	if err := conn.QueryRow(ctx, "SELECT subject, body FROM support_tickets WHERE id = 1").Scan(&subject, &body); err != nil {
		t.Fatal(err)
	}
	if subject != "Cannot log in" || body != nil {
		t.Errorf("subject %q body %v: no_ai column must be withheld for agents", subject, body)
	}
	if !strings.Contains(n.all(), "body") {
		t.Errorf("notices = %q", n.all())
	}
}

// TestPsql drives the proxy with psql from the postgres:17 image.
func TestPsql(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	addr, _ := startStack(t)
	_, port, _ := net.SplitHostPort(addr)
	script := "SET dbgw.reason = 'integration test with psql';\n" +
		"SELECT id, email, plan FROM users WHERE id = 3;\n" +
		"SELECT 1 AS a; SELECT 2 AS b;\n" +
		"SHOW server_version;\n" +
		"BEGIN;\nSELECT count(*) FROM orders;\nCOMMIT;\n"
	run := func(host string, extra ...string) (string, error) {
		args := append([]string{"run", "--rm", "-i"}, extra...)
		args = append(args, "postgres:17", "psql", "-X", "-v", "ON_ERROR_STOP=1",
			fmt.Sprintf("host=%s port=%s dbname=dev-main user=taro password=%s sslmode=disable", host, port, humanToken))
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", args...)
		cmd.Stdin = strings.NewReader(script)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	// Linux: host networking reaches 127.0.0.1. Docker Desktop: the host's
	// loopback is reachable as host.docker.internal.
	out, err := run("127.0.0.1", "--network", "host")
	if err != nil && strings.Contains(out, "Connection refused") {
		out, err = run("host.docker.internal")
	}
	if err != nil && (strings.Contains(out, "Connection refused") || strings.Contains(out, "Unable to find image") || strings.Contains(out, "Cannot connect to the Docker daemon")) {
		t.Skipf("psql container cannot reach the proxy: %s", out)
	}
	if err != nil {
		t.Fatalf("psql: %v\n%s", err, out)
	}
	t.Logf("psql output:\n%s", out)
	for _, want := range []string{"u***@example.com", "(1 row)", " a \n", " b \n", "17.0 (dbgateway)", "5000", "BEGIN", "COMMIT", "NOTICE"} {
		if !strings.Contains(out, want) {
			t.Errorf("psql output lacks %q:\n%s", want, out)
		}
	}
	// A denied statement makes psql fail with the gateway's reason.
	script = "SET dbgw.reason = 'integration test with psql';\nDELETE FROM users;\n"
	out, err = run("127.0.0.1", "--network", "host")
	if err != nil && strings.Contains(out, "Connection refused") {
		out, err = run("host.docker.internal")
	}
	t.Logf("psql output:\n%s", out)
	if err == nil || !strings.Contains(out, "ERROR") || !strings.Contains(out, "request_id") {
		t.Errorf("DELETE through psql: %v\n%s", err, out)
	}
}
