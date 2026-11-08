//go:build integration

package server_test

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/server"
)

// ensurePGWriter creates dbgw_writer in the dev database if missing.
func ensurePGWriter(t *testing.T) {
	t.Helper()
	db, err := sql.Open("pgx", fmt.Sprintf("postgres://postgres:postgres@%s:%s/app?sslmode=disable",
		env("DBGW_TEST_PG_HOST", "127.0.0.1"), env("DBGW_TEST_PG_PORT", "55432")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dbgw_writer') THEN CREATE ROLE dbgw_writer LOGIN PASSWORD 'writer'; END IF; END $$`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO dbgw_writer`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func startApprovals(t *testing.T) *stack {
	t.Helper()
	ensurePGWriter(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	dir := t.TempDir()
	t.Setenv("DBGW_E2E_PASSWORD", "reader")
	t.Setenv("DBGW_E2E_WRITER", "writer")
	yaml := fmt.Sprintf(`
server: { listen: "%[1]s", public_url: "http://%[1]s" }
auth: { dev_login: true }
store: { path: "%[2]s/db.sqlite" }
audit: { dir: "%[2]s/audit" }
approvals: { enabled: true }
databases:
  - name: dev-main
    primary: { host: %[3]s, port: %[4]s, dbname: app, read_user: dbgw_reader, password_env: DBGW_E2E_PASSWORD,
               write_user: dbgw_writer, write_password_env: DBGW_E2E_WRITER, sslmode: disable }
groups:
  - { name: developers, members: [taro@example.com] }
  - { name: approvers, members: [hanako@example.com] }
role_bindings:
  - { group: developers, databases: "*", roles: [querier, writer] }
  - { group: approvers, databases: "*", roles: [querier, writer, approver] }
approval_rules:
  - { name: default, when: "true", steps: [{ role: approver }], expire_after: 10m }
`, addr, dir, env("DBGW_TEST_PG_HOST", "127.0.0.1"), env("DBGW_TEST_PG_PORT", "55432"))
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	hs := &http.Server{Handler: srv.Handler()}
	go func() { _ = hs.Serve(ln) }()
	go func() { _ = srv.RunBackground(ctx) }()
	t.Cleanup(func() { cancel(); _ = hs.Close(); srv.Close() })
	return &stack{base: "http://" + addr}
}

func browserLogin(t *testing.T, base, email string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	_, page := form(t, c, "GET", base+"/login", nil)
	if r, _ := form(t, c, "POST", base+"/login", url.Values{"csrf": {csrf(t, page)}, "email": {email}}); r.StatusCode != http.StatusFound {
		t.Fatalf("login %s: %d", email, r.StatusCode)
	}
	return c
}

func TestEndToEndApproval(t *testing.T) {
	s := startApprovals(t)
	token := oauth(t, s) // agent on behalf of taro@example.com

	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "1"}, nil).Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint: s.base + "/mcp", HTTPClient: &http.Client{Transport: &bearer{token: token, next: http.DefaultTransport}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// Read the current value to restore it afterwards.
	_, out := call(t, cs, "execute_sql", map[string]any{"database": "dev-main", "sql": "SELECT plan FROM users WHERE id = 11",
		"reason": "e2e approval: read the current plan of user 11"})
	orig := out["rows"].([]any)[0].([]any)[0].(string)
	target := map[string]string{"pro": "free", "free": "pro"}[orig]

	// 1. The agent submits a write: pending, not an error.
	res, out := call(t, cs, "execute_sql", map[string]any{"database": "dev-main",
		"sql":    fmt.Sprintf("UPDATE users SET plan = '%s' WHERE id = 11", target),
		"reason": "e2e approval: change the plan of user 11 per support ticket 1234"})
	if res.IsError || out["status"] != "pending" {
		t.Fatalf("submit: %v", out)
	}
	id := out["request_id"].(string)
	if !strings.Contains(fmt.Sprint(out["approvers"]), "hanako@example.com") {
		t.Fatalf("approvers = %v", out["approvers"])
	}

	// 2. The requester's human cannot approve; an approver must step up first.
	taro := browserLogin(t, s.base, "taro@example.com")
	_, page := form(t, taro, "GET", s.base+"/approvals/"+id, nil)
	if strings.Contains(page, "/approvals/"+id+"/approve") {
		t.Fatal("the requester must not be offered the approve button")
	}

	hanako := browserLogin(t, s.base, "hanako@example.com")
	r, page := form(t, hanako, "GET", s.base+"/approvals/"+id, nil)
	if r.StatusCode != http.StatusOK || !strings.Contains(page, "/approvals/"+id+"/approve") {
		t.Fatalf("approver page: %d", r.StatusCode)
	}
	r, _ = form(t, hanako, "POST", s.base+"/approvals/"+id+"/approve", url.Values{"csrf": {csrf(t, page)}})
	if r.StatusCode/100 != 3 || !strings.Contains(r.Header.Get("Location"), "/stepup") {
		t.Fatalf("approve without step-up: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	_, page = form(t, hanako, "GET", s.base+r.Header.Get("Location"), nil)
	if r, _ := form(t, hanako, "POST", s.base+"/stepup/dev", url.Values{"csrf": {csrf(t, page)}, "next": {"/approvals/" + id}}); r.StatusCode/100 != 3 {
		t.Fatalf("dev step-up: %d", r.StatusCode)
	}
	_, page = form(t, hanako, "GET", s.base+"/approvals/"+id, nil)
	if r, _ := form(t, hanako, "POST", s.base+"/approvals/"+id+"/approve", url.Values{"csrf": {csrf(t, page)}}); r.StatusCode/100 != 3 {
		t.Fatalf("approve: %d", r.StatusCode)
	}

	// 3. dbgateway executes the write; get_request reports success.
	var status string
	for range 50 {
		_, out = call(t, cs, "get_request", map[string]any{"request_id": id})
		req, _ := out["request"].(map[string]any)
		status, _ = req["status"].(string)
		if status == "succeeded" || status == "failed" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if status != "succeeded" {
		t.Fatalf("request = %v", out)
	}
	_, out = call(t, cs, "execute_sql", map[string]any{"database": "dev-main", "sql": "SELECT plan FROM users WHERE id = 11",
		"reason": "e2e approval: verify the plan change of user 11"})
	if got := out["rows"].([]any)[0].([]any)[0]; got != target {
		t.Fatalf("plan = %v, want %s", got, target)
	}

	// Restore through the same flow is not needed for the test; reset directly.
	t.Cleanup(func() {
		db, _ := sql.Open("pgx", fmt.Sprintf("postgres://postgres:postgres@%s:%s/app?sslmode=disable",
			env("DBGW_TEST_PG_HOST", "127.0.0.1"), env("DBGW_TEST_PG_PORT", "55432")))
		defer db.Close()
		_, _ = db.Exec("UPDATE users SET plan = $1 WHERE id = 11", orig)
	})
}
