package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/structpb"

	dbgatewayv1 "github.com/kyosu-1/dbgateway/gen/dbgateway/v1"
	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/api"
	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/auth"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/gateway/gatewaytest"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/policy"
	"github.com/kyosu-1/dbgateway/internal/store"
)

const queryConfig = `
server:
  listen: 127.0.0.1:8443
  public_url: %s
auth:
  dev_login: true
approvals: { enabled: true }
databases:
  - name: prod
    labels: { env: prod }
    primary: { host: localhost, read_user: r, write_user: w, sslmode: disable }
    docs:
      description: Production database.
      tables:
        public.users: { description: One row per account., columns: { plan: "free | pro" } }
      examples:
        - title: Accounts per plan
          description: All accounts.
          sql: |
            SELECT plan, count(*)
            FROM users GROUP BY plan
groups:
  - { name: dev, members: [taro@example.com] }
  - { name: sre, members: [hanako@example.com] }
role_bindings:
  - { group: dev, databases: "*", roles: [querier, writer] }
  - { group: sre, databases: "*", roles: [querier, writer, approver] }
data_classes:
  - { columns: [public.users.email], class: masked }
  - { column_pattern: "public\\.users\\.(id|plan|name)", class: public }
approval_rules:
  - { name: default, when: "true", steps: [{ role: approver }], expire_after: 30m }
`

type cliEnv struct {
	public string
	store  store.Store
	fa     *gatewaytest.Adapter
	tokens map[string]string // email -> raw access token
}

// newCLIEnv starts a dbgateway API server (GatewayService on a fake
// database) and redirects the credentials file to a temporary directory.
func newCLIEnv(t *testing.T) *cliEnv {
	t.Helper()
	ctx := context.Background()
	srv := httptest.NewUnstartedServer(nil)
	public := "http://" + srv.Listener.Addr().String()
	cfg, err := config.Parse([]byte(strings.Replace(queryConfig, "%s", public, 1)))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := auth.New(ctx, auth.Options{Config: cfg, Store: st, RBAC: policy.NewRBAC(cfg), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	sink, err := audit.OpenFileSink(t.TempDir(), 0, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.New(sink)
	if err != nil {
		t.Fatal(err)
	}
	fa := gatewaytest.New()
	fa.Result = analysis.Result{Columns: []analysis.ResultColumn{{Name: "id", Type: "int8"}, {Name: "email", Type: "text"}},
		Rows: [][]any{{int64(1), "user1@example.com"}, {int64(22), "user22@example.com"}}}
	gw, err := gateway.New(gateway.Options{Config: cfg, Adapters: map[string]analysis.Adapter{"postgres": fa}, Audit: al, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	svc := approval.New(approval.Options{Config: cfg, Store: st, Executor: gw, Audit: al, Logger: logger})
	gw.SetApprovals(svc)
	mux := http.NewServeMux()
	path, h := api.NewGatewayService(a, gw, svc, cfg)
	mux.Handle(path, h)
	srv.Config.Handler = mux
	srv.Start()

	credPath := filepath.Join(t.TempDir(), "credentials.json")
	old := credentialsPath
	credentialsPath = func() (string, error) { return credPath, nil }
	t.Setenv("DBGW_SERVER", "")
	t.Cleanup(func() {
		credentialsPath = old
		srv.Close()
		svc.Wait()
		gw.Close()
		_ = al.Close()
		st.Close()
	})
	e := &cliEnv{public: public, store: st, fa: fa, tokens: map[string]string{}}
	now := time.Now()
	for _, email := range []string{"taro@example.com", "hanako@example.com"} {
		raw := auth.AccessTokenPrefix + "cli-" + email
		if err := st.CreateToken(ctx, &store.Token{ID: "tok_" + email, Hash: store.HashSecret(raw), Type: store.TokenAccess,
			Kind: identity.KindHuman, Human: email, ClientID: auth.CLIClientID, Scopes: []string{identity.ScopeRead},
			Audience: public, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		e.tokens[email] = raw
	}
	e.login(t, "taro@example.com")
	return e
}

// login saves credentials as `dbgw login` would.
func (e *cliEnv) login(t *testing.T, email string) {
	t.Helper()
	if err := saveCredentials(&Credentials{Server: e.public, AccessToken: e.tokens[email], ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

type result struct {
	stdout, stderr string
	err            error
}

func (r result) exitCode() int {
	var ec *ExitCodeError
	switch {
	case r.err == nil:
		return 0
	case errors.As(r.err, &ec):
		return ec.Code
	}
	return 1
}

// run executes a dbgw command line with the client commands.
func run(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	root := &cobra.Command{Use: "dbgw", SilenceUsage: true, SilenceErrors: true}
	root.AddCommand(QueryCmd(), ExplainCmd(), DatabasesCmd(), SearchCmd(), RequestsCmd(), RequestCmd(), TokenCmd())
	var out, errw bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errw)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return result{stdout: out.String(), stderr: errw.String(), err: err}
}

const reason = "CLI test: check the user's plan for support"

func TestQueryTable(t *testing.T) {
	newCLIEnv(t)
	r := run(t, "", "query", "--db", "prod", "--reason", reason, "SELECT id, email FROM users WHERE id IN (1, 22)")
	if r.err != nil {
		t.Fatalf("err = %v, stderr = %s", r.err, r.stderr)
	}
	lines := strings.Split(r.stdout, "\n")
	if lines[0] != " id | email*" || lines[1] != "----+--------" {
		t.Fatalf("header:\n%s", r.stdout)
	}
	// Numbers are right-aligned; the masked e-mail is not the original.
	if !strings.HasPrefix(lines[2], "  1 | ") || !strings.HasPrefix(lines[3], " 22 | ") || strings.Contains(r.stdout, "user1@example.com") {
		t.Fatalf("rows:\n%s", r.stdout)
	}
	if !strings.HasSuffix(r.stdout, "(2 rows)\n* masked: email\n") {
		t.Fatalf("footer:\n%s", r.stdout)
	}
}

func TestQueryJSONAndCSV(t *testing.T) {
	newCLIEnv(t)
	r := run(t, "", "query", "--db", "prod", "--reason", reason, "--format", "json", "SELECT", "id,", "email", "FROM", "users")
	if r.err != nil {
		t.Fatalf("err = %v, stderr = %s", r.err, r.stderr)
	}
	var got struct {
		Status    string `json:"status"`
		RequestID string `json:"request_id"`
		Columns   []struct {
			Name   string `json:"name"`
			Masked bool   `json:"masked"`
		} `json:"columns"`
		Rows     [][]any `json:"rows"`
		RowCount int     `json:"row_count"`
		Notice   string  `json:"notice"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, r.stdout)
	}
	if got.Status != "ok" || got.RequestID == "" || len(got.Columns) != 2 || !got.Columns[1].Masked || got.Columns[0].Masked ||
		len(got.Rows) != 2 || got.Rows[0][0] != 1.0 || got.Rows[0][1] == "user1@example.com" || got.RowCount != 2 || got.Notice == "" {
		t.Fatalf("json = %+v", got)
	}

	r = run(t, "", "query", "--db", "prod", "--reason", reason, "-o", "csv", "SELECT id, email FROM users")
	if r.err != nil {
		t.Fatalf("err = %v, stderr = %s", r.err, r.stderr)
	}
	if !regexp.MustCompile(`\Aid,email\n1,[^\n]+\n22,[^\n]+\n\z`).MatchString(r.stdout) || strings.Contains(r.stdout, "user1@example.com") {
		t.Fatalf("csv:\n%s", r.stdout)
	}
	if !strings.Contains(r.stderr, "masked or withheld columns: email") {
		t.Fatalf("stderr = %q", r.stderr)
	}
}

func TestQueryInputSources(t *testing.T) {
	e := newCLIEnv(t)
	if r := run(t, "SELECT id, email FROM users WHERE id = 1\n", "query", "--db", "prod", "--reason", reason); r.err != nil {
		t.Fatalf("stdin: %v %s", r.err, r.stderr)
	}
	file := filepath.Join(t.TempDir(), "q.sql")
	if err := os.WriteFile(file, []byte("SELECT id, email FROM users WHERE id = 2;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := run(t, "", "query", "--db", "prod", "--reason", reason, "-f", file); r.err != nil {
		t.Fatalf("file: %v %s", r.err, r.stderr)
	}
	execs := e.fa.Execs()
	if len(execs) != 2 || execs[0].SQL != "SELECT id, email FROM users WHERE id = 1" || execs[1].SQL != "SELECT id, email FROM users WHERE id = 2;" {
		t.Fatalf("execs = %+v", execs)
	}
	for name, args := range map[string][]string{
		"empty stdin":  {"query", "--db", "prod", "--reason", reason},
		"file and arg": {"query", "--db", "prod", "--reason", reason, "-f", file, "SELECT 1"},
		"no reason":    {"query", "--db", "prod", "SELECT 1"},
		"bad format":   {"query", "--db", "prod", "--reason", reason, "-o", "xml", "SELECT 1"},
	} {
		if r := run(t, "", args...); r.err == nil || r.exitCode() != 1 {
			t.Errorf("%s: err = %v", name, r.err)
		}
	}
	if len(e.fa.Execs()) != 2 {
		t.Fatal("invalid invocations must not reach the database")
	}
}

func TestQueryExitCodes(t *testing.T) {
	e := newCLIEnv(t)

	r := run(t, "", "query", "--db", "prod", "--reason", reason, "DROP TABLE users")
	if r.exitCode() != ExitDenied || r.stdout != "" || !strings.Contains(r.stderr, "denied: ") || !strings.Contains(r.stderr, "hint: ") ||
		!strings.Contains(r.stderr, "rule: default-deny-ddl") {
		t.Fatalf("denied: code %d\nstdout=%s\nstderr=%s", r.exitCode(), r.stdout, r.stderr)
	}

	r = run(t, "", "query", "--db", "prod", "--reason", reason, "UPDATE users SET plan = 'pro' WHERE id = 1")
	id := regexp.MustCompile(`req_[a-z0-9]+`).FindString(r.stderr)
	if r.exitCode() != ExitPending || id == "" || !strings.Contains(r.stderr, e.public+"/approvals/"+id) ||
		!strings.Contains(r.stderr, "hanako@example.com") || !strings.Contains(r.stderr, "NOT run") {
		t.Fatalf("pending: code %d\nstderr=%s", r.exitCode(), r.stderr)
	}
	// JSON output still carries the full response on stdout.
	r = run(t, "", "query", "--db", "prod", "--reason", reason, "-o", "json", "UPDATE users SET plan = 'pro' WHERE id = 2")
	if r.exitCode() != ExitPending || !strings.Contains(r.stdout, `"status": "pending"`) || !strings.Contains(r.stdout, `"approval_url"`) {
		t.Fatalf("pending json: code %d\nstdout=%s", r.exitCode(), r.stdout)
	}

	e.fa.Set(func(a *gatewaytest.Adapter) {
		a.ExecErr = &pgconn.PgError{Code: "42703", Message: `column "x" does not exist`}
	})
	r = run(t, "", "query", "--db", "prod", "--reason", reason, "SELECT id FROM users")
	if r.exitCode() != ExitFailure || !strings.Contains(r.stderr, "error: ") || !strings.Contains(r.stderr, "SQLSTATE 42703") {
		t.Fatalf("error: code %d\nstderr=%s", r.exitCode(), r.stderr)
	}
	if len(e.fa.Writes()) != 0 {
		t.Fatal("nothing must be written")
	}
}

func TestNotLoggedIn(t *testing.T) {
	e := newCLIEnv(t)
	if err := deleteCredentials(); err != nil {
		t.Fatal(err)
	}
	r := run(t, "", "dbs")
	if !errors.Is(r.err, errNotLoggedIn) {
		t.Fatalf("no credentials: %v", r.err)
	}
	// Expired locally.
	if err := saveCredentials(&Credentials{Server: e.public, AccessToken: e.tokens["taro@example.com"], ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if r := run(t, "", "query", "--db", "prod", "--reason", reason, "SELECT 1"); !errors.Is(r.err, errNotLoggedIn) {
		t.Fatalf("expired: %v", r.err)
	}
	// Revoked on the server.
	e.login(t, "taro@example.com")
	if _, err := e.store.RevokeToken(context.Background(), "tok_taro@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	if r := run(t, "", "dbs"); !errors.Is(r.err, errNotLoggedIn) || !strings.Contains(r.err.Error(), "dbgw login") {
		t.Fatalf("revoked: %v", r.err)
	}
}

func TestDatabasesSearchExplain(t *testing.T) {
	newCLIEnv(t)
	r := run(t, "", "dbs")
	if r.err != nil || !regexp.MustCompile(`(?m)^prod\s+postgres\s+querier,writer,viewer\s+yes\s+yes\s+approval\s+\S+\s+env=prod\s+Production database\.$`).MatchString(r.stdout) ||
		!regexp.MustCompile(`LABELS\s+DESCRIPTION\n`).MatchString(r.stdout) {
		t.Fatalf("dbs: %v\n%s", r.err, r.stdout)
	}
	r = run(t, "", "search", "--db", "prod", "users")
	if r.err != nil || !strings.Contains(r.stdout, "public.users (table) -- One row per account.") || !regexp.MustCompile(`(?m)^  email\*\s+text`).MatchString(r.stdout) ||
		!regexp.MustCompile(`(?m)^  plan\s+text\s+.*-- free \| pro$`).MatchString(r.stdout) ||
		!strings.Contains(r.stdout, "* masked for you") ||
		!strings.Contains(r.stdout, "Examples:\n  Accounts per plan -- All accounts.\n    SELECT plan, count(*)\n    FROM users GROUP BY plan\n") {
		t.Fatalf("search: %v\n%s", r.err, r.stdout)
	}
	if r := run(t, "", "search", "--db", "nope"); r.err == nil || !strings.Contains(r.err.Error(), "no access") {
		t.Fatalf("search unknown db: %v", r.err)
	}
	r = run(t, "", "explain", "--db", "prod", "UPDATE users SET plan = 'x' WHERE id = 1 RETURNING id, email")
	if r.err != nil || !strings.Contains(r.stdout, "Decision:") || !strings.Contains(r.stdout, "approve") ||
		!strings.Contains(r.stdout, "Approval rule:  default, expires after 30m0s") || !strings.Contains(r.stdout, "hanako@example.com") ||
		!regexp.MustCompile(`(?m)^  email\s+masked\s+masked \*$`).MatchString(r.stdout) {
		t.Fatalf("explain: %v\n%s", r.err, r.stdout)
	}
	r = run(t, "", "explain", "--db", "prod", "-o", "json", "DROP TABLE users")
	if r.err != nil || !strings.Contains(r.stdout, `"decision": "POLICY_DECISION_DENY"`) {
		t.Fatalf("explain json: %v\n%s", r.err, r.stdout)
	}
}

func TestRequestCommands(t *testing.T) {
	e := newCLIEnv(t)
	submit := func(sql string) string {
		t.Helper()
		r := run(t, "", "query", "--db", "prod", "--reason", reason, sql)
		id := regexp.MustCompile(`req_[a-z0-9]+`).FindString(r.stderr)
		if r.exitCode() != ExitPending || id == "" {
			t.Fatalf("submit: %d %s", r.exitCode(), r.stderr)
		}
		return id
	}
	first := submit("UPDATE users SET plan = 'pro' WHERE id = 1")
	second := submit("UPDATE users SET plan = 'free' WHERE id = 2")

	r := run(t, "", "requests")
	if r.err != nil || !strings.Contains(r.stdout, first) || !strings.Contains(r.stdout, second) || !strings.Contains(r.stdout, "pending") {
		t.Fatalf("requests: %v\n%s", r.err, r.stdout)
	}
	r = run(t, "", "request", first)
	if r.err != nil || !strings.Contains(r.stdout, "Status:         pending") || !strings.Contains(r.stdout, "UPDATE users SET plan = 'pro' WHERE id = 1") ||
		!strings.Contains(r.stdout, "step 1:") {
		t.Fatalf("request: %v\n%s", r.err, r.stdout)
	}
	if r := run(t, "", "request", "cancel", second); r.err != nil || !strings.Contains(r.stderr, "Canceled "+second) {
		t.Fatalf("cancel: %v %s", r.err, r.stderr)
	}
	if r := run(t, "", "request", "reject", first); r.err == nil || !strings.Contains(r.err.Error(), "cannot reject your own") {
		t.Fatalf("self reject: %v", r.err)
	}

	e.login(t, "hanako@example.com")
	r = run(t, "", "requests", "--scope", "awaiting")
	if r.err != nil || !strings.Contains(r.stdout, first) || strings.Contains(r.stdout, second) {
		t.Fatalf("awaiting: %v\n%s", r.err, r.stdout)
	}
	if r := run(t, "", "request", "reject", first, "--comment", "use the batch job"); r.err != nil || !strings.Contains(r.stderr, "Rejected "+first) {
		t.Fatalf("reject: %v %s", r.err, r.stderr)
	}
	r = run(t, "", "request", first, "-o", "json")
	if r.err != nil || !strings.Contains(r.stdout, `"status": "APPROVAL_STATUS_REJECTED"`) || !strings.Contains(r.stdout, "use the batch job") {
		t.Fatalf("request json: %v\n%s", r.err, r.stdout)
	}
	if r := run(t, "", "requests", "--scope", "everything"); r.err == nil {
		t.Fatal("bad scope accepted")
	}
	if r := run(t, "", "request", "req_nope"); r.err == nil || !strings.Contains(r.err.Error(), "does not exist") {
		t.Fatalf("missing request: %v", r.err)
	}
}

func TestTokenPrint(t *testing.T) {
	e := newCLIEnv(t)
	r := run(t, "", "token", "print")
	if r.err != nil || r.stdout != e.tokens["taro@example.com"]+"\n" || !strings.Contains(r.stderr, "secret") {
		t.Fatalf("token print: %v\nstdout=%q\nstderr=%q", r.err, r.stdout, r.stderr)
	}
	if err := deleteCredentials(); err != nil {
		t.Fatal(err)
	}
	if r := run(t, "", "token", "print"); !errors.Is(r.err, errNotLoggedIn) || r.stdout != "" {
		t.Fatalf("not logged in: %v %q", r.err, r.stdout)
	}
}

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                "plain",
		"日本語":                  "日本語",
		"a\nb\tc\r":            `a\nb\tc\r`,
		"\x1b[31mred\x1b[0m":   `\x1b[31mred\x1b[0m`,
		"\u202eevil":           `\u202eevil`,
		"bell\x07 and del\x7f": `bell\x07 and del\x7f`,
	} {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResultTableWidths(t *testing.T) {
	cols := []*dbgatewayv1.ResultColumn{{Name: "name"}, {Name: "n"}, {Name: "secret", Withheld: true}}
	rows := []*dbgatewayv1.Row{
		{Values: []*structpb.Value{structpb.NewStringValue("山田"), structpb.NewNumberValue(1234), structpb.NewNullValue()}},
		{Values: []*structpb.Value{structpb.NewNullValue(), structpb.NewNumberValue(1.5), structpb.NewNullValue()}},
	}
	var b bytes.Buffer
	if err := resultTable(&b, cols, rows, 2); err != nil {
		t.Fatal(err)
	}
	want := " name | n    | secret!\n" +
		"------+------+------------\n" +
		" 山田 | 1234 | (withheld)\n" +
		" NULL |  1.5 | (withheld)\n" +
		"(2 rows)\n" +
		"! withheld (values not returned): secret\n"
	if b.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}
