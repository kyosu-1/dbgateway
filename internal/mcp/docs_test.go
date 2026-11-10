package mcp

import (
	"context"
	"errors"
	"testing"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/gateway/gatewaytest"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

const docsYAML = `
auth: { dev_login: true }
databases:
  - name: db
    labels: { env: prod }
    primary: { host: localhost, read_user: r, sslmode: disable }
    docs:
      description: Accounts of the shop.
      tables:
        public.users:
          description: One row per account.
          columns: { email: Login e-mail. }
      examples:
        - { title: Accounts per plan, sql: "SELECT plan, count(*) FROM users GROUP BY plan" }
  - name: other
    primary: { host: localhost, read_user: r, sslmode: disable }
    docs: { description: Not for this agent. }
groups:
  - { name: dev, members: [taro@example.com] }
role_bindings:
  - { group: dev, databases: "*", roles: [querier] }
data_classes:
  - { columns: [public.users.email], class: masked }
`

// The docs reach agents through list_databases and search_objects, only
// for the databases they may search, without changing masking.
func TestToolsReturnDocs(t *testing.T) {
	cfg, err := config.Parse([]byte(docsYAML))
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
	defer al.Close()
	gw, err := gateway.New(gateway.Options{Config: cfg, Adapters: map[string]analysis.Adapter{"postgres": gatewaytest.New()}, Audit: al})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	agent := &identity.Principal{Kind: identity.KindAgent, Human: "taro@example.com", Agent: "claude", Groups: []string{"dev"},
		Scopes: []string{identity.ScopeRead}, Databases: []string{"db"}}
	h := &handlers{gw: gw, principal: func(*mcpauth.TokenInfo) *identity.Principal { return agent }}
	req := &mcp.CallToolRequest{Extra: &mcp.RequestExtra{TokenInfo: &mcpauth.TokenInfo{}}}
	ctx := context.Background()

	_, dbs, err := h.listDatabases(ctx, req, ListDatabasesInput{})
	if err != nil || len(dbs.Databases) != 1 || dbs.Databases[0].Description != "Accounts of the shop." {
		t.Fatalf("list_databases: %v %+v", err, dbs)
	}
	_, sr, err := h.searchObjects(ctx, req, SearchObjectsInput{Database: "db", Keyword: "users"})
	if err != nil || len(sr.Objects) != 1 || sr.Objects[0].Description != "One row per account." {
		t.Fatalf("search_objects: %v %+v", err, sr)
	}
	for _, c := range sr.Objects[0].Columns {
		if c.Name == "email" && (c.Description != "Login e-mail." || !c.Masked) {
			t.Errorf("email = %+v", c)
		}
	}
	if len(sr.Examples) != 1 || sr.Examples[0].Title != "Accounts per plan" {
		t.Fatalf("examples = %+v", sr.Examples)
	}
	// The agent is limited to "db": "other" and its docs look exactly
	// like a database that does not exist.
	_, _, errOther := h.searchObjects(ctx, req, SearchObjectsInput{Database: "other"})
	_, _, errNope := h.searchObjects(ctx, req, SearchObjectsInput{Database: "nope"})
	if !errors.Is(errOther, gateway.ErrNoAccess) || !errors.Is(errNope, gateway.ErrNoAccess) {
		t.Fatalf("other: %v, nope: %v", errOther, errNope)
	}
}
