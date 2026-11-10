package gateway_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/gateway/gatewaytest"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

const docsYAML = `
auth: { dev_login: true }
databases:
  - name: prod
    labels: { env: prod }
    primary: { host: localhost, read_user: r, sslmode: disable }
    docs:
      description: "  Core OLTP database. Amounts are in JPY.  "
      tables:
        PUBLIC.Users:
          description: One row per account.
          columns:
            Email: Login e-mail address.
            plan: free, pro or enterprise.
        public.orders:
          description: One row per checkout.
      examples:
        - title: Accounts per plan
          description: Counts every account.
          sql: SELECT plan, count(*) FROM users GROUP BY plan
        - title: Orders per account
          sql: SELECT u.id, count(o.id) FROM public.users u JOIN orders o ON o.user_id = u.id GROUP BY u.id
        - title: Order count
          sql: SELECT count(*) FROM orders
        - title: Broken
          sql: SELECT * FROM no_such_table
  - name: other
    primary: { host: localhost, read_user: r, sslmode: disable }
groups:
  - { name: dev, members: [taro@example.com] }
  - { name: ops, members: [jiro@example.com] }
  - { name: schema, members: [saburo@example.com] }
role_bindings:
  - { group: dev, databases: "*", roles: [querier] }
  - { group: ops, databases: [prod], roles: [approver] }
  - { group: schema, databases: [prod], roles: [viewer] }
data_classes:
  - { columns: [public.users.email], class: masked }
  - { column_pattern: "public\\.users\\.(id|plan|name)", class: public }
`

func docsGateway(t *testing.T) *gateway.Gateway {
	t.Helper()
	gw, fa, _, _ := newUnitGateway(t, docsYAML)
	fa.Set(func(a *gatewaytest.Adapter) {
		a.Tables["public.orders"] = []string{"id", "user_id", "total_amount"}
	})
	return gw
}

func TestListDatabasesDescription(t *testing.T) {
	gw := docsGateway(t)
	desc := func(p *identity.Principal) map[string]string {
		out := map[string]string{}
		for _, d := range gw.ListDatabases(p) {
			out[d.Name] = d.Description
		}
		return out
	}
	if got := desc(taro); got["prod"] != "Core OLTP database. Amounts are in JPY." || got["other"] != "" {
		t.Fatalf("querier: %v", got)
	}
	saburo := &identity.Principal{Kind: identity.KindHuman, Human: "saburo@example.com", Groups: []string{"schema"}}
	if got := desc(saburo); got["prod"] == "" {
		t.Fatalf("viewer sees the schema, so the docs too: %v", got)
	}
	// A role without schema access sees the database but not its docs.
	jiro := &identity.Principal{Kind: identity.KindHuman, Human: "jiro@example.com", Groups: []string{"ops"}}
	if got := desc(jiro); len(got) != 1 || got["prod"] != "" {
		t.Fatalf("approver only: %v", got)
	}
	// Agents restricted to another database do not see it at all.
	agent := &identity.Principal{Kind: identity.KindAgent, Human: "taro@example.com", Agent: "claude", Groups: []string{"dev"},
		Scopes: []string{identity.ScopeRead}, Databases: []string{"other"}}
	if got := desc(agent); len(got) != 1 || got["other"] != "" {
		t.Fatalf("agent scoped to other: %v", got)
	}
}

func TestSearchObjectsDocs(t *testing.T) {
	gw := docsGateway(t)
	ctx := context.Background()
	agent := &identity.Principal{Kind: identity.KindAgent, Human: "taro@example.com", Agent: "claude", Groups: []string{"dev"},
		Scopes: []string{identity.ScopeRead}}

	resp, err := gw.SearchObjects(ctx, agent, gateway.SearchRequest{Database: "prod", Keyword: "users"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Objects) != 1 {
		t.Fatalf("objects = %+v", resp.Objects)
	}
	users := resp.Objects[0]
	if users.Description != "One row per account." || users.Comment != "" {
		t.Fatalf("users = %+v", users)
	}
	cols := map[string]analysis.ObjectColumn{}
	for _, c := range users.Columns {
		cols[c.Name] = c
	}
	// A description does not change masking: email stays masked for agents.
	if c := cols["email"]; c.Description != "Login e-mail address." || !c.Masked || c.Class != "masked" {
		t.Fatalf("email = %+v", c)
	}
	if cols["plan"].Description != "free, pro or enterprise." || cols["id"].Description != "" {
		t.Fatalf("columns = %+v", cols)
	}
	if got := titles(resp.Examples); !slices.Equal(got, []string{"Accounts per plan", "Orders per account"}) {
		t.Fatalf("examples for users = %v", got)
	}
	ex := resp.Examples[1]
	if !slices.Equal(ex.Tables, []string{"public.users", "public.orders"}) || ex.SQL == "" {
		t.Fatalf("example = %+v", ex)
	}
	if resp.Examples[0].Description != "Counts every account." {
		t.Fatalf("example description = %+v", resp.Examples[0])
	}

	// Everything: every example that references a listed table; the one
	// that cannot be analyzed is never shown.
	resp, err = gw.SearchObjects(ctx, agent, gateway.SearchRequest{Database: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if got := titles(resp.Examples); !slices.Equal(got, []string{"Accounts per plan", "Orders per account", "Order count"}) {
		t.Fatalf("all examples = %v", got)
	}
	for _, o := range resp.Objects {
		if o.Name == "orders" && o.Description != "One row per checkout." {
			t.Fatalf("orders = %+v", o)
		}
	}

	// Names only: no descriptions, no examples.
	resp, err = gw.SearchObjects(ctx, agent, gateway.SearchRequest{Database: "prod", Detail: "names"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Examples != nil || resp.Objects[0].Description != "" {
		t.Fatalf("names: %+v", resp)
	}

	// No docs on the other database.
	resp, err = gw.SearchObjects(ctx, agent, gateway.SearchRequest{Database: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Examples != nil || resp.Objects[0].Description != "" {
		t.Fatalf("other: %+v", resp)
	}
}

// Without search access the docs are refused exactly like an unknown
// database.
func TestSearchObjectsDocsNeedAccess(t *testing.T) {
	gw := docsGateway(t)
	ctx := context.Background()
	jiro := &identity.Principal{Kind: identity.KindHuman, Human: "jiro@example.com", Groups: []string{"ops"}}
	scoped := &identity.Principal{Kind: identity.KindAgent, Human: "taro@example.com", Agent: "claude", Groups: []string{"dev"},
		Scopes: []string{identity.ScopeRead}, Databases: []string{"other"}}
	for _, p := range []*identity.Principal{jiro, scoped} {
		resp, err := gw.SearchObjects(ctx, p, gateway.SearchRequest{Database: "prod"})
		if !errors.Is(err, gateway.ErrNoAccess) || resp != nil {
			t.Fatalf("%s: %v %+v", p.Human, err, resp)
		}
	}
	_, unknown := gw.SearchObjects(ctx, jiro, gateway.SearchRequest{Database: "nope"})
	if unknown == nil || unknown.Error() != gateway.ErrNoAccess.Error() {
		t.Fatalf("unknown database: %v", unknown)
	}
}

func titles(exs []gateway.Example) []string {
	var out []string
	for _, e := range exs {
		out = append(out, e.Title)
	}
	return out
}
