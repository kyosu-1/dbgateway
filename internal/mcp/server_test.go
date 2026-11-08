package mcp

import (
	"context"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/gateway/gatewaytest"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

type noRequests struct{}

func (noRequests) Get(context.Context, *identity.Principal, string) (*approval.Request, error) {
	return nil, approval.ErrNotFound
}

func tools(t *testing.T, yaml string) map[string]*mcp.Tool {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	gw, err := gateway.New(gateway.Options{Config: cfg, Adapters: map[string]analysis.Adapter{"postgres": gatewaytest.New()}})
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(gw, nil, WithApprovals(noRequests{}))
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*mcp.Tool{}
	for _, tl := range res.Tools {
		out[tl.Name] = tl
	}
	return out
}

const baseYAML = `
auth: { dev_login: true }
databases:
  - name: db
    primary: { host: localhost, read_user: r, write_user: w, sslmode: disable }
`

func TestToolsAndAnnotations(t *testing.T) {
	ro := tools(t, baseYAML)
	if names := keys(ro); !slices.Equal(names, []string{"execute_sql", "explain_policy", "list_databases", "search_objects"}) {
		t.Fatalf("read-only tools = %v", names)
	}
	if !ro["execute_sql"].Annotations.ReadOnlyHint {
		t.Error("read-only execute_sql must be annotated read-only")
	}

	rw := tools(t, baseYAML+"approvals: { enabled: true }\n")
	if names := keys(rw); !slices.Equal(names, []string{"execute_sql", "explain_policy", "get_request", "list_databases", "search_objects"}) {
		t.Fatalf("tools with approvals = %v", names)
	}
	ex := rw["execute_sql"].Annotations
	if ex.ReadOnlyHint || ex.DestructiveHint == nil || !*ex.DestructiveHint {
		t.Errorf("execute_sql annotations with approvals: %+v", ex)
	}
	for _, n := range []string{"explain_policy", "get_request"} {
		if !rw[n].Annotations.ReadOnlyHint {
			t.Errorf("%s must be read-only", n)
		}
	}
}

func keys(m map[string]*mcp.Tool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
