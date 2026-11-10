package gateway_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/gateway/gatewaytest"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

type observerRecorder struct {
	mu       sync.Mutex
	requests []gateway.RequestObservation
	catalogs []string
}

func (r *observerRecorder) ObserveRequest(o gateway.RequestObservation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, o)
}

func (r *observerRecorder) ObserveCatalogLoad(db string, _ time.Duration, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res := "ok"
	if err != nil {
		res = "error"
	}
	r.catalogs = append(r.catalogs, db+":"+res)
}

func (r *observerRecorder) take() []gateway.RequestObservation {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.requests
	r.requests = nil
	return out
}

type brokenSink struct{}

func (brokenSink) LastHash() (string, error)      { return audit.GenesisHash, nil }
func (brokenSink) Append([]byte, time.Time) error { return errors.New("disk full") }
func (brokenSink) Close() error                   { return nil }

func newObservedGateway(t *testing.T, sink audit.Sink) (*gateway.Gateway, *gatewaytest.Adapter, *observerRecorder) {
	t.Helper()
	cfg, err := config.Parse([]byte(unitYAML))
	if err != nil {
		t.Fatal(err)
	}
	if sink == nil {
		if sink, err = audit.OpenFileSink(t.TempDir(), 0, false, nil); err != nil {
			t.Fatal(err)
		}
	}
	al, err := audit.New(sink)
	if err != nil {
		t.Fatal(err)
	}
	fa := gatewaytest.New()
	obs := &observerRecorder{}
	gw, err := gateway.New(gateway.Options{Config: cfg, Adapters: map[string]analysis.Adapter{"postgres": fa}, Audit: al, Observer: obs})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Close(); _ = al.Close() })
	return gw, fa, obs
}

func TestObserverRequests(t *testing.T) {
	gw, fa, obs := newObservedGateway(t, nil)
	fa.Set(func(a *gatewaytest.Adapter) {
		a.Result = analysis.Result{Columns: []analysis.ResultColumn{{Name: "id", Type: "int8"}},
			Rows: [][]any{{int64(1)}, {int64(2)}, {int64(3)}}, RowCount: 3}
	})
	agent := &identity.Principal{Kind: identity.KindAgent, Human: "taro@example.com", Agent: "claude", Groups: []string{"dev"},
		Scopes: []string{identity.ScopeRead}}
	ctx := context.Background()

	if r := run(gw, agent, "prod", "SELECT id FROM users"); r.Status != gateway.StatusOK {
		t.Fatalf("read: %+v", r)
	}
	run(gw, taro, "prod", "UPDATE users SET plan = 'pro' WHERE id = 1") // no writer role
	run(gw, taro, "does-not-exist", "SELECT 1")                         // unknown database
	run(gw, taro, "prod", "SELECT id FROM users; SELECT 1")             // parse stage
	_, _ = gw.SearchObjects(ctx, taro, gateway.SearchRequest{Database: "prod"})
	_, _ = gw.SearchObjects(ctx, taro, gateway.SearchRequest{Database: "made-up"})
	_, _ = gw.ExplainPolicy(ctx, taro, gateway.ExplainRequest{Database: "prod", SQL: "SELECT id FROM users"})

	got := obs.take()
	want := []gateway.RequestObservation{
		{Event: "query", Database: "prod", Kind: identity.KindAgent, Decision: config.ActionAllow, Stage: "policy", Rows: 3},
		{Event: "query", Database: "prod", Kind: identity.KindHuman, Decision: config.ActionDeny, Stage: "role", Rows: -1},
		{Event: "query", Database: "", Kind: identity.KindHuman, Decision: config.ActionDeny, Stage: "role", Rows: -1},
		{Event: "query", Database: "prod", Kind: identity.KindHuman, Decision: config.ActionDeny, Stage: "parse", Rows: -1},
		{Event: "search", Database: "prod", Kind: identity.KindHuman, Decision: config.ActionAllow, Rows: -1},
		{Event: "search", Database: "", Kind: identity.KindHuman, Decision: config.ActionDeny, Stage: "role", Rows: -1},
		{Event: "explain", Database: "prod", Kind: identity.KindHuman, Decision: config.ActionAllow, Stage: "policy", Rows: -1},
	}
	if len(got) != len(want) {
		t.Fatalf("observations = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		g := got[i]
		if g.Duration < 0 {
			t.Errorf("[%d] duration = %v", i, g.Duration)
		}
		g.Duration = 0
		if g != want[i] {
			t.Errorf("[%d] = %+v, want %+v", i, g, want[i])
		}
	}
	if len(obs.catalogs) == 0 || obs.catalogs[0] != "prod:ok" {
		t.Errorf("catalog loads = %v", obs.catalogs)
	}

	// An allowed read whose execution fails is an error.
	fa.Set(func(a *gatewaytest.Adapter) { a.ExecErr = errors.New("connection reset") })
	run(gw, taro, "prod", "SELECT id FROM users")
	if got := obs.take(); len(got) != 1 || got[0].Decision != gateway.DecisionError || got[0].Rows != -1 {
		t.Fatalf("failed execution: %+v", got)
	}
}

func TestObserverAuditFailure(t *testing.T) {
	gw, _, obs := newObservedGateway(t, brokenSink{})
	if r := run(gw, taro, "prod", "SELECT id FROM users"); r.Status != gateway.StatusError {
		t.Fatalf("audit failure must fail closed: %+v", r)
	}
	if got := obs.take(); len(got) != 1 || got[0].Decision != gateway.DecisionError || got[0].Rows != -1 {
		t.Fatalf("observations: %+v", got)
	}
}
