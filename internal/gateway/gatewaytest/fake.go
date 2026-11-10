// Package gatewaytest provides a fake database adapter for unit tests of
// the gateway and the approval service. It analyzes SQL with the real
// PostgreSQL analyzer but never connects to a database.
package gatewaytest

import (
	"context"
	"strings"
	"sync"

	"github.com/kyosu-1/dbgateway/internal/adapter/postgres"
	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/config"
)

// Exec records one Execute call.
type Exec struct {
	SQL  string
	Opts analysis.ExecOptions
}

// Adapter is a fake analysis.Adapter. Configure the fields before use;
// they are read under the mutex.
type Adapter struct {
	*postgres.Analyzer

	mu sync.Mutex
	// Tables maps "schema.table" to column names for the catalog.
	Tables map[string][]string
	// EstimateRows is returned by Estimate.
	EstimateRows float64
	// EstimateErr makes Estimate fail.
	EstimateErr error
	// Result is returned by Execute (copied; RowsAffected is set from
	// Affected for writes).
	Result analysis.Result
	// Affected is the number of rows a write affects.
	Affected int64
	// ExecErr makes Execute fail.
	ExecErr error
	execs   []Exec
}

var _ analysis.Adapter = (*Adapter)(nil)

// New returns a fake adapter with a users table.
func New() *Adapter {
	return &Adapter{
		Analyzer: postgres.NewAnalyzer(postgres.NewFunctionAllowlist(nil)),
		Tables:   map[string][]string{"public.users": {"id", "name", "email", "plan"}},
		Affected: 1,
	}
}

type conn struct{}

func (conn) Close() {}

// Connect implements analysis.Adapter.
func (a *Adapter) Connect(context.Context, *config.Database) (analysis.Conn, error) {
	return conn{}, nil
}

// Catalog implements analysis.Adapter.
func (a *Adapter) Catalog(context.Context, analysis.Conn) (*analysis.Catalog, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cat := analysis.NewCatalog([]string{"public"}, []string{"pg_catalog"})
	for fqn, cols := range a.Tables {
		schema, name, _ := strings.Cut(fqn, ".")
		r := &analysis.Relation{Schema: schema, Name: name, Kind: analysis.RelTable}
		for _, c := range cols {
			r.Columns = append(r.Columns, analysis.Column{Name: c, Type: "text"})
		}
		cat.Add(r)
	}
	return cat, nil
}

// Estimate implements analysis.Adapter.
func (a *Adapter) Estimate(context.Context, analysis.Conn, string, analysis.ExecOptions) (*analysis.Estimate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.EstimateErr != nil {
		return nil, a.EstimateErr
	}
	return &analysis.Estimate{Rows: a.EstimateRows, Cost: 1}, nil
}

// Introspect implements analysis.Adapter.
func (a *Adapter) Introspect(context.Context, analysis.Conn, analysis.ObjectFilter) ([]analysis.Object, error) {
	return nil, nil
}

// Execute implements analysis.Adapter. Writes are checked against
// MaxAffectedRows like the real adapter (rolled back = nothing recorded
// as committed, but the call is still recorded).
func (a *Adapter) Execute(_ context.Context, _ analysis.Conn, sql string, opt analysis.ExecOptions) (*analysis.Result, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.execs = append(a.execs, Exec{SQL: sql, Opts: opt})
	if a.ExecErr != nil {
		return nil, a.ExecErr
	}
	res := a.Result
	if !opt.ReadOnly {
		res.RowsAffected = a.Affected
		if a.Affected > opt.MaxAffectedRows {
			return nil, &analysis.AffectedRowsError{Affected: a.Affected, Max: opt.MaxAffectedRows}
		}
	}
	res.TotalRows = int64(len(res.Rows))
	if opt.MaxRows > 0 && len(res.Rows) > opt.MaxRows {
		res.Rows, res.Truncated = res.Rows[:opt.MaxRows], true
	}
	res.RowCount = len(res.Rows)
	return &res, nil
}

// Set changes fields under the mutex.
func (a *Adapter) Set(fn func(a *Adapter)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fn(a)
}

// Execs returns the recorded Execute calls.
func (a *Adapter) Execs() []Exec {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Exec(nil), a.execs...)
}

// Writes returns the recorded write executions.
func (a *Adapter) Writes() []Exec {
	var out []Exec
	for _, e := range a.Execs() {
		if !e.Opts.ReadOnly {
			out = append(out, e)
		}
	}
	return out
}
