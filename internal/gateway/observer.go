package gateway

import (
	"errors"
	"time"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

// Observer receives measurements for operational metrics. Calls are made
// on the request path, so implementations must be fast and must not block.
//
// Observations only carry low-cardinality values: a configured database
// name (empty when the caller named a database that does not exist), the
// principal kind, the decision and the stage. Never identities, SQL, table
// names or request IDs.
type Observer interface {
	// ObserveRequest reports a finished execute_sql, export, search_objects
	// or explain_policy request.
	ObserveRequest(RequestObservation)
	// ObserveCatalogLoad reports a (re)load of a database's catalog.
	ObserveCatalogLoad(database string, d time.Duration, err error)
}

// RequestObservation describes one finished request.
type RequestObservation struct {
	// Event is query, export, search or explain.
	Event string
	// Database is the configured database name, or empty when the request
	// named a database that does not exist.
	Database string
	Kind     identity.Kind
	// Decision is allow, deny, approve or error. Error means the caller got
	// an error: the database was unavailable, the execution failed, or the
	// audit log could not be written. For explain it is the decision that
	// explain_policy reported.
	Decision string
	// Stage is the stage that decided (parse, role, policy), when known.
	Stage    string
	Duration time.Duration
	// Rows is the number of rows returned by an allowed read (query or
	// export); -1 otherwise.
	Rows int
}

// DecisionError is the decision of requests that ended in an error.
const DecisionError = "error"

// PoolStats is a snapshot of one connection pool of a database.
type PoolStats struct {
	Database string
	analysis.PoolStats
}

// PoolStats returns the connection pool statistics of every database whose
// connection has been opened and whose adapter reports them.
func (g *Gateway) PoolStats() []PoolStats {
	var out []PoolStats
	for name, d := range g.dbs {
		d.mu.Lock()
		conn := d.conn
		d.mu.Unlock()
		ps, ok := conn.(analysis.PoolStatser)
		if !ok {
			continue
		}
		for _, s := range ps.PoolStats() {
			out = append(out, PoolStats{Database: name, PoolStats: s})
		}
	}
	return out
}

// knownDatabase returns name if it is a configured database, else "", so
// that names made up by callers never become metric labels.
func (g *Gateway) knownDatabase(name string) string {
	if _, ok := g.dbs[name]; ok {
		return name
	}
	return ""
}

// observeExecute reports a finished ExecuteSQL call.
func (g *Gateway) observeExecute(p *identity.Principal, event, database, decision, stage string, out *ExecuteResponse, start time.Time) {
	if g.observer == nil || out == nil {
		return
	}
	o := RequestObservation{Event: event, Database: g.knownDatabase(database), Kind: principalKind(p),
		Decision: decision, Stage: stage, Duration: time.Since(start), Rows: -1}
	switch out.Status {
	case StatusError:
		o.Decision = DecisionError
	case StatusDenied:
		o.Decision = config.ActionDeny
	case StatusPending:
		o.Decision = config.ActionApprove
	case StatusOK:
		if o.Decision == config.ActionAllow {
			o.Rows = out.RowCount
		}
	}
	g.observer.ObserveRequest(o)
}

// observeLookup reports a finished SearchObjects or ExplainPolicy call.
// decision is the decision recorded when err is nil.
func (g *Gateway) observeLookup(p *identity.Principal, event, database, decision, stage string, err error, start time.Time) {
	if g.observer == nil {
		return
	}
	switch {
	case errors.Is(err, ErrNoAccess):
		decision, stage = config.ActionDeny, string(analysis.StageRole)
	case err != nil:
		decision = DecisionError
	}
	g.observer.ObserveRequest(RequestObservation{Event: event, Database: g.knownDatabase(database), Kind: principalKind(p),
		Decision: decision, Stage: stage, Duration: time.Since(start), Rows: -1})
}

func principalKind(p *identity.Principal) identity.Kind {
	if p == nil {
		return ""
	}
	return p.Kind
}
