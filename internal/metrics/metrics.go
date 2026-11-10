// Package metrics exposes operational metrics in the Prometheus text
// format. It is fed through small hooks of the core packages (the gateway's
// Observer, the events Publisher, the audit logger's error observer) and
// scrape-time snapshots (connection pools, notification and audit
// forwarding counters), so that the core packages do not depend on
// Prometheus.
//
// Every label has a small, fixed set of values: configured database names,
// principal kinds, decisions, stages, event types and statuses. Identities,
// SQL, table names and request IDs never become labels.
package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/notify"
)

const namespace = "dbgateway"

// other replaces a label value outside the expected set.
const other = "other"

// Options configures Metrics.
type Options struct {
	Config *config.Config // required
	// Version is the dbgateway version, reported in dbgateway_build_info.
	Version string
}

// Metrics holds a dedicated registry (not the global default one) and the
// collectors of dbgateway.
type Metrics struct {
	reg       *prometheus.Registry
	databases map[string]bool

	requests        *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	rowsReturned    *prometheus.HistogramVec
	approvals       *prometheus.CounterVec
	events          *prometheus.CounterVec
	auditFailures   prometheus.Counter
	catalogLoads    *prometheus.CounterVec
	catalogDuration *prometheus.HistogramVec
}

var (
	_ gateway.Observer = (*Metrics)(nil)
	_ events.Publisher = (*Metrics)(nil)
)

// New creates the registry with the Go runtime and process collectors and
// the dbgateway metrics.
func New(opts Options) *Metrics {
	m := &Metrics{reg: prometheus.NewRegistry(), databases: map[string]bool{}}
	for _, db := range opts.Config.Databases {
		m.databases[db.Name] = true
	}
	m.reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	version := opts.Version
	if version == "" {
		version = "dev"
	}
	buildInfo := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace, Name: "build_info",
		Help:        "Always 1; the labels carry the dbgateway version and the loaded configuration version.",
		ConstLabels: prometheus.Labels{"version": version, "config_version": opts.Config.Version},
	})
	buildInfo.Set(1)

	m.requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "requests_total",
		Help: "Finished execute_sql, export, search_objects and explain_policy requests.",
	}, []string{"event", "database", "kind", "decision", "stage"})
	m.requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Name: "request_duration_seconds",
		Help:    "Time to handle a request, including analysis, the database and the audit write.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
	}, []string{"event", "database", "decision"})
	m.rowsReturned = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Name: "rows_returned",
		Help:    "Rows returned by allowed reads (execute_sql and exports).",
		Buckets: []float64{0, 1, 10, 100, 1000, 10000, 100000},
	}, []string{"database", "kind"})
	m.approvals = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "approval_transitions_total",
		Help: "Approval request state changes: submitted, step_approved, approved, rejected, canceled, expired, succeeded, failed.",
	}, []string{"database", "status"})
	m.events = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "events_total",
		Help: "Operational events emitted (the events that notifications can route).",
	}, []string{"type"})
	m.auditFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace, Name: "audit_write_failures_total",
		Help: "Audit entries that could not be written to the primary output (the request failed closed).",
	})
	m.catalogLoads = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "catalog_loads_total",
		Help: "Catalog (schema) loads from the databases, by result (ok or error).",
	}, []string{"database", "result"})
	m.catalogDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Name: "catalog_load_duration_seconds",
		Help:    "Time to load a database's catalog.",
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
	}, []string{"database"})

	m.reg.MustRegister(buildInfo, m.requests, m.requestDuration, m.rowsReturned, m.approvals, m.events,
		m.auditFailures, m.catalogLoads, m.catalogDuration)
	return m
}

// Gatherer returns the registry (for tests and embedding programs).
func (m *Metrics) Gatherer() prometheus.Gatherer { return m.reg }

// Handler serves the metrics in the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})
}

// database returns name if it is a configured database, else "" (never a
// name made up by a caller).
func (m *Metrics) database(name string) string {
	if m.databases[name] {
		return name
	}
	return ""
}

// oneOf returns v if it is one of allowed, else "other".
func oneOf(v string, allowed ...string) string {
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return other
}

// ObserveRequest implements gateway.Observer.
func (m *Metrics) ObserveRequest(o gateway.RequestObservation) {
	db := m.database(o.Database)
	event := oneOf(o.Event, "query", "export", "search", "explain")
	decision := oneOf(o.Decision, config.ActionAllow, config.ActionDeny, config.ActionApprove, gateway.DecisionError)
	kind := oneOf(string(o.Kind), "human", "agent")
	stage := oneOf(o.Stage, "", "parse", "role", "policy")
	m.requests.WithLabelValues(event, db, kind, decision, stage).Inc()
	m.requestDuration.WithLabelValues(event, db, decision).Observe(o.Duration.Seconds())
	if o.Rows >= 0 {
		m.rowsReturned.WithLabelValues(db, kind).Observe(float64(o.Rows))
	}
}

// ObserveCatalogLoad implements gateway.Observer.
func (m *Metrics) ObserveCatalogLoad(database string, d time.Duration, err error) {
	db := m.database(database)
	result := "ok"
	if err != nil {
		result = "error"
	}
	m.catalogLoads.WithLabelValues(db, result).Inc()
	m.catalogDuration.WithLabelValues(db).Observe(d.Seconds())
}

// Publish implements events.Publisher: it counts events and approval state
// changes. It never blocks.
func (m *Metrics) Publish(_ context.Context, e events.Event) {
	m.events.WithLabelValues(oneOf(string(e.Type), string(events.ApprovalRequested), string(events.ApprovalDecided),
		string(events.ExecutionFinished), string(events.QueryDenied), string(events.BreakGlassUsed),
		string(events.AnomalyDetected), string(events.ConfigChanged))).Inc()
	var status string
	switch e.Type {
	case events.ApprovalRequested:
		status = "submitted"
	case events.ApprovalDecided:
		status = e.Status
		if status == "pending" { // one step of several approved
			status = "step_approved"
		}
		status = oneOf(status, "step_approved", "approved", "rejected", "canceled", "expired")
	case events.ExecutionFinished:
		status = oneOf(e.Status, "succeeded", "failed")
	default:
		return
	}
	m.approvals.WithLabelValues(m.database(e.Database), status).Inc()
}

// AuditWriteFailed counts an audit entry that could not be written; pass it
// to audit.Logger.SetErrorObserver.
func (m *Metrics) AuditWriteFailed(error) { m.auditFailures.Inc() }

// WatchPools exports the connection pool statistics returned by f at each
// scrape.
func (m *Metrics) WatchPools(f func() []gateway.PoolStats) {
	m.reg.MustRegister(&poolCollector{stats: f})
}

// WatchNotifications exports the notification delivery counters returned
// by f at each scrape.
func (m *Metrics) WatchNotifications(f func() notify.Stats) {
	m.reg.MustRegister(&notifyCollector{stats: f})
}

// WatchAuditForwarders exports the audit forwarding counters (e.g. OTLP)
// returned by f at each scrape.
func (m *Metrics) WatchAuditForwarders(f func() []audit.ForwarderStats) {
	m.reg.MustRegister(&forwarderCollector{stats: f})
}
