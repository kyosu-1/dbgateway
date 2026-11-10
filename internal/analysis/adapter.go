package analysis

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
)

// Adapter is implemented once per database type. Everything dialect-specific
// lives behind it; adding MySQL means writing a parser translation
// (Analyze), Estimate, Introspect, Catalog and Execute.
type Adapter interface {
	// Connect opens connection pools for a configured database.
	Connect(ctx context.Context, cfg *config.Database) (Conn, error)
	// Catalog loads table, view and column definitions used to resolve
	// names, "*" and views during analysis.
	Catalog(ctx context.Context, c Conn) (*Catalog, error)
	// Analyze parses SQL and converts it to the database-independent form.
	// It returns a *Rejection for statements that are always refused.
	Analyze(ctx context.Context, sql string, cat *Catalog) (*QueryAnalysis, error)
	// Estimate returns the planner's row/cost estimate without executing.
	Estimate(ctx context.Context, c Conn, sql string, opt ExecOptions) (*Estimate, error)
	// Introspect lists schema objects for exploration.
	Introspect(ctx context.Context, c Conn, filter ObjectFilter) ([]Object, error)
	// Execute runs a single statement with the given safety options.
	Execute(ctx context.Context, c Conn, sql string, opt ExecOptions) (*Result, error)
}

// Conn is an open database handle (typically a set of pools).
type Conn interface {
	Close()
}

// ExecOptions carries the safety limits for one execution.
//
// ReadOnly=false selects the write user. Execute then runs the statement
// in a read-write transaction and commits only if at most MaxAffectedRows
// rows were affected; Estimate still plans inside a read-only transaction.
type ExecOptions struct {
	ReadOnly         bool
	Replica          bool // run on the replica when one is configured (reads only)
	MaxRows          int  // rows returned (RETURNING for writes)
	MaxBytes         int64
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	// MaxAffectedRows bounds the rows a write may affect (required, > 0,
	// for writes).
	MaxAffectedRows int64
	// Backup, for writes, saves the rows the statement changes before it
	// runs (see BackupSpec). Execute then fails with a *BackupError unless
	// the backup holds exactly the affected rows.
	Backup *BackupSpec
}

// AffectedRowsError is returned by Execute when a write affected more rows
// than ExecOptions.MaxAffectedRows. The transaction has been rolled back.
type AffectedRowsError struct {
	Affected int64
	Max      int64
}

func (e *AffectedRowsError) Error() string {
	return fmt.Sprintf("the statement affected %d rows, more than the limit of %d; rolled back", e.Affected, e.Max)
}

// Estimate is the planner's estimate.
type Estimate struct {
	Rows float64 `json:"rows"`
	Cost float64 `json:"cost"`
}

// Result is the outcome of Execute. Values are already converted to
// JSON-friendly Go types (string, float64, int64, bool, nil, []any, map).
type Result struct {
	Columns   []ResultColumn
	Rows      [][]any
	RowCount  int   // rows returned
	TotalRows int64 // rows produced by the query; -1 if unknown
	Truncated bool
	Bytes     int64
	Duration  time.Duration
	// RowsAffected is the number of rows a write changed (0 for reads).
	RowsAffected int64
	// Backup is set when ExecOptions.Backup was requested.
	Backup *BackupResult
}

// ResultColumn is the name and database type of a result column.
type ResultColumn struct {
	Name string
	Type string
}

// ObjectFilter narrows Introspect.
type ObjectFilter struct {
	Keyword string // substring match on schema/table/column names
	Schema  string
	Detail  string // "names" | "summary" | "full"
	Limit   int
	// HiddenSchemas are never listed, even when requested (backup schemas).
	HiddenSchemas []string
}

// Object is a schema object returned by Introspect.
type Object struct {
	Type   string `json:"type"` // table | view | materialized_view | foreign_table
	Schema string `json:"schema"`
	Name   string `json:"name"`
	// Comment is the database's own COMMENT (detail "full").
	Comment string `json:"comment,omitempty"`
	// Description is the curated description from the configuration
	// (databases[].docs), filled by the caller. Both are kept.
	Description string         `json:"description,omitempty"`
	Columns     []ObjectColumn `json:"columns,omitempty"`
	Indexes     []ObjectIndex  `json:"indexes,omitempty"`
	// RowEstimate is the planner statistic (reltuples), when known.
	RowEstimate *int64 `json:"row_estimate,omitempty"`
}

// ObjectColumn describes a column in Introspect results.
type ObjectColumn struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
	Comment  string `json:"comment,omitempty"`
	// Description is the curated description from the configuration,
	// filled by the caller.
	Description string `json:"description,omitempty"`
	// Class is filled by the caller from the data classification.
	Class  string `json:"class,omitempty"`
	Masked bool   `json:"masked,omitempty"`
}

// ObjectIndex describes an index.
type ObjectIndex struct {
	Name       string `json:"name"`
	Definition string `json:"definition"`
}

// RelKind is the kind of a relation.
type RelKind string

const (
	RelTable       RelKind = "table"
	RelView        RelKind = "view"
	RelMatView     RelKind = "materialized_view"
	RelForeign     RelKind = "foreign_table"
	RelPartitioned RelKind = "partitioned_table"
)

// Catalog is the subset of schema information needed for analysis.
type Catalog struct {
	// SearchPath is the fixed search path applied to every session.
	SearchPath []string
	// ImplicitSchemas are searched before SearchPath (pg_catalog for PostgreSQL).
	ImplicitSchemas []string
	Relations       map[string]*Relation // key: lower-case "schema.name"
	LoadedAt        time.Time
}

// Relation is a table, view, etc.
type Relation struct {
	Schema  string
	Name    string
	Kind    RelKind
	Columns []Column
	// Definition is the view query for views/materialized views. Empty for
	// system views, which are treated as base relations.
	Definition string
}

// Column is a relation column.
type Column struct {
	Name     string
	Type     string
	Nullable bool
	Comment  string
}

// NewCatalog returns an empty catalog with the given search path.
func NewCatalog(searchPath, implicit []string) *Catalog {
	return &Catalog{SearchPath: searchPath, ImplicitSchemas: implicit, Relations: map[string]*Relation{}, LoadedAt: time.Now()}
}

// Add registers a relation.
func (c *Catalog) Add(r *Relation) {
	c.Relations[strings.ToLower(r.Schema+"."+r.Name)] = r
}

// Lookup resolves a possibly unqualified relation name the same way the
// database would with the fixed search path.
func (c *Catalog) Lookup(schema, name string) *Relation {
	if schema != "" {
		return c.Relations[strings.ToLower(schema+"."+name)]
	}
	for _, s := range c.ImplicitSchemas {
		if r := c.Relations[strings.ToLower(s+"."+name)]; r != nil {
			return r
		}
	}
	for _, s := range c.SearchPath {
		if r := c.Relations[strings.ToLower(s+"."+name)]; r != nil {
			return r
		}
	}
	return nil
}

// Column returns the named column of r, or nil.
func (r *Relation) Column(name string) *Column {
	for i := range r.Columns {
		if r.Columns[i].Name == name {
			return &r.Columns[i]
		}
	}
	return nil
}

// PoolStats is a snapshot of one connection pool, for metrics.
type PoolStats struct {
	// Pool is read, replica or write.
	Pool string
	// Open is the number of open connections (in use and idle); InUse and
	// Idle split it. Max is the configured maximum (0 when unlimited).
	Open, InUse, Idle, Max int64
	// WaitCount is the number of acquisitions that had to wait for a
	// connection, and WaitDuration their total waiting time (cumulative).
	WaitCount    int64
	WaitDuration time.Duration
}

// PoolStatser is optionally implemented by a Conn to report its pools.
type PoolStatser interface {
	PoolStats() []PoolStats
}
