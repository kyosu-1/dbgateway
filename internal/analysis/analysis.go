// Package analysis defines the database-independent result of analyzing a
// SQL statement, plus the Adapter interface each database implements.
//
// Policy, masking and audit only ever see these types; everything specific
// to a database dialect stays inside its adapter.
package analysis

import (
	"errors"
	"fmt"
)

// StmtKind is the coarse statement type.
type StmtKind string

const (
	KindSelect   StmtKind = "select"
	KindInsert   StmtKind = "insert"
	KindUpdate   StmtKind = "update"
	KindDelete   StmtKind = "delete"
	KindMerge    StmtKind = "merge"
	KindTruncate StmtKind = "truncate"
	KindDDL      StmtKind = "ddl"
	KindOther    StmtKind = "other"
)

// Usage describes where a column is referenced.
type Usage string

const (
	UsageOutput Usage = "output" // in the result (select list, RETURNING)
	UsageFilter Usage = "filter" // WHERE, HAVING, JOIN ON/USING, aggregate FILTER
	UsageGroup  Usage = "group"  // GROUP BY, DISTINCT ON, window PARTITION BY
	UsageOrder  Usage = "order"  // ORDER BY, window/aggregate ORDER BY
	UsageWrite  Usage = "write"  // assigned by INSERT/UPDATE/MERGE
	UsageOther  Usage = "other"  // anything else (LIMIT expressions, function args in FROM, ...)
)

// QueryAnalysis is the result of Analyze. Multiple statements are rejected
// at parse time, so it always holds exactly one statement.
type QueryAnalysis struct {
	Statement Statement
	// Output describes each result column in order, with its lineage.
	// Only set for statements that return rows.
	Output []OutputColumn
	// Normalized is the SQL with literal values replaced by placeholders,
	// safe to log and to show in notifications.
	Normalized string
}

// Statement is the database-independent description of one statement.
type Statement struct {
	Kind      StmtKind
	IsWrite   bool        // INSERT/UPDATE/DELETE/MERGE/TRUNCATE, or a CTE containing one
	Tables    []TableRef  // schema-qualified; read vs written is distinguished
	Columns   []ColumnRef // every referenced base column (output, filters, joins, ...)
	HasWhere  bool        // UPDATE/DELETE has a WHERE clause
	Functions []string    // called functions, schema-qualified where known
	Unknown   bool        // some part could not be fully analyzed; never auto-allow
	// UnknownReasons explains why Unknown is set.
	UnknownReasons []string
}

// TableRef is a referenced relation.
type TableRef struct {
	Schema string
	Name   string
	Read   bool
	Write  bool
}

// FQN returns schema.name.
func (t TableRef) FQN() string { return t.Schema + "." + t.Name }

// ColumnRef is a referenced base-table column. Columns read through views,
// subqueries and CTEs are resolved down to base tables.
type ColumnRef struct {
	Schema string
	Table  string
	Column string
	Usages []Usage
}

// FQN returns schema.table.column.
func (c ColumnRef) FQN() string { return c.Schema + "." + c.Table + "." + c.Column }

// OutputColumn describes one result column.
type OutputColumn struct {
	Name string
	// Sources are the base columns the value is derived from.
	Sources []ColumnID
	// Direct is true when the value is exactly one base column, unmodified
	// (so a format-preserving masking method can be applied).
	Direct bool
	// Unknown is true when lineage could not be determined. Results with an
	// unknown output column must not be returned.
	Unknown bool
}

// ColumnID identifies a base-table column.
type ColumnID struct {
	Schema string
	Table  string
	Column string
}

// FQN returns schema.table.column.
func (c ColumnID) FQN() string { return c.Schema + "." + c.Table + "." + c.Column }

// Stage identifies where a request was rejected.
type Stage string

const (
	StageParse  Stage = "parse"
	StageRole   Stage = "role"
	StagePolicy Stage = "policy"
)

// Rejection is returned by Analyze when a statement must be refused
// regardless of configuration. It carries an AI-friendly reason and hint.
type Rejection struct {
	Code   string // stable machine-readable code, e.g. "multiple_statements"
	Reason string // why it was rejected
	Hint   string // how to get the query through
}

func (r *Rejection) Error() string { return fmt.Sprintf("%s: %s", r.Code, r.Reason) }

// Reject constructs a *Rejection.
func Reject(code, reason, hint string) *Rejection {
	return &Rejection{Code: code, Reason: reason, Hint: hint}
}

// AsRejection unwraps a *Rejection from err.
func AsRejection(err error) (*Rejection, bool) {
	var r *Rejection
	ok := errors.As(err, &r)
	return r, ok
}
