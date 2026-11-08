package postgres

import (
	"context"
	"fmt"
	"strings"

	pg "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/kyosu-1/dbgateway/internal/analysis"
)

// Analyzer converts PostgreSQL SQL into analysis.QueryAnalysis.
//
// It follows two rules from the design: fail closed (anything that cannot
// be parsed or classified is rejected) and lean towards danger when unsure
// (Statement.Unknown is set so the statement is never auto-allowed).
type Analyzer struct {
	funcs *FunctionAllowlist
}

// NewAnalyzer returns an analyzer using the given function allowlist.
func NewAnalyzer(funcs *FunctionAllowlist) *Analyzer {
	return &Analyzer{funcs: funcs}
}

// Analyze parses and analyzes a single SQL statement.
func (a *Analyzer) Analyze(_ context.Context, sql string, cat *analysis.Catalog) (*analysis.QueryAnalysis, error) {
	if strings.TrimSpace(sql) == "" {
		return nil, analysis.Reject("empty", "The SQL is empty.", "Specify exactly one SQL statement to run.")
	}
	tree, err := pg.Parse(sql)
	if err != nil {
		return nil, analysis.Reject("parse_error",
			fmt.Sprintf("Could not parse the SQL (%s). SQL that cannot be parsed is not run, for safety.", err.Error()),
			"Check that it is valid PostgreSQL syntax and send a single statement.")
	}
	switch len(tree.Stmts) {
	case 0:
		return nil, analysis.Reject("empty", "The SQL contains no statement.", "Specify exactly one SQL statement to run.")
	case 1:
	default:
		return nil, analysis.Reject("multiple_statements",
			fmt.Sprintf("The SQL contains %d statements. Multiple statements cannot be sent together.", len(tree.Stmts)),
			"Send exactly one statement per call; do not separate statements with semicolons.")
	}
	stmt := tree.Stmts[0].Stmt
	if stmt == nil || stmt.Node == nil {
		return nil, analysis.Reject("empty", "The SQL contains no statement.", "Specify exactly one SQL statement to run.")
	}

	qa := &analysis.QueryAnalysis{Normalized: normalize(sql)}
	st := &qa.Statement
	kind, rej := classify(stmt)
	if rej != nil {
		return nil, rej
	}
	st.Kind = kind
	switch kind {
	case analysis.KindInsert, analysis.KindUpdate, analysis.KindDelete, analysis.KindMerge, analysis.KindTruncate:
		st.IsWrite = true
	}
	if kind == analysis.KindDDL {
		// DDL is never executed through dbgateway; the policy decides how
		// to explain the denial. No deeper analysis is needed.
		return qa, nil
	}

	// Pass 1: safety scan over the whole tree (forbidden constructs,
	// function allowlist, nested data-modifying statements).
	if rej := a.scan(stmt, st); rej != nil {
		return nil, rej
	}

	// Pass 2: name resolution and column lineage.
	r := newResolver(cat)
	switch n := stmt.Node.(type) {
	case *pg.Node_SelectStmt:
		qa.Output = r.selectStmt(n.SelectStmt, nil, analysis.UsageOutput)
	case *pg.Node_InsertStmt:
		qa.Output = r.insertStmt(n.InsertStmt, nil)
	case *pg.Node_UpdateStmt:
		qa.Output = r.updateStmt(n.UpdateStmt, nil)
		st.HasWhere = n.UpdateStmt.WhereClause != nil
	case *pg.Node_DeleteStmt:
		qa.Output = r.deleteStmt(n.DeleteStmt, nil)
		st.HasWhere = n.DeleteStmt.WhereClause != nil
	case *pg.Node_MergeStmt:
		qa.Output = r.mergeStmt(n.MergeStmt, nil)
		st.HasWhere = n.MergeStmt.JoinCondition != nil
	case *pg.Node_TruncateStmt:
		for _, rel := range n.TruncateStmt.Relations {
			if rv := rel.GetRangeVar(); rv != nil {
				r.recordTable(rv, false, true)
			}
		}
	}
	r.finish(st)
	if r.isWrite {
		st.IsWrite = true
	}
	return qa, nil
}

// classify maps the top-level node to a statement kind, rejecting
// statements that are never allowed.
func classify(n *pg.Node) (analysis.StmtKind, *analysis.Rejection) {
	switch x := n.Node.(type) {
	case *pg.Node_SelectStmt:
		return analysis.KindSelect, nil
	case *pg.Node_InsertStmt:
		return analysis.KindInsert, nil
	case *pg.Node_UpdateStmt:
		return analysis.KindUpdate, nil
	case *pg.Node_DeleteStmt:
		return analysis.KindDelete, nil
	case *pg.Node_MergeStmt:
		return analysis.KindMerge, nil
	case *pg.Node_TruncateStmt:
		return analysis.KindTruncate, nil
	case *pg.Node_TransactionStmt:
		return "", analysis.Reject("transaction_control",
			"Transaction control (BEGIN / COMMIT / ROLLBACK, etc.) is not allowed.",
			"dbgateway manages transactions. Send only the SQL statement itself.")
	case *pg.Node_VariableSetStmt, *pg.Node_AlterSystemStmt:
		return "", analysis.Reject("set",
			"Session settings (SET / RESET / SET ROLE, etc.) cannot be changed.",
			"dbgateway fixes the session settings. Send only the SQL statement itself, without changing settings.")
	case *pg.Node_VariableShowStmt:
		return "", analysis.Reject("show", "SHOW is not allowed.", "If you need a setting's value, ask an administrator.")
	case *pg.Node_DoStmt:
		return "", analysis.Reject("do_block", "DO blocks are not allowed.", "Do not use procedural code; express it as a single SELECT statement.")
	case *pg.Node_CopyStmt:
		return "", analysis.Reject("copy", "COPY is not allowed (this prevents access to files and programs on the server).", "Fetch only the rows you need with a SELECT statement.")
	case *pg.Node_ExplainStmt:
		if explainHasAnalyze(x.ExplainStmt) {
			return "", analysis.Reject("explain_analyze", "EXPLAIN ANALYZE is not allowed because it actually runs the statement.", "Remove ANALYZE, or send the SELECT statement itself.")
		}
		return "", analysis.Reject("explain", "EXPLAIN cannot be run with execute_sql.", "Send the SELECT statement itself; dbgateway checks the estimated rows automatically.")
	case *pg.Node_CallStmt:
		return "", analysis.Reject("call", "CALL (calling a procedure) is not allowed.", "Fetch the data you need with a SELECT statement.")
	case *pg.Node_LockStmt:
		return "", analysis.Reject("lock", "LOCK is not allowed.", "Send a SELECT statement without taking locks.")
	case *pg.Node_NotifyStmt, *pg.Node_ListenStmt, *pg.Node_UnlistenStmt:
		return "", analysis.Reject("notify", "NOTIFY / LISTEN / UNLISTEN is not allowed.", "Notifications are not available.")
	case *pg.Node_PrepareStmt, *pg.Node_ExecuteStmt, *pg.Node_DeallocateStmt:
		return "", analysis.Reject("prepare", "PREPARE / EXECUTE / DEALLOCATE is not allowed.", "Send the SQL statement itself directly.")
	case *pg.Node_DeclareCursorStmt, *pg.Node_FetchStmt, *pg.Node_ClosePortalStmt:
		return "", analysis.Reject("cursor", "Cursor operations are not allowed.", "Send the SELECT statement directly; dbgateway applies the row limit.")
	case *pg.Node_DiscardStmt, *pg.Node_LoadStmt, *pg.Node_CheckPointStmt:
		return "", analysis.Reject("utility", "This kind of utility statement is not allowed.", "Send a SELECT statement.")
	}
	if isDDL(n) {
		return analysis.KindDDL, nil
	}
	return "", analysis.Reject("unsupported_statement",
		fmt.Sprintf("This kind of statement (%s) cannot be evaluated, so it is not run.", nodeName(n)),
		"Express it as a SELECT statement.")
}

func explainHasAnalyze(e *pg.ExplainStmt) bool {
	for _, o := range e.Options {
		if d := o.GetDefElem(); d != nil && strings.EqualFold(d.Defname, "analyze") {
			if d.Arg == nil {
				return true
			}
			// EXPLAIN (ANALYZE false) is harmless, but keep it simple and
			// treat any explicit value other than false/off/0 as analyze.
			v := strings.ToLower(defElemString(d.Arg))
			return v != "false" && v != "off" && v != "0"
		}
	}
	return false
}

func defElemString(n *pg.Node) string {
	switch {
	case n.GetString_() != nil:
		return n.GetString_().Sval
	case n.GetBoolean() != nil:
		if n.GetBoolean().Boolval {
			return "true"
		}
		return "false"
	case n.GetInteger() != nil:
		return fmt.Sprint(n.GetInteger().Ival)
	case n.GetAConst() != nil:
		c := n.GetAConst()
		if c.GetBoolval() != nil {
			if c.GetBoolval().Boolval {
				return "true"
			}
			return "false"
		}
		if c.GetSval() != nil {
			return c.GetSval().Sval
		}
		if c.GetIval() != nil {
			return fmt.Sprint(c.GetIval().Ival)
		}
	}
	return "true"
}

var ddlNames = map[string]bool{
	"GrantStmt": true, "GrantRoleStmt": true, "RenameStmt": true, "CommentStmt": true,
	"IndexStmt": true, "ViewStmt": true, "RuleStmt": true, "ReindexStmt": true,
	"ClusterStmt": true, "VacuumStmt": true, "RefreshMatViewStmt": true, "SecLabelStmt": true,
	"DefineStmt": true, "CompositeTypeStmt": true, "ReassignOwnedStmt": true, "DropOwnedStmt": true,
	"ImportForeignSchemaStmt": true, "AlterDefaultPrivilegesStmt": true,
}

func isDDL(n *pg.Node) bool {
	name := nodeName(n)
	return strings.HasPrefix(name, "Create") || strings.HasPrefix(name, "Alter") ||
		strings.HasPrefix(name, "Drop") || ddlNames[name]
}

// nodeName returns the protobuf message name of the node's concrete value.
func nodeName(n *pg.Node) string {
	if m := nodeMessage(n); m != nil {
		return string(m.ProtoReflect().Descriptor().Name())
	}
	return "unknown"
}

// nodeMessage returns the concrete message wrapped by a Node.
func nodeMessage(n *pg.Node) proto.Message {
	if n == nil {
		return nil
	}
	var out proto.Message
	n.ProtoReflect().Range(func(_ protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		out = v.Message().Interface()
		return false
	})
	return out
}

// walk visits every message in the tree rooted at m in depth-first order.
// visit returns false to skip the children of a message.
func walk(m proto.Message, visit func(proto.Message) bool) {
	if m == nil {
		return
	}
	rm := m.ProtoReflect()
	if !rm.IsValid() {
		return
	}
	if !visit(m) {
		return
	}
	rm.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList() && fd.Message() != nil:
			l := v.List()
			for i := 0; i < l.Len(); i++ {
				walk(l.Get(i).Message().Interface(), visit)
			}
		case fd.Message() != nil && !fd.IsMap():
			walk(v.Message().Interface(), visit)
		}
		return true
	})
}

func normalize(sql string) string {
	out, err := pg.Normalize(sql)
	if err != nil {
		return ""
	}
	return out
}

// Normalize replaces literal values in sql with placeholders. It returns an
// empty string when the SQL cannot be parsed.
func (a *Analyzer) Normalize(sql string) string { return normalize(sql) }
