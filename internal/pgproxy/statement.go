package pgproxy

import (
	"strconv"
	"strings"

	pg "github.com/pganalyze/pg_query_go/v6"
)

// stmtKind says who answers a statement: the gateway or the proxy itself.
type stmtKind int

const (
	stmtGateway     stmtKind = iota // analyzed and executed by the gateway
	stmtEmpty                       // only whitespace and comments
	stmtSet                         // SET / RESET
	stmtShow                        // SHOW
	stmtTxn                         // BEGIN / COMMIT / ROLLBACK / ...
	stmtDiscard                     // DISCARD
	stmtDeallocate                  // DEALLOCATE (SQL-level)
	stmtVersion                     // SELECT version()
	stmtConstSelect                 // SELECT 1 (connection checks)
	stmtCopy                        // COPY (unsupported)
)

// statement is one SQL statement with what the proxy learned about it.
// Only local statements keep their parse tree; gateway statements are
// analyzed again by the gateway, which is the only authority on them.
type statement struct {
	sql  string
	kind stmtKind
	node *pg.Node // parse tree of local statements
	// rows is true when the statement is known to return rows without side
	// effects (plain SELECT, SHOW, EXPLAIN). Only such statements are
	// executed early to answer Describe.
	rows bool
	// verb is the command tag verb: SELECT, INSERT, UPDATE, DELETE, MERGE
	// or the leading keywords of other statements (e.g. CREATE TABLE).
	verb string
}

// splitStatements splits a simple-query string into statements using the
// PostgreSQL parser. If the string does not parse, it is returned whole so
// that the gateway reports (and audits) the syntax error.
func splitStatements(sql string) []string {
	parts, err := pg.SplitWithParser(sql, true)
	if err != nil {
		return []string{sql}
	}
	out := parts[:0]
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

// hasParameters reports whether sql contains $n parameter references.
func hasParameters(sql string) bool {
	res, err := pg.Scan(sql)
	if err != nil {
		return strings.Contains(sql, "$") // be conservative
	}
	for _, t := range res.Tokens {
		if t.Token == pg.Token_PARAM {
			return true
		}
	}
	return false
}

// classify parses one statement and decides how to handle it.
func classify(sql string) *statement {
	st := &statement{sql: sql, kind: stmtGateway, verb: leadingKeywords(sql)}
	tree, err := pg.Parse(sql)
	if err != nil {
		return st // the gateway reports the syntax error
	}
	if len(tree.Stmts) == 0 {
		st.kind = stmtEmpty
		return st
	}
	if len(tree.Stmts) > 1 {
		return st // the gateway rejects multiple statements
	}
	node := tree.Stmts[0].Stmt
	switch n := node.Node.(type) {
	case *pg.Node_VariableSetStmt:
		st.kind, st.node = stmtSet, node
	case *pg.Node_VariableShowStmt:
		st.kind, st.node, st.rows = stmtShow, node, true
	case *pg.Node_TransactionStmt:
		st.kind, st.node = stmtTxn, node
	case *pg.Node_DiscardStmt:
		st.kind, st.node = stmtDiscard, node
	case *pg.Node_DeallocateStmt:
		st.kind, st.node = stmtDeallocate, node
	case *pg.Node_CopyStmt:
		st.kind = stmtCopy
	case *pg.Node_ExplainStmt:
		st.rows = true
	case *pg.Node_InsertStmt:
		st.verb = "INSERT"
	case *pg.Node_UpdateStmt:
		st.verb = "UPDATE"
	case *pg.Node_DeleteStmt:
		st.verb = "DELETE"
	case *pg.Node_MergeStmt:
		st.verb = "MERGE"
	case *pg.Node_SelectStmt:
		sel := n.SelectStmt
		st.verb = "SELECT"
		switch {
		case isVersionSelect(sel):
			st.kind, st.node, st.rows = stmtVersion, node, true
		case isConstSelect(sel):
			st.kind, st.node, st.rows = stmtConstSelect, node, true
		default:
			st.rows = !hasWritableCTE(sel)
		}
	}
	return st
}

// commandTag returns the CommandComplete tag for n affected/returned rows.
func (st *statement) commandTag(n int) string {
	switch st.verb {
	case "SELECT", "UPDATE", "DELETE", "MERGE":
		return st.verb + " " + strconv.Itoa(n)
	case "INSERT":
		return "INSERT 0 " + strconv.Itoa(n)
	case "":
		return "OK"
	}
	return st.verb
}

// leadingKeywords returns up to two leading keywords in upper case (e.g.
// "CREATE TABLE"), used as the command tag of statements without rows.
func leadingKeywords(sql string) string {
	res, err := pg.Scan(sql)
	if err != nil {
		return ""
	}
	var words []string
	for _, t := range res.Tokens {
		if t.Token == pg.Token_SQL_COMMENT || t.Token == pg.Token_C_COMMENT {
			continue
		}
		if t.KeywordKind == pg.KeywordKind_NO_KEYWORD || len(words) == 2 {
			break
		}
		words = append(words, strings.ToUpper(sql[t.Start:t.End]))
		if words[0] != "CREATE" && words[0] != "DROP" && words[0] != "ALTER" {
			break
		}
	}
	return strings.Join(words, " ")
}

// bareSelect reports whether sel is a single SELECT list without FROM or
// any other clause.
func bareSelect(sel *pg.SelectStmt) bool {
	return sel.Op <= pg.SetOperation_SETOP_NONE && len(sel.FromClause) == 0 && sel.WhereClause == nil &&
		len(sel.GroupClause) == 0 && sel.HavingClause == nil && len(sel.WindowClause) == 0 &&
		len(sel.ValuesLists) == 0 && len(sel.SortClause) == 0 && sel.LimitCount == nil && sel.LimitOffset == nil &&
		len(sel.LockingClause) == 0 && sel.WithClause == nil && sel.IntoClause == nil && len(sel.DistinctClause) == 0 &&
		len(sel.TargetList) > 0
}

// isVersionSelect matches SELECT version() and SELECT pg_catalog.version().
func isVersionSelect(sel *pg.SelectStmt) bool {
	if !bareSelect(sel) || len(sel.TargetList) != 1 {
		return false
	}
	rt := sel.TargetList[0].GetResTarget()
	if rt == nil || len(rt.Indirection) > 0 {
		return false
	}
	fc := rt.Val.GetFuncCall()
	if fc == nil || len(fc.Args) > 0 || fc.AggStar || fc.AggDistinct || fc.Over != nil || fc.AggFilter != nil {
		return false
	}
	var name []string
	for _, n := range fc.Funcname {
		name = append(name, n.GetString_().GetSval())
	}
	switch strings.Join(name, ".") {
	case "version", "pg_catalog.version":
		return true
	}
	return false
}

// isConstSelect matches SELECT 1 style connection checks: only integer
// constants, nothing else.
func isConstSelect(sel *pg.SelectStmt) bool {
	if !bareSelect(sel) {
		return false
	}
	for _, t := range sel.TargetList {
		rt := t.GetResTarget()
		if rt == nil || len(rt.Indirection) > 0 {
			return false
		}
		c := rt.Val.GetAConst()
		if c == nil || c.Isnull || c.GetIval() == nil {
			return false
		}
	}
	return true
}

// hasWritableCTE reports whether a WITH clause contains INSERT, UPDATE,
// DELETE or MERGE.
func hasWritableCTE(sel *pg.SelectStmt) bool {
	if sel.WithClause == nil {
		return false
	}
	for _, c := range sel.WithClause.Ctes {
		cte := c.GetCommonTableExpr()
		if cte == nil || cte.Ctequery.GetSelectStmt() == nil {
			return true
		}
	}
	return false
}

// constString returns the value of a constant SET argument as a string.
func constString(n *pg.Node) (string, bool) {
	c := n.GetAConst()
	if c == nil || c.Isnull {
		return "", false
	}
	switch v := c.Val.(type) {
	case *pg.A_Const_Sval:
		return v.Sval.GetSval(), true
	case *pg.A_Const_Ival:
		return strconv.Itoa(int(v.Ival.GetIval())), true
	case *pg.A_Const_Fval:
		return v.Fval.GetFval(), true
	case *pg.A_Const_Boolval:
		if v.Boolval.GetBoolval() {
			return "on", true
		}
		return "off", true
	case nil:
		// Ival 0 is encoded as an empty Ival message.
		return "0", true
	}
	return "", false
}
