package mysql

import (
	"fmt"
	"slices"
	"strings"

	"github.com/pingcap/tidb/pkg/parser/ast"
	"github.com/pingcap/tidb/pkg/parser/test_driver"

	"github.com/kyosu-1/dbgateway/internal/analysis"
)

// scanner walks the whole statement looking for constructs that are always
// rejected, collects called functions, and checks them against the
// allowlist.
type scanner struct {
	a   *Analyzer
	st  *analysis.Statement
	top ast.Node
	rej *analysis.Rejection
}

func (a *Analyzer) scan(root ast.StmtNode, st *analysis.Statement) *analysis.Rejection {
	s := &scanner{a: a, st: st, top: root}
	root.Accept(s)
	return s.rej
}

func (s *scanner) Enter(n ast.Node) (ast.Node, bool) {
	if s.rej != nil {
		return n, true
	}
	s.rej = s.check(n)
	return n, s.rej != nil
}

func (s *scanner) Leave(n ast.Node) (ast.Node, bool) {
	return n, s.rej == nil
}

func (s *scanner) check(n ast.Node) *analysis.Rejection {
	switch x := n.(type) {
	case *ast.SelectStmt:
		if x.SelectIntoOpt != nil {
			return analysis.Reject("select_into", "SELECT ... INTO (OUTFILE / DUMPFILE / variables) is not allowed.", "Send the SELECT statement without the INTO clause.")
		}
		if x.LockInfo != nil && x.LockInfo.LockType != ast.SelectLockNone {
			return analysis.Reject("locking_clause", "FOR UPDATE / FOR SHARE / LOCK IN SHARE MODE is not allowed because it takes row locks.", "Send the SELECT statement without the locking clause.")
		}
		if len(x.TableHints) > 0 || (x.SelectStmtOpts != nil && len(x.SelectStmtOpts.TableHints) > 0) {
			return hintRejection()
		}
		if x.SelectStmtOpts != nil && x.SelectStmtOpts.CalcFoundRows {
			return analysis.Reject("calc_found_rows", "SQL_CALC_FOUND_ROWS is not allowed.", "If you need a count, run COUNT(*) separately.")
		}
	case *ast.UpdateStmt:
		if len(x.TableHints) > 0 {
			return hintRejection()
		}
	case *ast.DeleteStmt:
		if len(x.TableHints) > 0 {
			return hintRejection()
		}
	case *ast.InsertStmt:
		if len(x.TableHints) > 0 {
			return hintRejection()
		}
		if n != s.top {
			s.st.IsWrite = true
		}
	case *ast.TableName:
		if x.AsOf != nil || x.TableSample != nil {
			return analysis.Reject("unsupported_syntax", "AS OF / TABLESAMPLE is not supported in MySQL.", "Remove these clauses.")
		}
	case *ast.VariableExpr:
		if x.IsSystem {
			return analysis.Reject("system_variable", fmt.Sprintf("System variables (@@%s) cannot be read or changed.", x.Name),
				"Use VERSION() for the server version and DATABASE() for the default database.")
		}
		return analysis.Reject("user_variable", fmt.Sprintf("User variables (@%s) are not allowed.", x.Name),
			"Write the values directly in the SQL instead of using variables (values are redacted in the audit log).")
	case *test_driver.ParamMarkerExpr:
		return analysis.Reject("parameters", "SQL with parameters (?) cannot be run.", "Write the values directly in the SQL (values are redacted in the audit log).")
	case *ast.FuncCallExpr:
		return s.function(x.Schema.O, x.FnName.O)
	case *ast.AggregateFuncExpr:
		return s.function("", x.F)
	case *ast.WindowFuncExpr:
		return s.function("", x.Name)
	case *ast.TableNameExpr:
		return analysis.Reject("unsupported_syntax", "This expression is not allowed.", "Express it as a SELECT statement.")
	}
	return nil
}

func hintRejection() *analysis.Rejection {
	return analysis.Reject("optimizer_hint", "SQL with optimizer hints cannot be run.", "Remove the hints and send only the SQL statement itself.")
}

func (s *scanner) function(schema, name string) *analysis.Rejection {
	if schema == "" && strings.HasPrefix(name, "'tidb`.(") {
		// DATE '...' / TIME '...' / TIMESTAMP '...' literals, represented by
		// the parser as calls to internal functions.
		return nil
	}
	display := strings.ToLower(name)
	if schema != "" {
		display = schema + "." + display
	}
	if !slices.Contains(s.st.Functions, display) {
		s.st.Functions = append(s.st.Functions, display)
	}
	if !s.a.funcs.Allowed(schema, name) {
		return analysis.Reject("function_not_allowed",
			fmt.Sprintf("Function %s is not on the allow list, so it cannot be run (this prevents functions with side effects).", display),
			"Rewrite the query without this function, or if it is needed, ask an administrator to add it to sql.allowed_functions.")
	}
	return nil
}
