package postgres

import (
	"fmt"
	"slices"
	"strings"

	pg "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"

	"github.com/kyosu-1/dbgateway/internal/analysis"
)

// scan walks the whole statement looking for constructs that are always
// rejected, collects called functions, and checks them against the
// allowlist. Nested data-modifying statements (writable CTEs) mark the
// statement as a write.
func (a *Analyzer) scan(root *pg.Node, st *analysis.Statement) *analysis.Rejection {
	var rej *analysis.Rejection
	top := nodeMessage(root)
	walk(root, func(m proto.Message) bool {
		if rej != nil {
			return false
		}
		switch x := m.(type) {
		case *pg.IntoClause:
			rej = analysis.Reject("select_into", "SELECT ... INTO is not allowed because it creates a table.", "Send the SELECT statement without the INTO clause.")
		case *pg.LockingClause:
			rej = analysis.Reject("locking_clause", "FOR UPDATE / FOR SHARE is not allowed because it takes row locks.", "Send the SELECT statement without the locking clause.")
		case *pg.ParamRef:
			rej = analysis.Reject("parameters", "SQL with parameters ($1, etc.) cannot be run.", "Write the values directly in the SQL (values are redacted in the audit log).")
		case *pg.InsertStmt, *pg.UpdateStmt, *pg.DeleteStmt, *pg.MergeStmt:
			if m != top {
				st.IsWrite = true
			}
		case *pg.FuncCall:
			name := funcName(x.Funcname)
			if !slices.Contains(st.Functions, name) {
				st.Functions = append(st.Functions, name)
			}
			if !a.funcs.Allowed(x.Funcname) {
				rej = analysis.Reject("function_not_allowed",
					fmt.Sprintf("Function %s is not on the allow list, so it cannot be run (this prevents functions with side effects).", name),
					"Rewrite the query without this function, or if it is needed, ask an administrator to add it to sql.allowed_functions.")
			}
		}
		return true
	})
	return rej
}

// funcName renders a function name, schema-qualified when given.
func funcName(parts []*pg.Node) string {
	var names []string
	for _, p := range parts {
		if s := p.GetString_(); s != nil {
			names = append(names, s.Sval)
		}
	}
	return strings.Join(names, ".")
}
