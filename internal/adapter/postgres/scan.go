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
			rej = analysis.Reject("select_into", "SELECT ... INTO は表を作成するため実行できません。", "INTO句を外したSELECT文を送ってください。")
		case *pg.LockingClause:
			rej = analysis.Reject("locking_clause", "FOR UPDATE / FOR SHARE は行ロックを取るため実行できません。", "ロック句を外したSELECT文を送ってください。")
		case *pg.ParamRef:
			rej = analysis.Reject("parameters", "パラメータ（$1など）を含むSQLは実行できません。", "値をSQLに直接書いてください（値は監査ログでは伏せられます）。")
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
					fmt.Sprintf("関数 %s は許可リストにないため実行できません（副作用のある関数を防ぐため）。", name),
					"この関数を使わずに書き直すか、必要なら管理者に sql.allowed_functions への追加を依頼してください。")
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
