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
		return nil, analysis.Reject("empty", "SQLが空です。", "実行するSQLを1文だけ指定してください。")
	}
	tree, err := pg.Parse(sql)
	if err != nil {
		return nil, analysis.Reject("parse_error",
			fmt.Sprintf("SQLを解析できませんでした（%s）。解析できないSQLは安全のため実行しません。", err.Error()),
			"PostgreSQLの構文として正しいか確認して、1文だけを送ってください。")
	}
	switch len(tree.Stmts) {
	case 0:
		return nil, analysis.Reject("empty", "SQLに文が含まれていません。", "実行するSQLを1文だけ指定してください。")
	case 1:
	default:
		return nil, analysis.Reject("multiple_statements",
			fmt.Sprintf("%d個の文が含まれています。複数の文をまとめて送ることはできません。", len(tree.Stmts)),
			"セミコロンで区切らず、1回の呼び出しで1文だけを送ってください。")
	}
	stmt := tree.Stmts[0].Stmt
	if stmt == nil || stmt.Node == nil {
		return nil, analysis.Reject("empty", "SQLに文が含まれていません。", "実行するSQLを1文だけ指定してください。")
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
			"トランザクション制御（BEGIN/COMMIT/ROLLBACKなど）は実行できません。",
			"トランザクションはdbgatewayが管理します。SQL本体だけを送ってください。")
	case *pg.Node_VariableSetStmt, *pg.Node_AlterSystemStmt:
		return "", analysis.Reject("set",
			"SET / RESET / SET ROLE などのセッション設定は変更できません。",
			"セッション設定はdbgatewayが固定しています。設定を変えずにSQL本体だけを送ってください。")
	case *pg.Node_VariableShowStmt:
		return "", analysis.Reject("show", "SHOW は実行できません。", "設定値の確認が必要な場合は管理者に問い合わせてください。")
	case *pg.Node_DoStmt:
		return "", analysis.Reject("do_block", "DOブロックは実行できません。", "手続き的な処理は使わず、1つのSELECT文で表現してください。")
	case *pg.Node_CopyStmt:
		return "", analysis.Reject("copy", "COPY は実行できません（サーバー上のファイルやプログラムへのアクセスを防ぐため）。", "SELECT文で必要な行だけを取得してください。")
	case *pg.Node_ExplainStmt:
		if explainHasAnalyze(x.ExplainStmt) {
			return "", analysis.Reject("explain_analyze", "EXPLAIN ANALYZE は文を実際に実行するため実行できません。", "ANALYZEを外すか、SELECT文そのものを送ってください。")
		}
		return "", analysis.Reject("explain", "EXPLAIN は execute_sql では実行できません。", "SELECT文そのものを送ってください。見積もり行数はdbgatewayが自動で確認します。")
	case *pg.Node_CallStmt:
		return "", analysis.Reject("call", "CALL（プロシージャの呼び出し）は実行できません。", "SELECT文で必要なデータを取得してください。")
	case *pg.Node_LockStmt:
		return "", analysis.Reject("lock", "LOCK は実行できません。", "ロックを取らずにSELECT文を送ってください。")
	case *pg.Node_NotifyStmt, *pg.Node_ListenStmt, *pg.Node_UnlistenStmt:
		return "", analysis.Reject("notify", "NOTIFY / LISTEN / UNLISTEN は実行できません。", "通知機能は使えません。")
	case *pg.Node_PrepareStmt, *pg.Node_ExecuteStmt, *pg.Node_DeallocateStmt:
		return "", analysis.Reject("prepare", "PREPARE / EXECUTE / DEALLOCATE は実行できません。", "SQL本体を直接送ってください。")
	case *pg.Node_DeclareCursorStmt, *pg.Node_FetchStmt, *pg.Node_ClosePortalStmt:
		return "", analysis.Reject("cursor", "カーソル操作は実行できません。", "SELECT文を直接送ってください。行数の上限はdbgatewayがかけます。")
	case *pg.Node_DiscardStmt, *pg.Node_LoadStmt, *pg.Node_CheckPointStmt:
		return "", analysis.Reject("utility", "この種類のユーティリティ文は実行できません。", "SELECT文を送ってください。")
	}
	if isDDL(n) {
		return analysis.KindDDL, nil
	}
	return "", analysis.Reject("unsupported_statement",
		fmt.Sprintf("この種類の文（%s）は判定できないため実行しません。", nodeName(n)),
		"SELECT文で表現してください。")
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
