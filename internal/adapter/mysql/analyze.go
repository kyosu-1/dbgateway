package mysql

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/ast"
	pmysql "github.com/pingcap/tidb/pkg/parser/mysql"
	// The parser needs a value-expression driver; test_driver is the
	// lightweight one meant for using the parser on its own.
	_ "github.com/pingcap/tidb/pkg/parser/test_driver"

	"github.com/kyosu-1/dbgateway/internal/analysis"
)

// SQLMode is the sql_mode fixed on every session. The parser lexes with the
// same mode so that the analyzed statement and the executed statement are
// tokenized identically:
//
//   - ANSI_QUOTES: "x" is an identifier (as in PostgreSQL), never a string.
//   - NO_BACKSLASH_ESCAPES: in '...' only a doubled quote escapes a quote; a backslash is
//     an ordinary character. This removes the classic class of
//     escape-confusion bugs between a client-side parser and the server.
//
// The rest are MySQL 8.4 defaults.
const SQLMode = "ANSI_QUOTES,NO_BACKSLASH_ESCAPES,ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES," +
	"NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION"

// viewSQLMode is used to parse view definitions from
// information_schema.VIEWS. MySQL renders them with backquoted identifiers
// and backslash-escaped string literals regardless of the session mode.
const viewSQLMode = "ANSI_QUOTES"

var (
	sessionMode = mustMode(SQLMode)
	viewMode    = mustMode(viewSQLMode)
)

func mustMode(s string) pmysql.SQLMode {
	m, err := pmysql.GetSQLMode(s)
	if err != nil {
		panic(err)
	}
	return m
}

// parserPool holds parsers configured for one SQL mode. TiDB parsers are
// not safe for concurrent use.
type parserPool struct {
	pool sync.Pool
}

func newParserPool(mode pmysql.SQLMode) *parserPool {
	pp := &parserPool{}
	pp.pool.New = func() any {
		p := parser.New()
		p.SetSQLMode(mode)
		p.EnableWindowFunc(true)
		return p
	}
	return pp
}

func (pp *parserPool) parse(sql string) ([]ast.StmtNode, error) {
	p := pp.pool.Get().(*parser.Parser)
	defer pp.pool.Put(p)
	stmts, _, err := p.ParseSQL(sql)
	return stmts, err
}

var (
	sessionParsers = newParserPool(sessionMode)
	viewParsers    = newParserPool(viewMode)
)

// Analyzer converts MySQL SQL into analysis.QueryAnalysis.
//
// Like the PostgreSQL analyzer it fails closed: anything that cannot be
// parsed or classified is rejected, and Statement.Unknown is set whenever
// part of the statement could not be resolved.
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
	if rej := checkText(sql); rej != nil {
		return nil, rej
	}
	stmts, err := sessionParsers.parse(sql)
	if err != nil {
		return nil, analysis.Reject("parse_error",
			fmt.Sprintf("SQLを解析できませんでした（%s）。解析できないSQLは安全のため実行しません。", parseErrorText(err)),
			"MySQLの構文として正しいか確認して、1文だけを送ってください。文字列は '...'、識別子は \"...\" か `...` で囲みます（sql_mode に ANSI_QUOTES を設定しています）。")
	}
	switch len(stmts) {
	case 0:
		return nil, analysis.Reject("empty", "SQLに文が含まれていません。", "実行するSQLを1文だけ指定してください。")
	case 1:
	default:
		return nil, analysis.Reject("multiple_statements",
			fmt.Sprintf("%d個の文が含まれています。複数の文をまとめて送ることはできません。", len(stmts)),
			"セミコロンで区切らず、1回の呼び出しで1文だけを送ってください。")
	}
	stmt := stmts[0]

	qa := &analysis.QueryAnalysis{Normalized: normalizeText(sql)}
	st := &qa.Statement
	kind, rej := classify(stmt)
	if rej != nil {
		return nil, rej
	}
	st.Kind = kind
	switch kind {
	case analysis.KindInsert, analysis.KindUpdate, analysis.KindDelete, analysis.KindTruncate:
		st.IsWrite = true
	}
	if kind == analysis.KindDDL {
		// DDL is never executed through dbgateway; the policy decides how
		// to explain the denial.
		return qa, nil
	}

	// Pass 1: safety scan over the whole tree.
	if rej := a.scan(stmt, st); rej != nil {
		return nil, rej
	}

	// Pass 2: name resolution and column lineage.
	r := newResolver(cat)
	switch n := stmt.(type) {
	case *ast.SelectStmt, *ast.SetOprStmt:
		qa.Output = toOutput(r.query(n.(ast.ResultSetNode), nil, analysis.UsageOutput))
	case *ast.InsertStmt:
		qa.Output = r.insertStmt(n)
	case *ast.UpdateStmt:
		qa.Output = r.updateStmt(n)
		st.HasWhere = n.Where != nil
	case *ast.DeleteStmt:
		qa.Output = r.deleteStmt(n)
		st.HasWhere = n.Where != nil
	case *ast.TruncateTableStmt:
		if n.Table != nil {
			r.recordTable(n.Table, false, true)
		}
	}
	r.finish(st)
	return qa, nil
}

// parseErrorText shortens TiDB parser errors (which echo part of the SQL)
// to the position information.
func parseErrorText(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, " near "); i > 0 {
		msg = msg[:i]
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// classify maps the top-level statement to a statement kind, rejecting
// statements that are never allowed.
func classify(n ast.StmtNode) (analysis.StmtKind, *analysis.Rejection) {
	switch x := n.(type) {
	case *ast.SelectStmt, *ast.SetOprStmt:
		return analysis.KindSelect, nil
	case *ast.InsertStmt:
		return analysis.KindInsert, nil
	case *ast.UpdateStmt:
		return analysis.KindUpdate, nil
	case *ast.DeleteStmt:
		return analysis.KindDelete, nil
	case *ast.TruncateTableStmt:
		return analysis.KindTruncate, nil
	case *ast.BeginStmt, *ast.CommitStmt, *ast.RollbackStmt, *ast.SavepointStmt, *ast.ReleaseSavepointStmt:
		return "", analysis.Reject("transaction_control",
			"トランザクション制御（BEGIN / START TRANSACTION / COMMIT / ROLLBACK / SAVEPOINTなど）は実行できません。",
			"トランザクションはdbgatewayが管理します。SQL本体だけを送ってください。")
	case *ast.SetStmt, *ast.SetRoleStmt, *ast.SetPwdStmt, *ast.SetConfigStmt, *ast.SetResourceGroupStmt,
		*ast.SetSessionStatesStmt, *ast.SetBindingStmt:
		return "", analysis.Reject("set",
			"SET（変数・ロール・パスワード・トランザクション特性など）は実行できません。",
			"セッション設定はdbgatewayが固定しています。設定を変えずにSQL本体だけを送ってください。")
	case *ast.ShowStmt:
		return "", analysis.Reject("show", "SHOW は実行できません。",
			"表や列を調べるには search_objects を使ってください。")
	case *ast.ExplainStmt:
		if x.Analyze {
			return "", analysis.Reject("explain_analyze", "EXPLAIN ANALYZE は文を実際に実行するため実行できません。", "ANALYZEを外すか、SELECT文そのものを送ってください。")
		}
		return "", analysis.Reject("explain", "EXPLAIN / DESCRIBE は execute_sql では実行できません。",
			"SELECT文そのものを送ってください。見積もり行数はdbgatewayが自動で確認します。表の定義は search_objects で確認できます。")
	case *ast.LoadDataStmt, *ast.ImportIntoStmt:
		return "", analysis.Reject("load_data", "LOAD DATA / IMPORT INTO は実行できません（サーバーやクライアントのファイルへのアクセスを防ぐため）。", "INSERT文で必要な行だけを書いてください（承認が必要です）。")
	case *ast.CallStmt:
		return "", analysis.Reject("call", "CALL（プロシージャの呼び出し）は実行できません。", "SELECT文で必要なデータを取得してください。")
	case *ast.DoStmt:
		return "", analysis.Reject("do", "DO は実行できません。", "SELECT文で表現してください。")
	case *ast.LockTablesStmt, *ast.UnlockTablesStmt:
		return "", analysis.Reject("lock", "LOCK TABLES / UNLOCK TABLES は実行できません。", "ロックを取らずにSELECT文を送ってください。")
	case *ast.PrepareStmt, *ast.ExecuteStmt, *ast.DeallocateStmt:
		return "", analysis.Reject("prepare", "PREPARE / EXECUTE / DEALLOCATE は実行できません。", "SQL本体を直接送ってください。")
	case *ast.UseStmt:
		return "", analysis.Reject("use", "USE（既定のデータベースの変更）は実行できません。", "表名をデータベース名で修飾して書いてください（例: app.users）。")
	case *ast.KillStmt:
		return "", analysis.Reject("kill", "KILL は実行できません。", "接続やクエリの停止は管理者に依頼してください。")
	case *ast.FlushStmt, *ast.ShutdownStmt, *ast.RestartStmt, *ast.AdminStmt, *ast.BinlogStmt,
		*ast.HelpStmt, *ast.TrafficStmt:
		return "", analysis.Reject("utility", "この種類のユーティリティ文は実行できません。", "SELECT文を送ってください。")
	case *ast.GrantStmt, *ast.RevokeStmt, *ast.GrantRoleStmt, *ast.RevokeRoleStmt, *ast.GrantProxyStmt,
		*ast.CreateUserStmt, *ast.AlterUserStmt, *ast.DropUserStmt, *ast.RenameUserStmt, *ast.SetDefaultRoleStmt,
		*ast.AnalyzeTableStmt, *ast.OptimizeTableStmt:
		return analysis.KindDDL, nil
	case ast.DDLNode:
		return analysis.KindDDL, nil
	}
	return "", analysis.Reject("unsupported_statement",
		fmt.Sprintf("この種類の文（%s）は判定できないため実行しません。", stmtName(n)),
		"SELECT文で表現してください。")
}

func stmtName(n ast.Node) string {
	return strings.TrimPrefix(fmt.Sprintf("%T", n), "*ast.")
}

// Normalize replaces literal values in sql with placeholders and drops
// comments. It returns an empty string when the SQL cannot be parsed or is
// rejected before parsing.
func (a *Analyzer) Normalize(sql string) string {
	if checkText(sql) != nil {
		return ""
	}
	if _, err := sessionParsers.parse(sql); err != nil {
		return ""
	}
	return normalizeText(sql)
}
