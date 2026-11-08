package pgproxy

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
	pg "github.com/pganalyze/pg_query_go/v6"

	"github.com/kyosu-1/dbgateway/internal/gateway"
)

// Statements answered by the proxy itself: session settings, SHOW,
// transaction control and connection checks. None of them reach a
// database.

// ServerVersion is reported as server_version and by SELECT version().
const ServerVersion = "17.0 (dbgateway)"

// reasonParam is the setting holding the session's reason.
const reasonParam = "dbgw.reason"

// maxReasonLen bounds SET dbgw.reason (bytes).
const maxReasonLen = 1000

// reportedParams are sent as ParameterStatus after authentication, in this
// order.
var reportedParams = []string{
	"server_version", "server_encoding", "client_encoding", "DateStyle", "IntervalStyle", "TimeZone",
	"integer_datetimes", "standard_conforming_strings", "is_superuser", "session_authorization", "application_name",
}

// initParams sets the session's settings from their defaults and the
// startup packet.
func (s *session) initParams(startup map[string]string) {
	set := func(name, value string, report bool) {
		s.params[strings.ToLower(name)] = &param{name: name, value: value, report: report}
		s.initial[strings.ToLower(name)] = value
	}
	set("server_version", ServerVersion, true)
	set("server_encoding", "UTF8", true)
	set("client_encoding", "UTF8", true)
	set("DateStyle", "ISO, MDY", true)
	set("IntervalStyle", "postgres", true)
	set("TimeZone", "UTC", true)
	set("integer_datetimes", "on", true)
	set("standard_conforming_strings", "on", true)
	set("is_superuser", "off", true)
	set("session_authorization", s.user, true)
	set("application_name", startup["application_name"], true)
	set("extra_float_digits", "1", false)
	set("client_min_messages", "notice", false)
	search := []string{"public"}
	if db := s.srv.cfg.Database(s.database); db != nil {
		search = db.SearchPath
	}
	set("search_path", strings.Join(search, ", "), false)
}

// setParam changes a setting, reporting it to the client when needed.
func (s *session) setParam(r *result, name, value string) {
	p := s.params[name]
	if p.value == value {
		return
	}
	p.value = value
	if p.report {
		r.status = append(r.status, &pgproto3.ParameterStatus{Name: p.name, Value: value})
	}
}

// resetAll restores every setting to its startup value (RESET ALL,
// DISCARD ALL).
func (s *session) resetAll(r *result) {
	s.reason = ""
	for name, v := range s.initial {
		s.setParam(r, name, v)
	}
}

func isUTF8(enc string) bool {
	switch strings.ToLower(strings.ReplaceAll(strings.Trim(enc, `'"`), "-", "")) {
	case "utf8", "unicode", "auto":
		return true
	}
	return false
}

func isUTC(tz string) bool {
	switch strings.ToLower(strings.Trim(tz, `'"`)) {
	case "utc", "etc/utc", "gmt", "etc/gmt", "z", "zulu", "universal", "utc0", "+00", "+00:00", "0", "default", "local":
		return true
	}
	return false
}

func ignoredSetting(name, why string) *pgproto3.NoticeResponse {
	return notice("NOTICE", fmt.Sprintf("SET %s は受け付けましたが、効果はありません。%s / SET %s is accepted but has no effect.", name, why, name), "", "")
}

// execSet handles SET and RESET.
func (s *session) execSet(v *pg.VariableSetStmt) *result {
	tag := "SET"
	if v.Kind == pg.VariableSetKind_VAR_RESET || v.Kind == pg.VariableSetKind_VAR_RESET_ALL {
		tag = "RESET"
	}
	r := &result{tag: tag}
	if v.Kind == pg.VariableSetKind_VAR_RESET_ALL {
		s.resetAll(r)
		return r
	}
	name := strings.ToLower(v.Name)
	if v.IsLocal {
		r.notices = append(r.notices, notice("WARNING",
			"SET LOCAL は効果がありません。dbgateway は各文を別々のトランザクションで実行します。 / SET LOCAL has no effect: dbgateway runs each statement in its own transaction.",
			"", "SET（LOCAL なし）を使ってください。"))
		return r
	}
	reset := v.Kind == pg.VariableSetKind_VAR_SET_DEFAULT || v.Kind == pg.VariableSetKind_VAR_RESET
	var value string
	valueOK := false
	if v.Kind == pg.VariableSetKind_VAR_SET_VALUE {
		parts := make([]string, 0, len(v.Args))
		valueOK = len(v.Args) > 0
		for _, a := range v.Args {
			str, ok := constString(a)
			valueOK = valueOK && ok
			parts = append(parts, str)
		}
		value = strings.Join(parts, ", ")
	}
	if !reset && !valueOK && v.Kind != pg.VariableSetKind_VAR_SET_MULTI {
		switch name {
		case "timezone", "datestyle", "intervalstyle", "transaction", "session characteristics":
			// Values are ignored below; tolerate any syntax.
		default:
			return errResult(pgError("22023", fmt.Sprintf("SET %s: 値は定数で指定してください。 / invalid value for SET %s", v.Name, v.Name), ""))
		}
	}

	switch name {
	case reasonParam:
		switch {
		case reset:
			s.reason = ""
		case len(v.Args) != 1:
			return errResult(pgError("22023", "SET dbgw.reason には文字列を1つ指定してください。 / SET dbgw.reason takes a single string.",
				"例: SET dbgw.reason = '問い合わせ#1234の調査のため';"))
		case len(value) > maxReasonLen || !utf8.ValidString(value):
			return errResult(pgError("22001", fmt.Sprintf("dbgw.reason が長すぎます（最大 %d バイト）。 / dbgw.reason is too long.", maxReasonLen), ""))
		default:
			s.reason = strings.TrimSpace(value)
		}
	case "application_name":
		if reset {
			value = s.initial[name]
		}
		s.setParam(r, name, value)
	case "client_encoding":
		if !reset && !isUTF8(value) {
			return errResult(pgError("22023", fmt.Sprintf("client_encoding %q には対応していません（UTF8 のみ）。 / Only UTF8 is supported.", value), ""))
		}
	case "extra_float_digits", "client_min_messages":
		if reset {
			value = s.initial[name]
		}
		s.setParam(r, name, strings.ToLower(value))
	case "datestyle":
		if !reset && !strings.Contains(strings.ToLower(value), "iso") {
			r.notices = append(r.notices, ignoredSetting(v.Name, "日時は常に ISO 形式で返します。"))
		}
	case "timezone":
		if !reset && !(valueOK && isUTC(value)) {
			r.notices = append(r.notices, ignoredSetting(v.Name, "時刻は常に UTC で返します。"))
		}
	case "intervalstyle":
		if !reset && !strings.EqualFold(value, "postgres") {
			r.notices = append(r.notices, ignoredSetting(v.Name, "interval は常に postgres 形式で返します。"))
		}
	case "bytea_output":
		if !reset && !strings.EqualFold(value, "hex") {
			r.notices = append(r.notices, ignoredSetting(v.Name, "bytea は常に hex 形式で返します。"))
		}
	case "standard_conforming_strings":
		switch strings.ToLower(value) {
		case "on", "true", "yes", "1":
		default:
			if !reset {
				return errResult(pgError("0A000", "standard_conforming_strings は on 以外にできません。 / standard_conforming_strings must stay on.", ""))
			}
		}
	case "transaction", "session characteristics", "statement_timeout", "lock_timeout", "idle_in_transaction_session_timeout", "default_transaction_read_only":
		r.notices = append(r.notices, ignoredSetting(v.Name, "タイムアウトと読み取り専用の扱いは dbgateway の設定で決まります。"))
	case "search_path":
		return errResult(pgError("42501", "search_path は変更できません。 / search_path cannot be changed through dbgateway.",
			"テーブル名にスキーマ名を付けて書いてください（例: public.users）。"))
	default:
		return errResult(pgError("0A000", fmt.Sprintf("SET %s は dbgateway のプロキシでは使えません。 / SET %s is not supported by the dbgateway proxy.", v.Name, v.Name),
			"理由は SET dbgw.reason = '...'; で指定します。"))
	}
	return r
}

// textResult builds a SHOW result of text columns.
func textResult(columns []string, rows ...[]string) *result {
	r := &result{hasRows: true, tag: "SHOW"}
	for _, c := range columns {
		r.fields = append(r.fields, field{name: c, oid: pgtype.TextOID, typName: "text"})
	}
	for _, row := range rows {
		vals := make([][]byte, len(row))
		for i, v := range row {
			vals[i] = []byte(v)
		}
		r.rows = append(r.rows, vals)
	}
	return r
}

// execShow handles SHOW name and SHOW ALL.
func (s *session) execShow(name string) *result {
	name = strings.ToLower(name)
	switch name {
	case reasonParam:
		return textResult([]string{reasonParam}, []string{s.reason})
	case "all":
		var rows [][]string
		for _, p := range s.params {
			rows = append(rows, []string{p.name, p.value, ""})
		}
		rows = append(rows, []string{reasonParam, s.reason, "reason recorded with every query"})
		slices.SortFunc(rows, func(a, b []string) int { return strings.Compare(strings.ToLower(a[0]), strings.ToLower(b[0])) })
		return textResult([]string{"name", "setting", "description"}, rows...)
	}
	p, ok := s.params[name]
	if !ok {
		return errResult(pgError("42704", fmt.Sprintf("unrecognized configuration parameter %q", name), ""))
	}
	return textResult([]string{p.name}, []string{p.value})
}

// execTxn accepts BEGIN/COMMIT/ROLLBACK without opening a transaction.
func (s *session) execTxn(t *pg.TransactionStmt) *result {
	switch t.Kind {
	case pg.TransactionStmtKind_TRANS_STMT_BEGIN, pg.TransactionStmtKind_TRANS_STMT_START:
		tag := "BEGIN"
		if t.Kind == pg.TransactionStmtKind_TRANS_STMT_START {
			tag = "START TRANSACTION"
		}
		return &result{tag: tag, notices: []*pgproto3.NoticeResponse{notice("NOTICE",
			"dbgateway は各文を個別のトランザクションで実行します。BEGIN は受け付けますが、続く文はまとめて実行されません。 / dbgateway runs each statement in its own transaction; BEGIN is accepted but does not group statements.",
			"", "")}}
	case pg.TransactionStmtKind_TRANS_STMT_COMMIT:
		return &result{tag: "COMMIT"}
	case pg.TransactionStmtKind_TRANS_STMT_ROLLBACK:
		return &result{tag: "ROLLBACK"}
	}
	return errResult(pgError("0A000", "SAVEPOINT や PREPARE TRANSACTION は dbgateway のプロキシでは使えません。 / Savepoints and two-phase commit are not supported by the dbgateway proxy.", ""))
}

func (s *session) execDiscard(d *pg.DiscardStmt) *result {
	switch d.Target {
	case pg.DiscardMode_DISCARD_ALL:
		r := &result{tag: "DISCARD ALL"}
		clear(s.stmts)
		clear(s.portals)
		s.resetAll(r)
		return r
	case pg.DiscardMode_DISCARD_PLANS:
		return &result{tag: "DISCARD PLANS"}
	case pg.DiscardMode_DISCARD_SEQUENCES:
		return &result{tag: "DISCARD SEQUENCES"}
	default:
		return &result{tag: "DISCARD TEMP"}
	}
}

func (s *session) execDeallocate(d *pg.DeallocateStmt) *result {
	if d.Isall || d.Name == "" {
		clear(s.stmts)
		return &result{tag: "DEALLOCATE ALL"}
	}
	if _, ok := s.stmts[d.Name]; !ok {
		return errResult(pgError("26000", fmt.Sprintf("prepared statement %q does not exist", d.Name), ""))
	}
	delete(s.stmts, d.Name)
	return &result{tag: "DEALLOCATE"}
}

func columnName(t *pg.Node, def string) string {
	if rt := t.GetResTarget(); rt != nil && rt.Name != "" {
		return rt.Name
	}
	return def
}

func execVersion(sel *pg.SelectStmt) *result {
	return &result{
		hasRows: true,
		fields:  []field{{name: columnName(sel.TargetList[0], "version"), oid: pgtype.TextOID, typName: "text"}},
		rows:    [][][]byte{{[]byte("PostgreSQL " + ServerVersion)}},
		tag:     "SELECT 1",
	}
}

func execConstSelect(sel *pg.SelectStmt) *result {
	r := &result{hasRows: true, tag: "SELECT 1"}
	row := make([][]byte, len(sel.TargetList))
	for i, t := range sel.TargetList {
		r.fields = append(r.fields, field{name: columnName(t, "?column?"), oid: pgtype.Int4OID, typName: "int4"})
		row[i] = []byte(strconv.Itoa(int(t.GetResTarget().Val.GetAConst().GetIval().GetIval())))
	}
	r.rows = [][][]byte{row}
	return r
}

// responseField reads a field of the gateway response by its JSON name, so
// that fields added later (e.g. approval_url for pending statements) are
// picked up without a compile-time dependency.
func responseField(resp *gateway.ExecuteResponse, name string) string {
	b, err := json.Marshal(resp)
	if err != nil {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	s, _ := m[name].(string)
	return s
}
