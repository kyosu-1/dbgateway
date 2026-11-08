package pgproxy

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

// describeCacheTTL bounds how long a result computed to answer Describe
// (statement) may be reused by the following Bind/Execute.
const describeCacheTTL = 30 * time.Second

// session is one authenticated client connection. Its methods run on the
// connection's goroutine, except cancelRunning.
type session struct {
	srv   *Server
	conn  net.Conn
	be    *pgproto3.Backend
	log   *slog.Logger
	types *pgtype.Map

	p        *identity.Principal
	database string
	user     string
	traceID  string // correlates the session's statements in the audit log
	pid      uint32
	secret   []byte

	params  map[string]*param // by lower-case name
	initial map[string]string // startup values, restored by RESET
	reason  string            // SET dbgw.reason

	stmts          map[string]*prepared
	portals        map[string]*portal
	ignoreTillSync bool

	mu      sync.Mutex
	running context.CancelFunc
}

// param is a session setting the proxy answers SHOW for.
type param struct {
	name   string // canonical spelling, e.g. DateStyle
	value  string
	report bool // sent as ParameterStatus
}

// prepared is a statement created by Parse.
type prepared struct {
	st *statement
	// described is the result computed to answer Describe (statement); the
	// next Bind takes it so that the statement does not run twice.
	described   *result
	describedAt time.Time
}

// portal is a portal created by Bind.
type portal struct {
	st              *statement
	formats         []int16
	res             *result // nil until executed
	pos             int     // rows already sent
	noticesSent     bool
	describedNoData bool
}

// result is the outcome of one statement, ready to be sent.
type result struct {
	hasRows bool // send RowDescription (possibly with zero columns)
	fields  []field
	rows    [][][]byte // text format; nil element = NULL
	tag     string
	notices []*pgproto3.NoticeResponse
	status  []*pgproto3.ParameterStatus
	err     *pgproto3.ErrorResponse
	empty   bool // EmptyQueryResponse
}

func errResult(e *pgproto3.ErrorResponse) *result { return &result{err: e} }

func newSession(srv *Server, conn net.Conn, log *slog.Logger) *session {
	var b [10]byte
	_, _ = rand.Read(b[:])
	return &session{
		srv: srv, conn: conn, be: pgproto3.NewBackend(conn, conn), log: log, types: pgtype.NewMap(),
		traceID: "pgproxy_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])),
		params:  map[string]*param{}, initial: map[string]string{},
		stmts: map[string]*prepared{}, portals: map[string]*portal{},
	}
}

func (s *session) close() {
	if s.pid != 0 {
		s.srv.unregister(s)
	}
}

func (s *session) send(m pgproto3.BackendMessage) { s.be.Send(m) }

// flush writes buffered messages; false means the connection is broken.
func (s *session) flush() bool {
	_ = s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return s.be.Flush() == nil
}

// sendFatal sends a FATAL error; the caller closes the connection.
func (s *session) sendFatal(e *pgproto3.ErrorResponse) {
	s.send(e)
	s.flush()
}

// startup authenticates the client and sends the initial parameters. It
// returns false when the connection must be closed.
func (s *session) startup(ctx context.Context, m *pgproto3.StartupMessage, minor uint16) bool {
	params := m.Parameters
	s.user = params["user"]
	s.database = params["database"]
	if s.database == "" {
		s.database = s.user
	}
	if s.database == "" {
		s.sendFatal(fatal("3D000", "接続先（database）を指定してください。 / No database specified: use the dbgateway connection name as the database name.", ""))
		return false
	}
	switch strings.ToLower(params["replication"]) {
	case "", "false", "off", "no", "0":
	default:
		s.sendFatal(fatal("0A000", "replication connections are not supported by the dbgateway proxy", ""))
		return false
	}
	if enc := params["client_encoding"]; enc != "" && !isUTF8(enc) {
		s.sendFatal(fatal("22023", fmt.Sprintf("client_encoding %q is not supported: dbgateway only speaks UTF8", enc), ""))
		return false
	}
	var unrecognized []string
	for k := range params {
		if strings.HasPrefix(k, "_pq_.") {
			unrecognized = append(unrecognized, k)
		}
	}
	if minor != 0 || len(unrecognized) > 0 {
		slices.Sort(unrecognized)
		s.send(&pgproto3.NegotiateProtocolVersion{NewestMinorProtocol: 0, UnrecognizedOptions: unrecognized})
	}

	s.send(&pgproto3.AuthenticationCleartextPassword{})
	if !s.flush() {
		return false
	}
	_ = s.be.SetAuthType(pgproto3.AuthTypeCleartextPassword)
	s.be.SetMaxBodyLen(maxTokenSize)
	msg, err := s.be.Receive()
	if err != nil {
		s.log.Debug("pgproxy: no password received", "err", err)
		return false
	}
	pw, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		s.sendFatal(fatal("08P01", "expected a password response", ""))
		return false
	}
	p, err := s.authenticate(ctx, pw.Password)
	if err != nil || p == nil {
		s.log.Warn("pgproxy authentication failed", "user", s.user, "err", err)
		s.sendFatal(fatal("28P01",
			"dbgateway トークンによる認証に失敗しました。 / Authentication with the dbgateway token failed.",
			"パスワードに dbgateway のアクセストークン（dbgw_at_...）を指定してください。トークンは `dbgw login` または `dbgw token create` で取得できます。"))
		return false
	}
	if !p.HasScope(identity.ScopeRead) {
		s.sendFatal(fatal("28000", "このトークンには db:read スコープがありません。 / The token lacks the db:read scope.", ""))
		return false
	}
	if !s.canQuery(p) {
		s.sendFatal(fatal("3D000",
			fmt.Sprintf("接続先 %q は存在しないか、クエリを実行する権限がありません。 / Database %q does not exist or you may not query it.", s.database, s.database),
			"データベース名には dbgateway の接続名を指定してください（`dbgw` の list_databases で確認できます）。"))
		return false
	}
	s.p = p
	s.be.SetMaxBodyLen(maxMessageSize)
	_ = s.be.SetAuthType(pgproto3.AuthTypeOk)

	s.initParams(params)
	s.srv.register(s)
	s.send(&pgproto3.AuthenticationOk{})
	for _, name := range reportedParams {
		pp := s.params[strings.ToLower(name)]
		s.send(&pgproto3.ParameterStatus{Name: pp.name, Value: pp.value})
	}
	s.send(&pgproto3.BackendKeyData{ProcessID: s.pid, SecretKey: s.secret})
	s.send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if !s.flush() {
		return false
	}
	s.log = s.log.With("human", p.Human, "kind", string(p.Kind), "database", s.database, "trace_id", s.traceID)
	if p.Agent != "" {
		s.log = s.log.With("agent", p.Agent)
	}
	s.log.Info("pgproxy session started")
	return true
}

func (s *session) authenticate(ctx context.Context, token string) (*identity.Principal, error) {
	if token == "" {
		return nil, errors.New("empty password")
	}
	ctx, cancel := context.WithTimeout(ctx, authTimeout)
	defer cancel()
	return s.srv.authn(ctx, token)
}

// canQuery reports whether p may run queries on the session's database.
func (s *session) canQuery(p *identity.Principal) bool {
	for _, d := range s.srv.gw.ListDatabases(p) {
		if d.Name == s.database {
			return d.CanRead
		}
	}
	return false
}

// serve is the message loop after startup.
func (s *session) serve(ctx context.Context) {
	defer s.log.Info("pgproxy session ended")
	for {
		if s.srv.idle > 0 {
			_ = s.conn.SetReadDeadline(time.Now().Add(s.srv.idle))
		} else {
			_ = s.conn.SetReadDeadline(time.Time{})
		}
		msg, err := s.be.Receive()
		if err != nil {
			var tooBig *pgproto3.ExceededMaxBodyLenErr
			var ne net.Error
			switch {
			case errors.As(err, &tooBig):
				s.sendFatal(fatal("54000", fmt.Sprintf("message too large (limit %d bytes)", maxMessageSize), ""))
			case errors.As(err, &ne) && ne.Timeout():
				s.sendFatal(fatal("57P05", "terminating connection due to idle timeout", ""))
			}
			return
		}
		if ctx.Err() != nil || !s.dispatch(ctx, msg) {
			return
		}
	}
}

// dispatch handles one message; false closes the connection.
func (s *session) dispatch(ctx context.Context, msg pgproto3.FrontendMessage) bool {
	switch msg.(type) {
	case *pgproto3.Terminate:
		return false
	case *pgproto3.Sync:
		s.ignoreTillSync = false
		clear(s.portals) // portals do not outlive the implicit transaction
		s.send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		return s.flush()
	case *pgproto3.Flush:
		return s.flush()
	case *pgproto3.CopyData, *pgproto3.CopyDone, *pgproto3.CopyFail:
		return true // ignored outside COPY, as PostgreSQL does
	}
	if s.ignoreTillSync {
		return true // after an error, discard until Sync
	}
	var errResp *pgproto3.ErrorResponse
	switch m := msg.(type) {
	case *pgproto3.Query:
		s.simpleQuery(ctx, m.String)
		return s.flush()
	case *pgproto3.Parse:
		errResp = s.parse(m)
	case *pgproto3.Bind:
		errResp = s.bind(m)
	case *pgproto3.Describe:
		errResp = s.describe(ctx, m)
	case *pgproto3.Execute:
		errResp = s.execute(ctx, m)
	case *pgproto3.Close:
		errResp = s.closeObject(m)
	case *pgproto3.FunctionCall:
		s.send(pgError("0A000", "関数呼び出しプロトコルは使えません。 / The function call protocol is not supported by the dbgateway proxy.", ""))
		s.send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		return s.flush()
	default:
		s.sendFatal(fatal("08P01", fmt.Sprintf("unexpected message %T", msg), ""))
		return false
	}
	if errResp != nil {
		s.send(errResp)
		s.ignoreTillSync = true
	}
	return true
}

// ---------------------------------------------------------------------------
// Simple query protocol

func (s *session) simpleQuery(ctx context.Context, sql string) {
	delete(s.stmts, "")
	delete(s.portals, "")
	parts := splitStatements(sql)
	if len(parts) == 0 {
		s.send(&pgproto3.EmptyQueryResponse{})
	}
	for _, part := range parts {
		r := s.run(ctx, classify(part))
		s.sendNotices(r)
		if r.err != nil {
			s.send(r.err)
			break // the rest of the query string is not executed
		}
		if r.empty {
			s.send(&pgproto3.EmptyQueryResponse{})
			continue
		}
		if r.hasRows {
			s.send(rowDescription(r.fields, nil))
			for _, row := range r.rows {
				s.send(&pgproto3.DataRow{Values: row})
			}
		}
		s.send(&pgproto3.CommandComplete{CommandTag: []byte(r.tag)})
	}
	s.send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
}

func (s *session) sendNotices(r *result) {
	for _, st := range r.status {
		s.send(st)
	}
	for _, n := range r.notices {
		if s.wantNotice(n.Severity) {
			s.send(n)
		}
	}
}

// noticeLevels orders client_min_messages values.
var noticeLevels = map[string]int{"debug": 0, "log": 1, "info": 2, "notice": 3, "warning": 4, "error": 5}

// wantNotice applies client_min_messages to notices (INFO is always sent,
// as in PostgreSQL).
func (s *session) wantNotice(severity string) bool {
	levels := noticeLevels
	min := strings.ToLower(s.params["client_min_messages"].value)
	if strings.HasPrefix(min, "debug") {
		min = "debug"
	}
	want, ok := levels[min]
	if !ok {
		want = levels["notice"]
	}
	return severity == "INFO" || levels[strings.ToLower(severity)] >= want
}

func rowDescription(fields []field, formats []int16) *pgproto3.RowDescription {
	rd := &pgproto3.RowDescription{Fields: make([]pgproto3.FieldDescription, len(fields))}
	for i, f := range fields {
		var format int16
		if formats != nil {
			format = formats[i]
		}
		rd.Fields[i] = pgproto3.FieldDescription{Name: []byte(f.name), DataTypeOID: f.oid, DataTypeSize: typeSize(f.oid),
			TypeModifier: -1, Format: format}
	}
	return rd
}

// ---------------------------------------------------------------------------
// Running statements

// run executes one statement, locally or through the gateway.
func (s *session) run(ctx context.Context, st *statement) *result {
	switch st.kind {
	case stmtEmpty:
		return &result{empty: true}
	case stmtSet:
		return s.execSet(st.node.GetVariableSetStmt())
	case stmtShow:
		return s.execShow(st.node.GetVariableShowStmt().GetName())
	case stmtTxn:
		return s.execTxn(st.node.GetTransactionStmt())
	case stmtDiscard:
		return s.execDiscard(st.node.GetDiscardStmt())
	case stmtDeallocate:
		return s.execDeallocate(st.node.GetDeallocateStmt())
	case stmtVersion:
		return execVersion(st.node.GetSelectStmt())
	case stmtConstSelect:
		return execConstSelect(st.node.GetSelectStmt())
	case stmtCopy:
		return errResult(pgError("0A000", "COPY は dbgateway のプロキシでは使えません。 / COPY is not supported by the dbgateway proxy.",
			"SELECT で必要な行を取得してください。"))
	}
	return s.runGateway(ctx, st)
}

func (s *session) runGateway(ctx context.Context, st *statement) *result {
	reason := s.effectiveReason()
	if reason == "" {
		return errResult(pgError("42501",
			"クエリの理由が設定されていません。dbgateway ではすべてのクエリに理由が必要です。 / No reason is set: dbgateway requires a reason for every query.",
			"先に SET dbgw.reason = '問い合わせ#1234の調査のため'; を実行してください（接続時の application_name に理由の文を書いても構いません）。"))
	}
	qctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.setRunning(cancel)
	defer s.setRunning(nil)
	resp := s.srv.gw.ExecuteSQL(qctx, s.p, gateway.ExecuteRequest{Database: s.database, SQL: st.sql, Reason: reason, TraceID: s.traceID})
	if resp == nil {
		return errResult(pgError("XX000", "internal error: no response from the gateway", ""))
	}
	s.log.Debug("pgproxy statement", "request_id", resp.RequestID, "status", resp.Status)
	if qctx.Err() != nil && ctx.Err() == nil && resp.Status != gateway.StatusOK {
		e := pgError("57014", "ユーザーの要求により文をキャンセルしました。 / canceling statement due to user request", "")
		e.Detail = "request_id: " + resp.RequestID
		return errResult(e)
	}
	return s.mapResponse(resp, st)
}

func (s *session) setRunning(cancel context.CancelFunc) {
	s.mu.Lock()
	s.running = cancel
	s.mu.Unlock()
}

// cancelRunning cancels the statement in progress, if any. It is called
// from another connection's goroutine (CancelRequest).
func (s *session) cancelRunning() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running != nil {
		s.running()
	}
}

// effectiveReason is SET dbgw.reason, else application_name when it reads
// like a sentence rather than a client name.
func (s *session) effectiveReason() string {
	if s.reason != "" {
		return s.reason
	}
	if app := strings.TrimSpace(s.params["application_name"].value); looksLikeReason(app) {
		return app
	}
	return ""
}

// knownClients are application_name prefixes set by clients themselves.
var knownClients = []string{
	"psql", "pgcli", "pg_dump", "pg_restore", "dbeaver", "pgadmin", "postgresql jdbc", "datagrip", "intellij",
	"goland", "pycharm", "tableplus", "navicat", "postico", "beekeeper", "azure data studio", "vscode", "metabase",
	"redash", "grafana", "superset", "pgx", "node-postgres", "psycopg", "npgsql", "sqlalchemy", "dbgw",
}

// looksLikeReason reports whether an application_name reads like a reason
// sentence: at least 8 characters, containing a space or non-ASCII text,
// and not a known client name.
func looksLikeReason(app string) bool {
	if len([]rune(app)) < 8 {
		return false
	}
	lower := strings.ToLower(app)
	for _, c := range knownClients {
		if strings.HasPrefix(lower, c) {
			return false
		}
	}
	return strings.ContainsFunc(app, func(r rune) bool { return r == ' ' || r > 0x7f })
}

// mapResponse converts a gateway response to protocol messages.
func (s *session) mapResponse(resp *gateway.ExecuteResponse, st *statement) *result {
	detail := "request_id: " + resp.RequestID
	switch resp.Status {
	case gateway.StatusOK:
		return s.okResult(resp, st, detail)
	case gateway.StatusDenied:
		msg := resp.Reason
		if msg == "" {
			msg = "dbgateway が実行を拒否しました。 / dbgateway denied the statement."
		}
		e := pgError("42501", msg, resp.Hint)
		e.Detail = detail
		if resp.Stage != "" {
			e.Detail += ", stage: " + resp.Stage
		}
		if resp.Rule != "" {
			e.Detail += ", rule: " + resp.Rule
		}
		return errResult(e)
	case gateway.StatusError:
		code := resp.Code
		if !validSQLState(code) {
			code = "XX000"
		}
		msg := resp.Reason
		if msg == "" {
			msg = "実行に失敗しました。 / The statement failed."
		}
		e := pgError(code, msg, resp.Hint)
		e.Detail = detail
		return errResult(e)
	case "pending":
		// Approval workflow: the statement was recorded and awaits approval.
		if url := responseField(resp, "approval_url"); url != "" {
			detail += ", approval_url: " + url
		}
		return &result{tag: st.commandTag(0), notices: []*pgproto3.NoticeResponse{notice("NOTICE",
			"この文は承認待ちです。承認されると dbgateway が実行します（まだ実行されていません）。 / This statement awaits approval and has not been executed yet.",
			detail, resp.Hint)}}
	}
	e := pgError("XX000", fmt.Sprintf("unexpected gateway status %q", resp.Status), "")
	e.Detail = detail
	return errResult(e)
}

func (s *session) okResult(resp *gateway.ExecuteResponse, st *statement, detail string) *result {
	r := &result{hasRows: st.rows || len(resp.Columns) > 0, tag: st.commandTag(len(resp.Rows))}
	var masked []string
	r.fields = make([]field, len(resp.Columns))
	for i, c := range resp.Columns {
		f := field{name: c.Name}
		if c.Masked || c.Withheld {
			// Masked values are strings and withheld ones NULL, whatever the
			// column type was.
			f.oid, f.typName = pgtype.TextOID, "text"
			state := "masked"
			if c.Withheld {
				state = "withheld"
			}
			if c.Class != "" {
				state += ", " + c.Class
			}
			masked = append(masked, fmt.Sprintf("%s (%s)", c.Name, state))
		} else {
			f.oid, f.typName = resolveType(s.types, c.Type)
		}
		r.fields[i] = f
	}
	r.rows = make([][][]byte, len(resp.Rows))
	for i, row := range resp.Rows {
		if len(row) != len(r.fields) {
			e := pgError("XX000", "結果の列数が一致しないため結果を返しません。 / Result shape mismatch; result withheld.", "")
			e.Detail = detail
			return errResult(e)
		}
		vals := make([][]byte, len(row))
		for j, v := range row {
			vals[j] = renderText(r.fields[j].typName, v)
		}
		r.rows[i] = vals
	}
	if len(masked) > 0 {
		r.notices = append(r.notices, notice("NOTICE",
			"一部の列はマスクまたは非表示（NULL）にしています: "+strings.Join(masked, ", ")+" / Some columns are masked or withheld.",
			detail, ""))
	}
	if resp.Truncated {
		msg := fmt.Sprintf("上限に達したため結果を%d行で打ち切りました。 / Result truncated to %d rows.", len(resp.Rows), len(resp.Rows))
		if resp.TotalRows != nil {
			msg = fmt.Sprintf("上限に達したため結果を%d行で打ち切りました（全%d行）。 / Result truncated to %d of %d rows.",
				len(resp.Rows), *resp.TotalRows, len(resp.Rows), *resp.TotalRows)
		}
		r.notices = append(r.notices, notice("WARNING", msg, detail, resp.Hint))
	}
	if resp.Notice != "" {
		r.notices = append(r.notices, notice("NOTICE", resp.Notice, "", ""))
	}
	return r
}

// validSQLState reports whether code is a five-character SQLSTATE.
func validSQLState(code string) bool {
	if len(code) != 5 {
		return false
	}
	for _, c := range code {
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}
