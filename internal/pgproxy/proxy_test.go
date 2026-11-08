package pgproxy

import (
	"context"
	"encoding/binary"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
)

func TestStartupAndAuthentication(t *testing.T) {
	addr := startProxy(t, &fakeGateway{}, proxyOpts{})

	c, ferr := connect(t, addr, defaultParams(), goodToken)
	if ferr != nil {
		t.Fatalf("startup failed: %+v", ferr)
	}
	want := map[string]string{
		"server_version": ServerVersion, "client_encoding": "UTF8", "DateStyle": "ISO, MDY", "integer_datetimes": "on",
		"standard_conforming_strings": "on", "TimeZone": "UTC", "application_name": "psql", "session_authorization": "taro",
	}
	for k, v := range want {
		if c.status[k] != v {
			t.Errorf("ParameterStatus %s = %q, want %q", k, c.status[k], v)
		}
	}
	if c.key == nil || c.key.ProcessID == 0 || len(c.key.SecretKey) != 4 {
		t.Errorf("BackendKeyData = %+v", c.key)
	}

	for _, tt := range []struct {
		name     string
		params   map[string]string
		password string
		code     string
	}{
		{"bad token", defaultParams(), "dbgw_at_wrong", "28P01"},
		{"empty password", defaultParams(), "", "28P01"},
		{"no scope", defaultParams(), "dbgw_at_noscope", "28000"},
		{"unknown database", map[string]string{"user": "taro", "database": "nope"}, goodToken, "3D000"},
		{"viewer only", map[string]string{"user": "taro", "database": "schema-only"}, goodToken, "3D000"},
		{"replication", map[string]string{"user": "taro", "database": "dev-main", "replication": "database"}, goodToken, "0A000"},
		{"encoding", map[string]string{"user": "taro", "database": "dev-main", "client_encoding": "LATIN1"}, goodToken, "22023"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, ferr := connect(t, addr, tt.params, tt.password)
			if ferr == nil || ferr.Code != tt.code || ferr.Severity != "FATAL" {
				t.Fatalf("got %+v, want FATAL %s", ferr, tt.code)
			}
		})
	}
}

func TestProtocolNegotiation(t *testing.T) {
	addr := startProxy(t, &fakeGateway{}, proxyOpts{})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	params := defaultParams()
	params["_pq_.something"] = "x"
	c, ferr := startupVersion(t, conn, pgproto3.ProtocolVersion32, params, goodToken)
	if ferr != nil {
		t.Fatal(ferr)
	}
	if c.npv == nil || c.npv.NewestMinorProtocol != 0 || !slices.Equal(c.npv.UnrecognizedOptions, []string{"_pq_.something"}) {
		t.Errorf("NegotiateProtocolVersion = %+v", c.npv)
	}
	if len(c.key.SecretKey) != 4 {
		t.Errorf("protocol 3.0 needs a 4-byte secret key, got %d", len(c.key.SecretKey))
	}
}

func TestSimpleQueryResultMapping(t *testing.T) {
	total := int64(250)
	gw := &fakeGateway{fn: func(_ context.Context, req gateway.ExecuteRequest) *gateway.ExecuteResponse {
		return &gateway.ExecuteResponse{
			Status: gateway.StatusOK, RequestID: "req_abc", Notice: gateway.DataNotice,
			Columns: []gateway.ResultColumn{
				{Name: "id", Type: "int8"},
				{Name: "email", Type: "text", Masked: true, Class: "masked"},
				{Name: "created_at", Type: "timestamptz"},
				{Name: "amount", Type: "numeric"},
				{Name: "tags", Type: "_text"},
				{Name: "ok", Type: "bool"},
				{Name: "body", Type: "text", Withheld: true, Class: "no_ai"},
				{Name: "meta", Type: "jsonb"},
				{Name: "ratio", Type: "float8"},
				{Name: "mood", Type: "my_enum"},
				{Name: "api_token", Type: "int8", Masked: true},
			},
			Rows: [][]any{
				{int64(1), "u***@example.com", "2026-11-08T21:00:00.5+09:00", "12.50", []any{"a", "b c", nil}, true, nil,
					map[string]any{"k": "<v>"}, 0.25, "happy", "****"},
			},
			RowCount: 1, Truncated: true, TotalRows: &total, Hint: "条件を絞ってください",
		}
	}}
	addr := startProxy(t, gw, proxyOpts{})
	c, _ := connect(t, addr, defaultParams(), goodToken)

	msgs := c.query("SET dbgw.reason = 'ticket #1234: check the user plan'; SELECT * FROM users WHERE id = 1")
	reqs := gw.requests()
	if len(reqs) != 1 {
		t.Fatalf("gateway calls = %d", len(reqs))
	}
	if reqs[0].SQL != "SELECT * FROM users WHERE id = 1" || reqs[0].Reason != "ticket #1234: check the user plan" ||
		reqs[0].Database != "dev-main" || !strings.HasPrefix(reqs[0].TraceID, "pgproxy_") {
		t.Errorf("request = %+v", reqs[0])
	}
	if got := tags(msgs); !slices.Equal(got, []string{"SET", "SELECT 1"}) {
		t.Errorf("tags = %v", got)
	}
	rd := find[*pgproto3.RowDescription](msgs)
	if len(rd) != 1 {
		t.Fatalf("messages = %v", types(msgs))
	}
	wantOIDs := []uint32{pgtype.Int8OID, pgtype.TextOID, pgtype.TimestamptzOID, pgtype.NumericOID, pgtype.TextArrayOID,
		pgtype.BoolOID, pgtype.TextOID, pgtype.JSONBOID, pgtype.Float8OID, pgtype.TextOID, pgtype.TextOID}
	for i, f := range rd[0].Fields {
		if f.DataTypeOID != wantOIDs[i] || f.Format != 0 {
			t.Errorf("field %s: oid %d format %d, want oid %d", f.Name, f.DataTypeOID, f.Format, wantOIDs[i])
		}
	}
	rows := find[*pgproto3.DataRow](msgs)
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	want := []string{"1", "u***@example.com", "2026-11-08 12:00:00.5+00", "12.50", `{a,"b c",NULL}`, "t", "<NULL>",
		`{"k":"<v>"}`, "0.25", "happy", "****"}
	for i, v := range rows[0].Values {
		got := string(v)
		if v == nil {
			got = "<NULL>"
		}
		if got != want[i] {
			t.Errorf("value %d = %q, want %q", i, got, want[i])
		}
	}
	var noticeText []string
	for _, n := range find[*pgproto3.NoticeResponse](msgs) {
		noticeText = append(noticeText, n.Severity+": "+n.Message+" | "+n.Detail)
	}
	joined := strings.Join(noticeText, "\n")
	for _, s := range []string{"email (masked, masked)", "body (withheld, no_ai)", "api_token (masked)", "1 of 250", gateway.DataNotice, "request_id: req_abc"} {
		if !strings.Contains(joined, s) {
			t.Errorf("notices missing %q:\n%s", s, joined)
		}
	}
	if !slices.Contains(types(msgs), "ReadyForQuery") {
		t.Error("no ReadyForQuery")
	}
}

func TestDenialAndErrorMapping(t *testing.T) {
	gw := &fakeGateway{fn: func(_ context.Context, req gateway.ExecuteRequest) *gateway.ExecuteResponse {
		switch {
		case strings.Contains(req.SQL, "deny"):
			return &gateway.ExecuteResponse{Status: gateway.StatusDenied, RequestID: "req_denied", Stage: "policy", Rule: "deny-ddl",
				Reason: "DDL は実行できません", Hint: "SELECT を使ってください"}
		case strings.Contains(req.SQL, "fail"):
			return &gateway.ExecuteResponse{Status: gateway.StatusError, RequestID: "req_err", Reason: "relation does not exist", Code: "42P01"}
		case strings.Contains(req.SQL, "boom"):
			return &gateway.ExecuteResponse{Status: gateway.StatusError, RequestID: "req_boom", Reason: "database unavailable"}
		case strings.Contains(req.SQL, "approve"):
			return &gateway.ExecuteResponse{Status: "pending", RequestID: "req_pending"}
		}
		return nil
	}}
	addr := startProxy(t, gw, proxyOpts{})
	c, _ := connect(t, addr, map[string]string{"user": "taro", "database": "dev-main", "application_name": "問い合わせ#1234の調査のため"}, goodToken)

	msgs := c.query("SELECT deny FROM t; SELECT 'not reached' FROM t")
	e := errorOf(t, msgs)
	if e.Severity != "ERROR" || e.Code != "42501" || e.Message != "DDL は実行できません" || e.Hint != "SELECT を使ってください" ||
		!strings.Contains(e.Detail, "req_denied") || !strings.Contains(e.Detail, "deny-ddl") {
		t.Errorf("denial = %+v", e)
	}
	if n := len(gw.requests()); n != 1 {
		t.Errorf("statements after an error must not run; gateway calls = %d", n)
	}
	if gw.requests()[0].Reason != "問い合わせ#1234の調査のため" {
		t.Errorf("application_name was not used as the reason: %q", gw.requests()[0].Reason)
	}

	e = errorOf(t, c.query("SELECT fail FROM t"))
	if e.Code != "42P01" || !strings.Contains(e.Detail, "req_err") {
		t.Errorf("error = %+v", e)
	}
	e = errorOf(t, c.query("SELECT boom FROM t"))
	if e.Code != "XX000" {
		t.Errorf("error without code = %+v", e)
	}

	msgs = c.query("UPDATE approve SET x = 1")
	if got := tags(msgs); !slices.Equal(got, []string{"UPDATE 0"}) {
		t.Errorf("pending tags = %v (%v)", got, types(msgs))
	}
	if n := find[*pgproto3.NoticeResponse](msgs); len(n) != 1 || !strings.Contains(n[0].Detail, "req_pending") {
		t.Errorf("pending notice = %+v", n)
	}
}

func TestMultiStatementSplit(t *testing.T) {
	gw := &fakeGateway{}
	addr := startProxy(t, gw, proxyOpts{})
	c, _ := connect(t, addr, defaultParams(), goodToken)
	msgs := c.query("SET dbgw.reason TO 'compare plan counts for ticket 42';\nSELECT count(*) FROM a; -- first\n SELECT 'x;y' FROM b;;")
	var sqls []string
	for _, r := range gw.requests() {
		sqls = append(sqls, r.SQL)
	}
	if !slices.Equal(sqls, []string{"SELECT count(*) FROM a", "-- first\n SELECT 'x;y' FROM b"}) {
		t.Errorf("statements = %q", sqls)
	}
	if got := tags(msgs); !slices.Equal(got, []string{"SET", "SELECT 1", "SELECT 1"}) {
		t.Errorf("tags = %v", got)
	}
	for _, r := range gw.requests() {
		if r.Reason != "compare plan counts for ticket 42" {
			t.Errorf("reason = %q", r.Reason)
		}
	}
}

func TestReasonRequired(t *testing.T) {
	gw := &fakeGateway{}
	addr := startProxy(t, gw, proxyOpts{})
	c, _ := connect(t, addr, defaultParams(), goodToken) // application_name=psql is not a reason

	e := errorOf(t, c.query("SELECT id FROM users"))
	if e.Code != "42501" || !strings.Contains(e.Hint, "SET dbgw.reason") {
		t.Errorf("error = %+v", e)
	}
	if len(gw.requests()) != 0 {
		t.Error("the gateway must not be called without a reason")
	}
	c.query("SET dbgw.reason = 'checking churn for ticket 7'")
	if msgs := c.query("SHOW dbgw.reason"); string(find[*pgproto3.DataRow](msgs)[0].Values[0]) != "checking churn for ticket 7" {
		t.Errorf("SHOW dbgw.reason = %v", types(msgs))
	}
	c.query("SELECT id FROM users")
	c.query("RESET dbgw.reason")
	errorOf(t, c.query("SELECT id FROM users"))
	if n := len(gw.requests()); n != 1 {
		t.Errorf("gateway calls = %d, want 1", n)
	}

	for app, want := range map[string]bool{
		"psql": false, "DBeaver 24.1.0 - Main": false, "PostgreSQL JDBC Driver": false, "short ok": true,
		"investigate ticket 12": true, "問い合わせの調査": true, "abc": false, "no_spaces_here": false,
	} {
		if got := looksLikeReason(app); got != want {
			t.Errorf("looksLikeReason(%q) = %v", app, got)
		}
	}
}

func TestLocalStatements(t *testing.T) {
	gw := &fakeGateway{}
	addr := startProxy(t, gw, proxyOpts{})
	c, _ := connect(t, addr, defaultParams(), goodToken)

	msgs := c.query("SHOW server_version")
	if rows := find[*pgproto3.DataRow](msgs); len(rows) != 1 || string(rows[0].Values[0]) != ServerVersion {
		t.Errorf("SHOW server_version = %v", types(msgs))
	}
	if rd := find[*pgproto3.RowDescription](msgs); string(rd[0].Fields[0].Name) != "server_version" {
		t.Errorf("column = %s", rd[0].Fields[0].Name)
	}
	if rows := find[*pgproto3.DataRow](c.query("SHOW TimeZone")); string(rows[0].Values[0]) != "UTC" {
		t.Error("SHOW TimeZone")
	}
	if e := errorOf(t, c.query("SHOW work_mem")); e.Code != "42704" {
		t.Errorf("SHOW unknown = %+v", e)
	}
	if rows := find[*pgproto3.DataRow](c.query("SHOW ALL")); len(rows) < 10 {
		t.Errorf("SHOW ALL rows = %d", len(rows))
	}

	if e := errorOf(t, c.query("SET search_path = evil, public")); e.Code != "42501" {
		t.Errorf("SET search_path = %+v", e)
	}
	if e := errorOf(t, c.query("SET role postgres")); e.Code != "0A000" {
		t.Errorf("SET role = %+v", e)
	}
	if e := errorOf(t, c.query("SET client_encoding = 'LATIN1'")); e.Code != "22023" {
		t.Errorf("SET client_encoding = %+v", e)
	}

	msgs = c.query("SET client_encoding = 'UTF8'; SET extra_float_digits = 3; SET DateStyle = ISO, MDY; SET application_name = 'DBeaver 24'")
	if got := tags(msgs); !slices.Equal(got, []string{"SET", "SET", "SET", "SET"}) {
		t.Errorf("tags = %v %v", got, types(msgs))
	}
	if ps := find[*pgproto3.ParameterStatus](msgs); len(ps) != 1 || ps[0].Name != "application_name" || ps[0].Value != "DBeaver 24" {
		t.Errorf("ParameterStatus = %+v", ps)
	}
	if rows := find[*pgproto3.DataRow](c.query("SHOW extra_float_digits")); string(rows[0].Values[0]) != "3" {
		t.Error("extra_float_digits not stored")
	}

	msgs = c.query("BEGIN; COMMIT; ROLLBACK")
	if got := tags(msgs); !slices.Equal(got, []string{"BEGIN", "COMMIT", "ROLLBACK"}) {
		t.Errorf("tags = %v", got)
	}
	if n := find[*pgproto3.NoticeResponse](msgs); len(n) != 1 || !strings.Contains(n[0].Message, "own transaction") {
		t.Errorf("BEGIN notice = %+v", n)
	}
	if rfq := find[*pgproto3.ReadyForQuery](msgs); rfq[0].TxStatus != 'I' {
		t.Errorf("TxStatus = %c", rfq[0].TxStatus)
	}
	if e := errorOf(t, c.query("SAVEPOINT a")); e.Code != "0A000" {
		t.Errorf("SAVEPOINT = %+v", e)
	}

	msgs = c.query("SELECT version()")
	if rows := find[*pgproto3.DataRow](msgs); len(rows) != 1 || !strings.HasPrefix(string(rows[0].Values[0]), "PostgreSQL 17") {
		t.Errorf("version = %v", types(msgs))
	}
	msgs = c.query("SELECT 1 AS ok, 2")
	rd := find[*pgproto3.RowDescription](msgs)
	if rows := find[*pgproto3.DataRow](msgs); len(rows) != 1 || string(rows[0].Values[1]) != "2" ||
		string(rd[0].Fields[0].Name) != "ok" || rd[0].Fields[0].DataTypeOID != pgtype.Int4OID {
		t.Errorf("SELECT 1 = %v", types(msgs))
	}
	if got := types(c.query("  ; -- nothing\n")); !slices.Equal(got, []string{"EmptyQueryResponse", "ReadyForQuery"}) {
		t.Errorf("empty query = %v", got)
	}
	if e := errorOf(t, c.query("COPY users TO STDOUT")); e.Code != "0A000" {
		t.Errorf("COPY = %+v", e)
	}
	msgs = c.untilReady(&pgproto3.FunctionCall{Function: 1234})
	if e := errorOf(t, msgs); e.Code != "0A000" {
		t.Errorf("FunctionCall = %+v", e)
	}
	if got := tags(c.query("DISCARD ALL")); !slices.Equal(got, []string{"DISCARD ALL"}) {
		t.Errorf("DISCARD = %v", got)
	}
	if len(gw.requests()) != 0 {
		t.Errorf("local statements reached the gateway: %+v", gw.requests())
	}
}

func TestExtendedProtocol(t *testing.T) {
	gw := &fakeGateway{fn: func(_ context.Context, req gateway.ExecuteRequest) *gateway.ExecuteResponse {
		return &gateway.ExecuteResponse{Status: gateway.StatusOK, RequestID: "req_x",
			Columns: []gateway.ResultColumn{{Name: "id", Type: "int8"}, {Name: "name", Type: "text"}, {Name: "at", Type: "timestamptz"}},
			Rows:    [][]any{{int64(7), "seven", "2026-11-08T00:00:00Z"}, {int64(8), nil, nil}, {int64(9), "nine", nil}}, RowCount: 3}
	}}
	addr := startProxy(t, gw, proxyOpts{})
	c, _ := connect(t, addr, map[string]string{"user": "taro", "database": "dev-main", "application_name": "extended protocol test"}, goodToken)

	// Prepare: Parse + Describe statement (as pgx does).
	msgs := c.untilReady(&pgproto3.Parse{Name: "s1", Query: "SELECT id, name, at FROM users"}, &pgproto3.Describe{ObjectType: 'S', Name: "s1"}, &pgproto3.Sync{})
	if got := types(msgs); !slices.Equal(got, []string{"ParseComplete", "ParameterDescription", "RowDescription", "ReadyForQuery"}) {
		t.Fatalf("prepare = %v", got)
	}
	// Bind with binary results for every column, then Execute.
	msgs = c.untilReady(&pgproto3.Bind{PreparedStatement: "s1", ResultFormatCodes: []int16{1}}, &pgproto3.Describe{ObjectType: 'P'},
		&pgproto3.Execute{}, &pgproto3.Sync{})
	if got := types(msgs); !slices.Equal(got, []string{"BindComplete", "RowDescription", "DataRow", "DataRow", "DataRow", "CommandComplete", "ReadyForQuery"}) {
		t.Fatalf("execute = %v", got)
	}
	if n := len(gw.requests()); n != 1 {
		t.Errorf("Describe + Execute must run the statement once; gateway calls = %d", n)
	}
	rd := find[*pgproto3.RowDescription](msgs)[0]
	if rd.Fields[0].Format != 1 || rd.Fields[0].DataTypeOID != pgtype.Int8OID {
		t.Errorf("portal description = %+v", rd.Fields[0])
	}
	row := find[*pgproto3.DataRow](msgs)[0]
	if len(row.Values[0]) != 8 || binary.BigEndian.Uint64(row.Values[0]) != 7 || string(row.Values[1]) != "seven" {
		t.Errorf("binary row = %v", row.Values)
	}
	var ts time.Time
	if err := pgtype.NewMap().Scan(pgtype.TimestamptzOID, pgtype.BinaryFormatCode, row.Values[2], &ts); err != nil || !ts.Equal(time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("binary timestamptz = %v, %v", ts, err)
	}
	if find[*pgproto3.DataRow](msgs)[1].Values[1] != nil {
		t.Error("NULL must stay NULL")
	}

	// Re-executing the statement runs it again; MaxRows suspends the portal.
	msgs = c.untilReady(&pgproto3.Bind{PreparedStatement: "s1"}, &pgproto3.Execute{MaxRows: 2}, &pgproto3.Execute{}, &pgproto3.Sync{})
	if got := types(msgs); !slices.Equal(got, []string{"BindComplete", "DataRow", "DataRow", "PortalSuspended", "DataRow", "CommandComplete", "ReadyForQuery"}) {
		t.Errorf("suspended = %v", got)
	}
	if n := len(gw.requests()); n != 2 {
		t.Errorf("gateway calls = %d, want 2", n)
	}

	// Local statements and empty statements work too.
	msgs = c.untilReady(&pgproto3.Parse{Query: "SET dbgw.reason = 'extended reason text'"}, &pgproto3.Bind{}, &pgproto3.Describe{ObjectType: 'P'},
		&pgproto3.Execute{}, &pgproto3.Parse{Query: ""}, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
	if got := types(msgs); !slices.Equal(got, []string{"ParseComplete", "BindComplete", "NoData", "CommandComplete", "ParseComplete", "BindComplete", "EmptyQueryResponse", "ReadyForQuery"}) {
		t.Errorf("local = %v", got)
	}
	c.untilReady(&pgproto3.Parse{Query: "SELECT a FROM t"}, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
	if r := gw.requests(); r[len(r)-1].Reason != "extended reason text" {
		t.Errorf("reason = %q", r[len(r)-1].Reason)
	}

	// Writes are never executed by Describe.
	before := len(gw.requests())
	msgs = c.untilReady(&pgproto3.Parse{Query: "DELETE FROM t"}, &pgproto3.Describe{ObjectType: 'S'}, &pgproto3.Sync{})
	if got := types(msgs); !slices.Equal(got, []string{"ParseComplete", "ParameterDescription", "NoData", "ReadyForQuery"}) || len(gw.requests()) != before {
		t.Errorf("describe write = %v", got)
	}

	// Close.
	msgs = c.untilReady(&pgproto3.Close{ObjectType: 'S', Name: "s1"}, &pgproto3.Bind{PreparedStatement: "s1"}, &pgproto3.Sync{})
	if got := types(msgs); !slices.Equal(got, []string{"CloseComplete", "ErrorResponse", "ReadyForQuery"}) {
		t.Errorf("close = %v", got)
	}
}

func TestExtendedProtocolRejections(t *testing.T) {
	gw := &fakeGateway{}
	addr := startProxy(t, gw, proxyOpts{})
	c, _ := connect(t, addr, map[string]string{"user": "taro", "database": "dev-main", "application_name": "extended protocol test"}, goodToken)

	// A parameterized statement fails at Parse; later messages are ignored
	// until Sync.
	msgs := c.untilReady(&pgproto3.Parse{Query: "SELECT * FROM users WHERE id = $1"}, &pgproto3.Bind{Parameters: [][]byte{[]byte("1")}},
		&pgproto3.Execute{}, &pgproto3.Sync{})
	if got := types(msgs); !slices.Equal(got, []string{"ErrorResponse", "ReadyForQuery"}) {
		t.Fatalf("got %v", got)
	}
	if e := errorOf(t, msgs); e.Code != "0A000" || !strings.Contains(e.Hint, "simple_protocol") {
		t.Errorf("error = %+v", e)
	}
	if e := errorOf(t, c.untilReady(&pgproto3.Parse{Query: "SELECT 1", ParameterOIDs: []uint32{23}}, &pgproto3.Sync{})); e.Code != "0A000" {
		t.Errorf("parameter OIDs = %+v", e)
	}
	msgs = c.untilReady(&pgproto3.Parse{Query: "SELECT id FROM users"}, &pgproto3.Bind{Parameters: [][]byte{[]byte("1")}}, &pgproto3.Sync{})
	if e := errorOf(t, msgs); e.Code != "0A000" {
		t.Errorf("bind parameters = %+v", e)
	}
	if e := errorOf(t, c.untilReady(&pgproto3.Parse{Query: "SELECT 1; SELECT 2"}, &pgproto3.Sync{})); e.Code != "42601" {
		t.Errorf("multiple statements = %+v", e)
	}
	if e := errorOf(t, c.untilReady(&pgproto3.Parse{Query: "COPY t FROM STDIN"}, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})); e.Code != "0A000" {
		t.Errorf("COPY = %+v", e)
	}
	if len(gw.requests()) != 0 {
		t.Errorf("gateway calls = %d", len(gw.requests()))
	}
	// The connection is still usable.
	if got := tags(c.query("SELECT n FROM t")); !slices.Equal(got, []string{"SELECT 1"}) {
		t.Errorf("tags = %v", got)
	}
}

func TestTLS(t *testing.T) {
	certFile, keyFile, pool := writeTestCert(t)

	t.Run("refuses non-loopback without TLS", func(t *testing.T) {
		srv, err := New(Options{Config: &config.Config{}, Gateway: &fakeGateway{}, Authenticate: fakeAuth})
		if err != nil {
			t.Fatal(err)
		}
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		if err := srv.Serve(context.Background(), publicListener{ln}); err == nil || !strings.Contains(err.Error(), "without TLS") {
			t.Fatalf("Serve = %v", err)
		}
		srv.cfg.PGProxy.Listen = "0.0.0.0:0"
		if err := srv.ListenAndServe(context.Background()); err == nil {
			t.Fatal("ListenAndServe on 0.0.0.0 without TLS must fail")
		}
	})

	pc := config.PGProxy{TLSCert: certFile, TLSKey: keyFile}
	addr := startProxy(t, &fakeGateway{}, proxyOpts{pc: pc, wrap: func(ln net.Listener) net.Listener { return publicListener{ln} }})

	t.Run("plaintext rejected on non-loopback", func(t *testing.T) {
		_, ferr := connect(t, addr, defaultParams(), goodToken)
		if ferr == nil || ferr.Code != "28000" || !strings.Contains(ferr.Message, "TLS") {
			t.Fatalf("got %+v", ferr)
		}
	})
	t.Run("TLS accepted", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if b := sslRequest(t, conn); b != 'S' {
			t.Fatalf("SSLRequest answer = %q", b)
		}
		tc := tlsClient(conn, pool)
		c, ferr := startup(t, tc, defaultParams(), goodToken)
		if ferr != nil {
			t.Fatalf("startup over TLS: %+v", ferr)
		}
		if got := tags(c.query("SELECT 1")); !slices.Equal(got, []string{"SELECT 1"}) {
			t.Errorf("tags = %v", got)
		}
	})
	t.Run("SSL declined without TLS on loopback", func(t *testing.T) {
		addr := startProxy(t, &fakeGateway{}, proxyOpts{})
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if b := sslRequest(t, conn); b != 'N' {
			t.Fatalf("SSLRequest answer = %q", b)
		}
		if _, ferr := startup(t, conn, defaultParams(), goodToken); ferr != nil {
			t.Fatalf("startup after N: %+v", ferr)
		}
	})
}

func TestCancelRequest(t *testing.T) {
	started := make(chan struct{})
	gw := &fakeGateway{fn: func(ctx context.Context, req gateway.ExecuteRequest) *gateway.ExecuteResponse {
		close(started)
		<-ctx.Done()
		return &gateway.ExecuteResponse{Status: gateway.StatusError, RequestID: "req_slow", Reason: "canceled"}
	}}
	addr := startProxy(t, gw, proxyOpts{})
	c, _ := connect(t, addr, map[string]string{"user": "taro", "database": "dev-main", "application_name": "cancel request test"}, goodToken)

	c.fe.Send(&pgproto3.Query{String: "SELECT pg_sleep_for_ever FROM t"})
	c.flush()
	<-started

	// A wrong key is ignored; the right one cancels.
	for _, secret := range [][]byte{{0, 0, 0, 0}, c.key.SecretKey} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		buf, _ := (&pgproto3.CancelRequest{ProcessID: c.key.ProcessID, SecretKey: secret}).Encode(nil)
		_, _ = conn.Write(buf)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var b [1]byte
		if _, err := conn.Read(b[:]); err == nil {
			t.Error("the server must close a cancel connection without replying")
		}
		conn.Close()
	}
	var msgs []pgproto3.BackendMessage
	for {
		m := c.recv()
		msgs = append(msgs, m)
		if _, ok := m.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}
	if e := errorOf(t, msgs); e.Code != "57014" || !strings.Contains(e.Detail, "req_slow") {
		t.Errorf("error = %+v", e)
	}
}

func TestConnectionLimitsAndTimeouts(t *testing.T) {
	t.Run("max connections", func(t *testing.T) {
		addr := startProxy(t, &fakeGateway{}, proxyOpts{pc: config.PGProxy{MaxConnections: 1}})
		if _, ferr := connect(t, addr, defaultParams(), goodToken); ferr != nil {
			t.Fatal(ferr)
		}
		_, ferr := connect(t, addr, defaultParams(), goodToken)
		if ferr == nil || ferr.Code != "53300" {
			t.Fatalf("got %+v", ferr)
		}
	})
	t.Run("idle timeout", func(t *testing.T) {
		addr := startProxy(t, &fakeGateway{}, proxyOpts{pc: config.PGProxy{IdleTimeout: config.Duration(200 * time.Millisecond)}})
		c, _ := connect(t, addr, defaultParams(), goodToken)
		e, ok := c.recv().(*pgproto3.ErrorResponse)
		if !ok || e.Code != "57P05" {
			t.Fatalf("got %+v", e)
		}
	})
	t.Run("message too large", func(t *testing.T) {
		addr := startProxy(t, &fakeGateway{}, proxyOpts{})
		c, _ := connect(t, addr, defaultParams(), goodToken)
		// Only the header is sent: the server must refuse before reading the body.
		hdr := []byte{'Q', 0, 0, 0, 0}
		binary.BigEndian.PutUint32(hdr[1:], maxMessageSize+5)
		if _, err := c.conn.Write(hdr); err != nil {
			t.Fatal(err)
		}
		e, ok := c.recv().(*pgproto3.ErrorResponse)
		if !ok || e.Code != "54000" {
			t.Fatalf("got %+v", e)
		}
	})
	t.Run("terminate", func(t *testing.T) {
		addr := startProxy(t, &fakeGateway{}, proxyOpts{})
		c, _ := connect(t, addr, defaultParams(), goodToken)
		c.fe.Send(&pgproto3.Terminate{})
		c.flush()
		if _, err := c.fe.Receive(); err == nil {
			t.Fatal("connection still open after Terminate")
		}
	})
}
