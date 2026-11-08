package pgproxy

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
)

// Extended query protocol, for statements without parameters.
//
// The gateway executes a statement as a whole and returns its rows, so the
// columns of a statement are only known once it has run. Describe therefore
// runs row-returning statements (plain SELECT, SHOW, EXPLAIN) and caches the
// result for the following Bind/Execute, so that each Describe+Execute
// cycle runs the statement once. Statements with possible side effects are
// never run by Describe: it answers NoData for them.

func errParameters() *pgproto3.ErrorResponse {
	return pgError("0A000",
		"パラメータ付きの文（$1 など）は dbgateway のプロキシでは使えません。 / Statements with parameters are not supported by the dbgateway proxy.",
		"値を SQL に直接書いてください（監査ログでは値は伏せられます）。pgx なら default_query_exec_mode=simple_protocol、JDBC なら preferQueryMode=simple が使えます。")
}

func (s *session) parse(m *pgproto3.Parse) *pgproto3.ErrorResponse {
	if m.Name != "" {
		if _, dup := s.stmts[m.Name]; dup {
			return pgError("42P05", fmt.Sprintf("prepared statement %q already exists", m.Name), "")
		}
	}
	if len(m.ParameterOIDs) > 0 || hasParameters(m.Query) {
		return errParameters()
	}
	var st *statement
	switch parts := splitStatements(m.Query); len(parts) {
	case 0:
		st = &statement{kind: stmtEmpty}
	case 1:
		st = classify(parts[0])
	default:
		return pgError("42601", "cannot insert multiple commands into a prepared statement", "")
	}
	s.stmts[m.Name] = &prepared{st: st}
	s.send(&pgproto3.ParseComplete{})
	return nil
}

func (s *session) bind(m *pgproto3.Bind) *pgproto3.ErrorResponse {
	ps, ok := s.stmts[m.PreparedStatement]
	if !ok {
		return pgError("26000", fmt.Sprintf("prepared statement %q does not exist", m.PreparedStatement), "")
	}
	if len(m.Parameters) > 0 {
		return errParameters()
	}
	for _, f := range m.ResultFormatCodes {
		if f != pgtype.TextFormatCode && f != pgtype.BinaryFormatCode {
			return pgError("08P01", fmt.Sprintf("unsupported format code: %d", f), "")
		}
	}
	if m.DestinationPortal != "" {
		if _, dup := s.portals[m.DestinationPortal]; dup {
			return pgError("42P03", fmt.Sprintf("cursor %q already exists", m.DestinationPortal), "")
		}
	}
	p := &portal{st: ps.st, formats: slices.Clone(m.ResultFormatCodes)}
	if ps.described != nil && time.Since(ps.describedAt) < describeCacheTTL {
		p.res = ps.described
	}
	ps.described = nil
	s.portals[m.DestinationPortal] = p
	s.send(&pgproto3.BindComplete{})
	return nil
}

func (s *session) describe(ctx context.Context, m *pgproto3.Describe) *pgproto3.ErrorResponse {
	switch m.ObjectType {
	case 'S':
		ps, ok := s.stmts[m.Name]
		if !ok {
			return pgError("26000", fmt.Sprintf("prepared statement %q does not exist", m.Name), "")
		}
		s.send(&pgproto3.ParameterDescription{})
		if !ps.st.rows {
			s.send(&pgproto3.NoData{})
			return nil
		}
		if ps.described == nil || time.Since(ps.describedAt) >= describeCacheTTL {
			ps.described, ps.describedAt = s.run(ctx, ps.st), time.Now()
		}
		r := ps.described
		if r.err != nil {
			ps.described = nil
			s.sendNotices(r)
			return r.err
		}
		if !r.hasRows {
			s.send(&pgproto3.NoData{})
			return nil
		}
		s.send(rowDescription(r.fields, nil))
		return nil
	case 'P':
		p, ok := s.portals[m.Name]
		if !ok {
			return pgError("34000", fmt.Sprintf("portal %q does not exist", m.Name), "")
		}
		if p.res == nil {
			if !p.st.rows {
				p.describedNoData = true
				s.send(&pgproto3.NoData{})
				return nil
			}
			p.res = s.run(ctx, p.st)
		}
		r := p.res
		if r.err != nil {
			s.sendPortalNotices(p)
			return r.err
		}
		if !r.hasRows {
			s.send(&pgproto3.NoData{})
			return nil
		}
		formats, errResp := resolveFormats(p.formats, len(r.fields))
		if errResp != nil {
			return errResp
		}
		s.send(rowDescription(r.fields, formats))
		return nil
	}
	return pgError("08P01", fmt.Sprintf("invalid DESCRIBE message subtype %d", m.ObjectType), "")
}

func (s *session) sendPortalNotices(p *portal) {
	if !p.noticesSent {
		p.noticesSent = true
		s.sendNotices(p.res)
	}
}

func (s *session) execute(ctx context.Context, m *pgproto3.Execute) *pgproto3.ErrorResponse {
	p, ok := s.portals[m.Portal]
	if !ok {
		return pgError("34000", fmt.Sprintf("portal %q does not exist", m.Portal), "")
	}
	if p.res == nil {
		p.res = s.run(ctx, p.st)
	}
	r := p.res
	s.sendPortalNotices(p)
	if r.err != nil {
		return r.err
	}
	if r.empty {
		s.send(&pgproto3.EmptyQueryResponse{})
		return nil
	}
	if r.hasRows {
		if p.describedNoData && len(r.fields) > 0 {
			return pgError("0A000", "この文は行を返しましたが、Describe では行を返さないと応答済みです。簡易問い合わせプロトコルで実行してください。 / The statement returned rows after Describe reported none; use the simple query protocol.", "")
		}
		formats, errResp := resolveFormats(p.formats, len(r.fields))
		if errResp != nil {
			return errResp
		}
		end := len(r.rows)
		if m.MaxRows > 0 && end-p.pos > int(m.MaxRows) {
			end = p.pos + int(m.MaxRows)
		}
		for _, row := range r.rows[p.pos:end] {
			vals, errResp := s.encodeRow(r.fields, formats, row)
			if errResp != nil {
				return errResp
			}
			s.send(&pgproto3.DataRow{Values: vals})
		}
		p.pos = end
		if end < len(r.rows) {
			s.send(&pgproto3.PortalSuspended{})
			return nil
		}
	}
	s.send(&pgproto3.CommandComplete{CommandTag: []byte(r.tag)})
	return nil
}

func (s *session) closeObject(m *pgproto3.Close) *pgproto3.ErrorResponse {
	switch m.ObjectType {
	case 'S':
		delete(s.stmts, m.Name)
	case 'P':
		delete(s.portals, m.Name)
	default:
		return pgError("08P01", fmt.Sprintf("invalid CLOSE message subtype %d", m.ObjectType), "")
	}
	s.send(&pgproto3.CloseComplete{})
	return nil
}

// resolveFormats expands Bind result format codes to one per column.
func resolveFormats(codes []int16, n int) ([]int16, *pgproto3.ErrorResponse) {
	out := make([]int16, n)
	switch len(codes) {
	case 0:
	case 1:
		for i := range out {
			out[i] = codes[0]
		}
	case n:
		copy(out, codes)
	default:
		return nil, pgError("08P01", fmt.Sprintf("bind message has %d result formats but query has %d columns", len(codes), n), "")
	}
	return out, nil
}

func (s *session) encodeRow(fields []field, formats []int16, row [][]byte) ([][]byte, *pgproto3.ErrorResponse) {
	vals := make([][]byte, len(row))
	for i, v := range row {
		out, err := encodeValue(s.types, fields[i], formats[i], v)
		if err != nil {
			return nil, pgError("0A000",
				fmt.Sprintf("列 %q をバイナリ形式で返せません。 / Cannot send column %q in binary format.", fields[i].name, fields[i].name),
				"結果をテキスト形式で要求してください。")
		}
		vals[i] = out
	}
	return vals, nil
}
