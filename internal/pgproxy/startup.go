package pgproxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// Startup packet request codes (protocol.sgml).
const (
	sslRequestCode    = 80877103
	gssEncRequestCode = 80877104
	cancelRequestCode = 80877102
	maxStartupPacket  = 10_000
)

// errUnsupportedVersion is returned for startup packets of protocol 2 or
// older.
var errUnsupportedVersion = errors.New("unsupported frontend protocol")

// startupPacket is a decoded startup-phase message. For StartupMessage,
// minor is the protocol minor version the client asked for.
type startupPacket struct {
	msg   pgproto3.FrontendMessage
	minor uint16
}

// readStartup reads one startup-phase packet using exact-length reads, so
// that nothing beyond it is buffered: bytes a client sends before the TLS
// handshake must never be interpreted after it.
func readStartup(r io.Reader) (*startupPacket, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(int32(binary.BigEndian.Uint32(hdr[:]))) - 4
	if n < 4 || n > maxStartupPacket {
		return nil, fmt.Errorf("invalid startup packet length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	code := binary.BigEndian.Uint32(buf)
	var m interface {
		pgproto3.FrontendMessage
		Decode([]byte) error
	}
	p := &startupPacket{}
	switch code {
	case sslRequestCode:
		m = &pgproto3.SSLRequest{}
	case gssEncRequestCode:
		m = &pgproto3.GSSEncRequest{}
	case cancelRequestCode:
		m = &pgproto3.CancelRequest{}
	default:
		if code>>16 != 3 {
			return nil, errUnsupportedVersion
		}
		// Accept any 3.x request and answer as 3.0 (NegotiateProtocolVersion
		// is sent later); pgproto3 only decodes 3.0 and 3.2.
		p.minor = uint16(code)
		binary.BigEndian.PutUint32(buf, pgproto3.ProtocolVersion30)
		m = &pgproto3.StartupMessage{}
	}
	if err := m.Decode(buf); err != nil {
		return nil, err
	}
	p.msg = m
	return p, nil
}

// writeMessages encodes and writes backend messages directly to w (used
// before the Backend exists and for fatal errors).
func writeMessages(w io.Writer, msgs ...pgproto3.BackendMessage) error {
	var buf []byte
	for _, m := range msgs {
		var err error
		if buf, err = m.Encode(buf); err != nil {
			return err
		}
	}
	_, err := w.Write(buf)
	return err
}

// rejectBusy answers a connection over the limit and closes it.
func rejectBusy(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_ = writeMessages(c, fatal("53300", "dbgateway の PostgreSQL プロキシへの接続数が上限に達しています。 / Too many connections to the dbgateway PostgreSQL proxy.", ""))
}

// handle runs one client connection: startup negotiation (TLS, cancel),
// authentication, then the session's message loop.
func (s *Server) handle(ctx context.Context, c net.Conn, requireTLS bool) {
	if ctx.Err() != nil {
		return
	}
	log := s.logger.With("remote", c.RemoteAddr().String())
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))

	var conn net.Conn = c
	tlsDone, gssDone := false, false
	var startup *startupPacket
	for startup == nil {
		p, err := readStartup(conn)
		if err != nil {
			if errors.Is(err, errUnsupportedVersion) {
				_ = writeMessages(conn, fatal("0A000", "unsupported frontend protocol: dbgateway supports protocol 3.0", ""))
			}
			log.Debug("pgproxy startup failed", "err", err)
			return
		}
		switch m := p.msg.(type) {
		case *pgproto3.SSLRequest:
			if tlsDone {
				_ = writeMessages(conn, fatal("08P01", "duplicate SSL negotiation request", ""))
				return
			}
			if s.tls == nil {
				if _, err := conn.Write([]byte{'N'}); err != nil {
					return
				}
				continue
			}
			if _, err := conn.Write([]byte{'S'}); err != nil {
				return
			}
			tc := tls.Server(c, s.tls)
			hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
			err := tc.HandshakeContext(hctx)
			cancel()
			if err != nil {
				log.Debug("pgproxy TLS handshake failed", "err", err)
				return
			}
			conn, tlsDone = tc, true
		case *pgproto3.GSSEncRequest:
			if gssDone || tlsDone {
				_ = writeMessages(conn, fatal("08P01", "unexpected GSSAPI encryption request", ""))
				return
			}
			gssDone = true
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
		case *pgproto3.CancelRequest:
			// The key is the credential; PostgreSQL sends no reply.
			s.cancel(m.ProcessID, m.SecretKey)
			return
		case *pgproto3.StartupMessage:
			startup = p
		}
	}
	if requireTLS && !tlsDone {
		_ = writeMessages(conn, fatal("28000",
			"この接続先では TLS が必須です。sslmode=require 以上で接続してください。 / TLS is required: connect with sslmode=require (or stricter).", ""))
		log.Info("pgproxy rejected a non-TLS connection")
		return
	}

	sess := newSession(s, conn, log)
	defer sess.close()
	if !sess.startup(ctx, startup.msg.(*pgproto3.StartupMessage), startup.minor) {
		return
	}
	sess.serve(ctx)
}

// fatal builds a FATAL ErrorResponse.
func fatal(code, msg, hint string) *pgproto3.ErrorResponse {
	return &pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: code, Message: msg, Hint: hint}
}

// pgError builds an ERROR ErrorResponse.
func pgError(code, msg, hint string) *pgproto3.ErrorResponse {
	return &pgproto3.ErrorResponse{Severity: "ERROR", SeverityUnlocalized: "ERROR", Code: code, Message: msg, Hint: hint}
}

// notice builds a NoticeResponse.
func notice(severity, msg, detail, hint string) *pgproto3.NoticeResponse {
	return &pgproto3.NoticeResponse{Severity: severity, SeverityUnlocalized: severity, Code: noticeCode(severity), Message: msg, Detail: detail, Hint: hint}
}

func noticeCode(severity string) string {
	if severity == "WARNING" {
		return "01000"
	}
	return "00000"
}
