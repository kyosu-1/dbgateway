package pgproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

const goodToken = "dbgw_at_good"

var testPrincipal = &identity.Principal{Kind: identity.KindHuman, Human: "taro@example.com", Scopes: []string{identity.ScopeRead}}

func fakeAuth(_ context.Context, token string) (*identity.Principal, error) {
	switch token {
	case goodToken:
		return testPrincipal, nil
	case "dbgw_at_noscope":
		return &identity.Principal{Kind: identity.KindHuman, Human: "x@example.com"}, nil
	}
	return nil, errors.New("invalid token")
}

// fakeGateway records requests and answers with fn.
type fakeGateway struct {
	mu   sync.Mutex
	reqs []gateway.ExecuteRequest
	fn   func(ctx context.Context, req gateway.ExecuteRequest) *gateway.ExecuteResponse
}

func (f *fakeGateway) ExecuteSQL(ctx context.Context, _ *identity.Principal, req gateway.ExecuteRequest) *gateway.ExecuteResponse {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	fn := f.fn
	f.mu.Unlock()
	if fn == nil {
		return &gateway.ExecuteResponse{Status: gateway.StatusOK, RequestID: "req_test",
			Columns: []gateway.ResultColumn{{Name: "n", Type: "int8"}}, Rows: [][]any{{int64(1)}}, RowCount: 1}
	}
	return fn(ctx, req)
}

func (f *fakeGateway) ListDatabases(*identity.Principal) []gateway.DatabaseInfo {
	return []gateway.DatabaseInfo{{Name: "dev-main", CanRead: true}, {Name: "schema-only", CanSearch: true}}
}

func (f *fakeGateway) requests() []gateway.ExecuteRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]gateway.ExecuteRequest(nil), f.reqs...)
}

type proxyOpts struct {
	pc   config.PGProxy
	wrap func(net.Listener) net.Listener
}

// startProxy serves a proxy on a loopback TCP listener and returns its
// address.
func startProxy(t *testing.T, gw Executor, o proxyOpts) string {
	t.Helper()
	cfg := &config.Config{PGProxy: o.pc}
	srv, err := New(Options{Config: cfg, Gateway: gw, Authenticate: fakeAuth, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if o.wrap != nil {
		ln = o.wrap(ln)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return addr
}

// client is a minimal PostgreSQL frontend.
type client struct {
	t      *testing.T
	conn   net.Conn
	fe     *pgproto3.Frontend
	status map[string]string
	key    *pgproto3.BackendKeyData
	npv    *pgproto3.NegotiateProtocolVersion
}

func defaultParams() map[string]string {
	return map[string]string{"user": "taro", "database": "dev-main", "application_name": "psql"}
}

// connect performs startup and authentication. It returns the FATAL error
// sent by the server, if any.
func connect(t *testing.T, addr string, params map[string]string, password string) (*client, *pgproto3.ErrorResponse) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return startup(t, conn, params, password)
}

func startup(t *testing.T, conn net.Conn, params map[string]string, password string) (*client, *pgproto3.ErrorResponse) {
	t.Helper()
	return startupVersion(t, conn, pgproto3.ProtocolVersion30, params, password)
}

func startupVersion(t *testing.T, conn net.Conn, version uint32, params map[string]string, password string) (*client, *pgproto3.ErrorResponse) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	c := &client{t: t, conn: conn, fe: pgproto3.NewFrontend(conn, conn), status: map[string]string{}}
	c.fe.Send(&pgproto3.StartupMessage{ProtocolVersion: version, Parameters: params})
	c.flush()
	for {
		msg := c.recv()
		switch m := msg.(type) {
		case *pgproto3.AuthenticationCleartextPassword:
			c.fe.Send(&pgproto3.PasswordMessage{Password: password})
			c.flush()
		case *pgproto3.AuthenticationOk:
		case *pgproto3.NegotiateProtocolVersion:
			c.npv = m
		case *pgproto3.ParameterStatus:
			c.status[m.Name] = m.Value
		case *pgproto3.BackendKeyData:
			c.key = m
		case *pgproto3.ReadyForQuery:
			return c, nil
		case *pgproto3.ErrorResponse:
			return nil, m
		default:
			t.Fatalf("unexpected startup message %T", msg)
		}
	}
}

func (c *client) flush() {
	c.t.Helper()
	if err := c.fe.Flush(); err != nil {
		c.t.Fatal(err)
	}
}

// recv returns a copy of the next message (Frontend reuses its messages).
func (c *client) recv() pgproto3.BackendMessage {
	c.t.Helper()
	msg, err := c.fe.Receive()
	if err != nil {
		c.t.Fatalf("receive: %v", err)
	}
	buf, err := msg.Encode(nil)
	if err != nil {
		c.t.Fatal(err)
	}
	cp := reflect.New(reflect.TypeOf(msg).Elem()).Interface().(pgproto3.BackendMessage)
	if err := cp.Decode(buf[5:]); err != nil {
		c.t.Fatal(err)
	}
	return cp
}

// untilReady sends msgs and collects the replies up to ReadyForQuery.
func (c *client) untilReady(msgs ...pgproto3.FrontendMessage) []pgproto3.BackendMessage {
	c.t.Helper()
	for _, m := range msgs {
		c.fe.Send(m)
	}
	c.flush()
	var out []pgproto3.BackendMessage
	for {
		msg := c.recv()
		out = append(out, msg)
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			return out
		}
	}
}

func (c *client) query(sql string) []pgproto3.BackendMessage {
	c.t.Helper()
	return c.untilReady(&pgproto3.Query{String: sql})
}

func find[T pgproto3.BackendMessage](msgs []pgproto3.BackendMessage) []T {
	var out []T
	for _, m := range msgs {
		if x, ok := m.(T); ok {
			out = append(out, x)
		}
	}
	return out
}

func types(msgs []pgproto3.BackendMessage) []string {
	var out []string
	for _, m := range msgs {
		out = append(out, reflect.TypeOf(m).Elem().Name())
	}
	return out
}

func tags(msgs []pgproto3.BackendMessage) []string {
	var out []string
	for _, m := range find[*pgproto3.CommandComplete](msgs) {
		out = append(out, string(m.CommandTag))
	}
	return out
}

func errorOf(t *testing.T, msgs []pgproto3.BackendMessage) *pgproto3.ErrorResponse {
	t.Helper()
	errs := find[*pgproto3.ErrorResponse](msgs)
	if len(errs) != 1 {
		t.Fatalf("want one ErrorResponse, got %v", types(msgs))
	}
	return errs[0]
}

// writeTestCert writes a self-signed certificate for 127.0.0.1 and returns
// the PEM paths and a pool trusting it.
func writeTestCert(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pgproxy-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}

// publicListener reports a non-loopback address while accepting on a
// loopback one, to exercise the TLS requirement.
type publicListener struct{ net.Listener }

func (publicListener) Addr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5433} }

// sslRequest sends an SSLRequest and returns the server's one-byte answer.
func sslRequest(t *testing.T, conn net.Conn) byte {
	t.Helper()
	buf, _ := (&pgproto3.SSLRequest{}).Encode(nil)
	if _, err := conn.Write(buf); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		t.Fatal(err)
	}
	return b[0]
}

func tlsClient(conn net.Conn, pool *x509.CertPool) *tls.Conn {
	return tls.Client(conn, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
}
