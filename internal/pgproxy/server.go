// Package pgproxy is a PostgreSQL wire-protocol (v3) front end for the
// gateway. It lets humans use psql, DBeaver and other PostgreSQL clients
// while every statement still goes through internal/gateway: role check,
// SQL analysis, policy, masking and audit. The proxy never talks to a
// database itself.
//
// Clients authenticate with a dbgateway token sent as a cleartext password
// (TLS is required unless the proxy listens on loopback). The database name
// selects the dbgateway connection. Statements are answered one by one; the
// simple query protocol and the extended query protocol without parameters
// are supported.
package pgproxy

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

// Executor is the part of the gateway the proxy uses. *gateway.Gateway
// implements it.
type Executor interface {
	ExecuteSQL(ctx context.Context, p *identity.Principal, req gateway.ExecuteRequest) *gateway.ExecuteResponse
	ListDatabases(p *identity.Principal) []gateway.DatabaseInfo
}

var _ Executor = (*gateway.Gateway)(nil)

// Options configures a Server.
type Options struct {
	Config  *config.Config
	Gateway Executor
	// Authenticate verifies a dbgateway access token (the password sent by
	// the client), e.g. (*auth.Server).Authenticate.
	Authenticate func(ctx context.Context, token string) (*identity.Principal, error)
	Logger       *slog.Logger
}

const (
	// maxMessageSize bounds a single protocol message from a client.
	maxMessageSize = 4 << 20
	// maxTokenSize bounds the password message during authentication.
	maxTokenSize = 1 << 10
	// handshakeTimeout bounds TLS negotiation, startup and authentication.
	handshakeTimeout = 30 * time.Second
	// writeTimeout bounds each write to a client.
	writeTimeout = time.Minute
	// authTimeout bounds token verification.
	authTimeout = 10 * time.Second
)

// Server accepts PostgreSQL client connections.
type Server struct {
	cfg    *config.Config
	gw     Executor
	authn  func(ctx context.Context, token string) (*identity.Principal, error)
	logger *slog.Logger
	tls    *tls.Config // nil when TLS is not configured
	sem    chan struct{}
	idle   time.Duration

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	sessions map[uint32]*session // by BackendKeyData process ID
}

// New validates the options and loads the TLS certificate.
func New(opts Options) (*Server, error) {
	if opts.Config == nil || opts.Gateway == nil || opts.Authenticate == nil {
		return nil, errors.New("pgproxy: Config, Gateway and Authenticate are required")
	}
	pc := opts.Config.PGProxy
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	maxConns := pc.MaxConnections
	if maxConns <= 0 {
		maxConns = config.DefaultPGProxyMaxConnections
	}
	idle := pc.IdleTimeout.D()
	if idle <= 0 {
		idle = config.DefaultPGProxyIdleTimeout
	}
	s := &Server{
		cfg: opts.Config, gw: opts.Gateway, authn: opts.Authenticate, logger: logger.With("component", "pgproxy"),
		sem: make(chan struct{}, maxConns), idle: idle,
		conns: map[net.Conn]struct{}{}, sessions: map[uint32]*session{},
	}
	if (pc.TLSCert == "") != (pc.TLSKey == "") {
		return nil, errors.New("pgproxy: tls_cert and tls_key must be set together")
	}
	if pc.TLSEnabled() {
		cert, err := tls.LoadX509KeyPair(pc.TLSCert, pc.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("pgproxy: load TLS certificate: %w", err)
		}
		s.tls = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	return s, nil
}

// ListenAndServe listens on pgproxy.listen and serves until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context) error {
	addr := s.cfg.PGProxy.Listen
	if addr == "" {
		return errors.New("pgproxy: pgproxy.listen is not configured")
	}
	if s.tls == nil && !isLoopbackAddr(addr) {
		return fmt.Errorf("pgproxy: refusing to listen on non-loopback address %s without TLS", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("pgproxy: %w", err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is done, then closes every
// connection and waits for their handlers. Serve closes ln.
//
// Unless ln listens on a loopback address, TLS must be configured and every
// client must use it, since the password is a dbgateway token.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	requireTLS := !isLoopbackAddr(ln.Addr().String())
	if requireTLS && s.tls == nil {
		_ = ln.Close()
		return fmt.Errorf("pgproxy: refusing to serve on non-loopback address %s without TLS", ln.Addr())
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	stop := context.AfterFunc(ctx, func() {
		_ = ln.Close()
		s.mu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
	})
	defer stop()
	s.logger.Info("pgproxy listening", "addr", ln.Addr().String(), "tls", s.tls != nil)

	var backoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			// Transient errors (e.g. too many open files): back off.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			s.logger.Warn("pgproxy accept failed", "err", err, "retry_in", backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		select {
		case s.sem <- struct{}{}:
		default:
			// Too many clients: answer without reading the startup packet.
			go rejectBusy(c)
			continue
		}
		if !s.track(ctx, c) {
			_ = c.Close()
			<-s.sem
			continue
		}
		wg.Go(func() {
			defer func() { <-s.sem }()
			defer s.untrack(c)
			s.handle(ctx, c, requireTLS)
		})
	}
	cancel() // close the remaining connections (also when ln was closed elsewhere)
	wg.Wait()
	return nil
}

// track records a connection so that shutdown can close it. It fails once
// ctx is done (shutdown has already closed the tracked connections).
func (s *Server) track(ctx context.Context, c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	_ = c.Close()
}

// register assigns a unique process ID and secret key to a session.
func (s *Server) register(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		var b [8]byte
		_, _ = rand.Read(b[:])
		pid := binary.BigEndian.Uint32(b[:4]) &^ (1 << 31) // positive int32, as a real backend PID
		if _, dup := s.sessions[pid]; pid == 0 || dup {
			continue
		}
		sess.pid, sess.secret = pid, b[4:]
		s.sessions[pid] = sess
		return
	}
}

func (s *Server) unregister(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[sess.pid] == sess {
		delete(s.sessions, sess.pid)
	}
}

// cancel handles a CancelRequest: the statement running on the matching
// session (if any) is cancelled. Unknown keys are ignored silently, as
// PostgreSQL does.
func (s *Server) cancel(pid uint32, secret []byte) {
	s.mu.Lock()
	sess := s.sessions[pid]
	s.mu.Unlock()
	if sess == nil || subtle.ConstantTimeCompare(sess.secret, secret) != 1 {
		return
	}
	sess.cancelRunning()
}

// isLoopbackAddr reports whether a host:port address is on loopback.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
