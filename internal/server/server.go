// Package server wires every component into the `dbgw serve` HTTP server:
// the OAuth authorization server, the MCP endpoint (Streamable HTTP), and
// the connectRPC API.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kyosu-1/dbgateway/internal/adapter/postgres"
	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/api"
	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/auth"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
	mcpserver "github.com/kyosu-1/dbgateway/internal/mcp"
	"github.com/kyosu-1/dbgateway/internal/notify"
	"github.com/kyosu-1/dbgateway/internal/pgproxy"
	"github.com/kyosu-1/dbgateway/internal/policy"
	"github.com/kyosu-1/dbgateway/internal/scim"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// Server is a running dbgateway instance.
type Server struct {
	cfg       *config.Config
	logger    *slog.Logger
	handler   http.Handler
	closers   []func()
	auth      *auth.Server
	pgproxy   *pgproxy.Server    // nil when disabled
	approvals *approval.Service  // nil when approvals are disabled
	notifier  *notify.Dispatcher // nil when no notifications are configured
	anomaly   *notify.Anomaly    // nil when no notifications are configured
}

// New builds the server from a validated configuration.
func New(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, logger: logger}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()

	sink, err := openAuditSink(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}
	auditLog, err := audit.New(sink)
	if err != nil {
		return nil, err
	}
	s.closers = append(s.closers, func() { _ = auditLog.Close() })

	st, err := store.OpenSQLite(ctx, cfg.Store.Path)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	s.closers = append(s.closers, func() { _ = st.Close() })

	// Notifications (best effort; never affect request outcomes).
	var pub events.Publisher = events.Nop{}
	if cfg.NotificationsEnabled() {
		s.notifier = notify.New(notify.Options{Config: cfg, Store: st, Logger: logger})
		s.closers = append(s.closers, s.notifier.Close)
		s.anomaly = notify.NewAnomaly(s.notifier, notify.AnomalyOptions{Config: cfg})
		pub = s.anomaly
	}
	if changed, prev, err := notify.ConfigChanged(ctx, st, cfg.Version); err != nil {
		logger.Warn("record config version failed", "err", err)
	} else if changed {
		pub.Publish(ctx, notify.ConfigChangedEvent(prev, cfg.Version))
	}

	gw, err := gateway.New(gateway.Options{
		Config:   cfg,
		Adapters: map[string]analysis.Adapter{"postgres": postgres.New(cfg.SQL.AllowedFunctions)},
		Audit:    auditLog,
		Logger:   logger,
		Events:   pub,
	})
	if err != nil {
		return nil, err
	}
	s.closers = append(s.closers, gw.Close)

	authSrv, err := auth.New(ctx, auth.Options{Config: cfg, Store: st, RBAC: policy.NewRBAC(cfg), Logger: logger})
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	s.auth = authSrv

	if cfg.PGProxy.Enabled() {
		s.pgproxy, err = pgproxy.New(pgproxy.Options{Config: cfg, Gateway: gw, Authenticate: authSrv.Authenticate, Logger: logger})
		if err != nil {
			return nil, fmt.Errorf("pgproxy: %w", err)
		}
	}

	mux := http.NewServeMux()
	authSrv.Register(mux)

	var mcpOpts []mcpserver.Option
	if cfg.Approvals.Enabled {
		s.approvals = approval.New(approval.Options{Config: cfg, Store: st, Executor: gw, Audit: auditLog, Events: pub, Logger: logger})
		gw.SetApprovals(s.approvals)
		if s.notifier != nil {
			s.notifier.SetApprovals(s.approvals) // Slack reject button
		}
		mcpOpts = append(mcpOpts, mcpserver.WithApprovals(s.approvals))
	}
	mcpSrv := mcpserver.NewServer(gw, auth.PrincipalFromTokenInfo, mcpOpts...)
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpSrv },
		&mcp.StreamableHTTPOptions{Stateless: true, Logger: logger, PropagateRequestCancellation: true})
	bearer := mcpauth.RequireBearerToken(authSrv.VerifyToken, &mcpauth.RequireBearerTokenOptions{
		ResourceMetadataURL: authSrv.ResourceMetadataURL(),
		Scopes:              []string{identity.ScopeRead},
		ClockSkew:           30 * time.Second,
	})
	mux.Handle("/mcp", bearer(mcpHandler))

	if cfg.SCIM.Enabled {
		mux.Handle(scim.PathPrefix+"/", scim.NewHandler(scim.Options{Config: cfg, Store: st, Logger: logger}))
	}

	path, h := api.NewTokenService(authSrv, st, cfg)
	mux.Handle(path, h)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})

	s.handler = withRequestLog(logger, mux)
	ok = true
	return s, nil
}

// openAuditSink opens the primary audit sink and, when configured, wraps it
// with best-effort forwarders (OTLP). Only the primary decides success.
func openAuditSink(ctx context.Context, cfg *config.Config, logger *slog.Logger) (audit.Sink, error) {
	var primary audit.Sink
	if cfg.Audit.Output == "stdout" {
		primary = audit.NewStdoutSink(os.Stdout)
	} else {
		fs, err := audit.OpenFileSink(cfg.Audit.Dir, cfg.Audit.Retention.D(), !cfg.Audit.NoFsync, logger)
		if err != nil {
			return nil, err
		}
		primary = fs
	}
	o := cfg.Audit.OTLP
	if o == nil {
		return primary, nil
	}
	headers, err := o.Headers()
	if err != nil {
		return nil, fmt.Errorf("audit.otlp: %w", err)
	}
	fwd, err := audit.NewOTLPForwarder(ctx, audit.OTLPOptions{Endpoint: o.Endpoint, Insecure: o.Insecure, Headers: headers})
	if err != nil {
		return nil, fmt.Errorf("audit.otlp: %w", err)
	}
	ms := audit.NewMultiSink(primary, fwd)
	ms.SetLogger(logger)
	return ms, nil
}

// Handler returns the root HTTP handler (useful for tests).
func (s *Server) Handler() http.Handler { return s.handler }

// Close releases all resources.
func (s *Server) Close() {
	for i := len(s.closers) - 1; i >= 0; i-- {
		s.closers[i]()
	}
	s.closers = nil
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Server.Listen,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	go s.auth.RunCleanup(ctx, 10*time.Minute) // expired sessions, codes and tokens
	if s.approvals != nil {
		go s.approvals.Run(ctx) // expiry, and resuming approved executions
	}
	if s.notifier != nil {
		go func() { _ = s.notifier.Run(ctx) }() // Slack Socket Mode (outbound only)
	}

	errc := make(chan error, 2)
	if s.pgproxy != nil {
		go func() {
			s.logger.Info("pgproxy listening", "addr", s.cfg.PGProxy.Listen)
			if err := s.pgproxy.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
				errc <- fmt.Errorf("pgproxy: %w", err)
			}
		}()
	}

	go func() {
		s.logger.Info("dbgateway listening", "addr", s.cfg.Server.Listen, "public_url", s.cfg.Server.PublicURL,
			"mode", s.cfg.Server.Mode, "config_version", s.cfg.Version)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s.logger.Info("shutting down")
	return srv.Shutdown(shutdownCtx)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// withRequestLog logs method, path, status and duration (never queries,
// headers or bodies, which may carry secrets).
func withRequestLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		logger.Debug("http", "method", r.Method, "path", r.URL.Path, "status", rec.status, "duration", time.Since(start))
	})
}
