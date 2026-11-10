// Package server wires every component into the `dbgw serve` HTTP server:
// the OAuth authorization server, the MCP endpoint (Streamable HTTP), and
// the connectRPC API.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kyosu-1/dbgateway/internal/adapter/mysql"
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
	"github.com/kyosu-1/dbgateway/internal/metrics"
	"github.com/kyosu-1/dbgateway/internal/notify"
	"github.com/kyosu-1/dbgateway/internal/policy"
	"github.com/kyosu-1/dbgateway/internal/scim"
	"github.com/kyosu-1/dbgateway/internal/store"
	"github.com/kyosu-1/dbgateway/internal/web"
)

func init() {
	gateway.RegisterErrorDescriber(mysql.DescribeError)
}

// Server is a running dbgateway instance.
type Server struct {
	cfg       *config.Config
	logger    *slog.Logger
	handler   http.Handler
	closers   []func()
	auth      *auth.Server
	approvals *approval.Service  // nil when approvals are disabled
	notifier  *notify.Dispatcher // nil when no notifications are configured
	anomaly   *notify.Anomaly    // nil when no notifications are configured
	metrics   *metrics.Metrics   // nil unless server.metrics_listen is set
	gw        *gateway.Gateway
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

	if cfg.Server.MetricsListen != "" {
		s.metrics = metrics.New(metrics.Options{Config: cfg, Version: mcpserver.Version})
		auditLog.SetErrorObserver(s.metrics.AuditWriteFailed)
		if fs, ok := sink.(interface{ Stats() []audit.ForwarderStats }); ok {
			s.metrics.WatchAuditForwarders(fs.Stats)
		}
	}

	st, err := openStore(ctx, cfg)
	if err != nil {
		return nil, err
	}
	s.closers = append(s.closers, func() { _ = st.Close() })

	// Notifications (best effort; never affect request outcomes). Metrics
	// count every event that reaches the notifier (including anomalies).
	var pub events.Publisher = events.Nop{}
	if s.metrics != nil {
		pub = s.metrics
	}
	if cfg.NotificationsEnabled() {
		s.notifier = notify.New(notify.Options{Config: cfg, Store: st, Logger: logger})
		s.closers = append(s.closers, s.notifier.Close)
		next := events.Publisher(s.notifier)
		if s.metrics != nil {
			next = events.Multi{s.metrics, s.notifier}
			s.metrics.WatchNotifications(s.notifier.Stats)
		}
		s.anomaly = notify.NewAnomaly(next, notify.AnomalyOptions{Config: cfg})
		pub = s.anomaly
	}
	if changed, prev, err := notify.ConfigChanged(ctx, st, cfg.Version); err != nil {
		logger.Warn("record config version failed", "err", err)
	} else if changed {
		pub.Publish(ctx, notify.ConfigChangedEvent(prev, cfg.Version))
	}

	gwOpts := gateway.Options{
		Config: cfg,
		Adapters: map[string]analysis.Adapter{
			"postgres": postgres.New(cfg.SQL.AllowedFunctions),
			"mysql":    mysql.New(cfg.SQL.AllowedFunctions),
		},
		Audit:      auditLog,
		Logger:     logger,
		Events:     pub,
		QuotaStore: st,
		RowsObserver: func(p *events.Principal, db string, n int64) {
			if s.anomaly != nil {
				s.anomaly.ObserveRows(p, db, n)
			}
		},
	}
	if s.metrics != nil {
		gwOpts.Observer = s.metrics
	}
	gw, err := gateway.New(gwOpts)
	if err != nil {
		return nil, err
	}
	s.gw = gw
	s.closers = append(s.closers, gw.Close)
	if s.metrics != nil {
		s.metrics.WatchPools(gw.PoolStats)
	}

	authSrv, err := auth.New(ctx, auth.Options{Config: cfg, Store: st, RBAC: policy.NewRBAC(cfg), Logger: logger})
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	s.auth = authSrv

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
	webOpts := web.Options{Config: cfg, Store: st, Auth: authSrv, Gateway: gw, Approvals: s.approvals, Logger: logger}
	if ps, ok := sink.(*audit.PostgresSink); ok {
		webOpts.AuditSearch = ps.Search
	}
	if s.notifier != nil {
		authSrv.SetSlackLinker(s.notifier.Linker())
	}
	webApp, err := web.New(webOpts)
	if err != nil {
		return nil, fmt.Errorf("web: %w", err)
	}
	webApp.Register(mux)

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
	path, h = api.NewGatewayService(authSrv, gw, s.approvals, cfg)
	mux.Handle(path, h)

	health := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	}
	mux.HandleFunc("GET /healthz", health)
	// /health for platforms that reserve /healthz on the public URL (Cloud
	// Run reserves paths ending in "z"; its own probes can still use /healthz).
	mux.HandleFunc("GET /health", health)

	s.handler = withRequestLog(logger, mux)
	ok = true
	return s, nil
}

// managementStore is the management database: the store and the SCIM
// persistence, implemented by every backend.
type managementStore interface {
	store.Store
	scim.Store
	notify.Store
}

// OpenStore opens the management database selected by store.driver (for
// CLI commands that need it, such as `dbgw passkey enroll`).
func OpenStore(ctx context.Context, cfg *config.Config) (store.Store, error) {
	return openStore(ctx, cfg)
}

// openStore opens the management database selected by store.driver.
func openStore(ctx context.Context, cfg *config.Config) (managementStore, error) {
	if cfg.Store.Driver == config.StorePostgres {
		dsn, err := cfg.StoreDSN()
		if err != nil {
			return nil, err
		}
		st, err := store.OpenPostgres(ctx, dsn)
		if err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
		return st, nil
	}
	st, err := store.OpenSQLite(ctx, cfg.Store.Path)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return st, nil
}

// openAuditSink opens the primary audit sink and, when configured, wraps it
// with best-effort forwarders (OTLP). Only the primary decides success.
func openAuditSink(ctx context.Context, cfg *config.Config, logger *slog.Logger) (audit.Sink, error) {
	var primary audit.Sink
	var pgSink *audit.PostgresSink
	switch cfg.Audit.Output {
	case config.AuditOutputStdout:
		primary = audit.NewStdoutSink(os.Stdout)
	case config.AuditOutputPostgres:
		dsn, err := cfg.AuditDSN()
		if err != nil {
			return nil, err
		}
		if pgSink, err = audit.OpenPostgresSink(ctx, dsn, cfg.Audit.Retention.D(), logger); err != nil {
			return nil, err
		}
		primary = pgSink
	default:
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
	fwd, err := func() (audit.Forwarder, error) {
		headers, err := o.Headers()
		if err != nil {
			return nil, err
		}
		return audit.NewOTLPForwarder(ctx, audit.OTLPOptions{Endpoint: o.Endpoint, Insecure: o.Insecure, Headers: headers})
	}()
	if err != nil {
		_ = primary.Close()
		return nil, fmt.Errorf("audit.otlp: %w", err)
	}
	if pgSink != nil {
		// The PostgreSQL sink re-chains lines to the shared tail; it
		// forwards them as stored.
		pgSink.SetForwarders(logger, fwd)
		return pgSink, nil
	}
	ms := audit.NewMultiSink(primary, fwd)
	ms.SetLogger(logger)
	return ms, nil
}

// Handler returns the root HTTP handler (useful for tests).
func (s *Server) Handler() http.Handler { return s.handler }

// MetricsHandler returns the handler of the metrics listener (GET
// /metrics), or nil when server.metrics_listen is not set. It is never
// mounted on the main handler: metrics are served on their own listener.
func (s *Server) MetricsHandler() http.Handler {
	if s.metrics == nil {
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", s.metrics.Handler())
	return mux
}

// Close releases all resources.
func (s *Server) Close() {
	for i := len(s.closers) - 1; i >= 0; i-- {
		s.closers[i]()
	}
	s.closers = nil
}

// startBackground starts the loops that run beside the HTTP server.
func (s *Server) startBackground(ctx context.Context) {
	go s.auth.RunCleanup(ctx, 10*time.Minute) // expired sessions, codes and tokens
	if s.approvals != nil {
		go s.approvals.Run(ctx) // expiry, and resuming approved executions
	}
	if s.notifier != nil {
		go func() { _ = s.notifier.Run(ctx) }() // Slack Socket Mode (outbound only)
	}
	go s.gw.RunBackupRetention(ctx, time.Hour) // backup.retention
}

// RunBackground runs only the background loops (approval execution and
// expiry, cleanup, Slack) until ctx is cancelled, for callers that serve
// Handler() themselves (e.g. tests or an embedding program).
func (s *Server) RunBackground(ctx context.Context) error {
	s.startBackground(ctx)
	<-ctx.Done()
	return nil
}

// Run serves HTTP with the
// background loops until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Server.Listen,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	var metricsSrv *http.Server
	var metricsLn net.Listener
	if h := s.MetricsHandler(); h != nil {
		// Bind before starting so that a taken port fails startup.
		ln, err := net.Listen("tcp", s.cfg.Server.MetricsListen)
		if err != nil {
			return fmt.Errorf("server.metrics_listen: %w", err)
		}
		metricsLn = ln
		metricsSrv = &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    64 << 10,
		}
	}
	s.startBackground(ctx)

	errc := make(chan error, 2)

	go func() {
		s.logger.Info("dbgateway listening", "addr", s.cfg.Server.Listen, "public_url", s.cfg.Server.PublicURL,
			"mode", s.cfg.Server.Mode, "config_version", s.cfg.Version)
		errc <- srv.ListenAndServe()
	}()
	if metricsSrv != nil {
		go func() {
			s.logger.Info("metrics listening", "addr", metricsLn.Addr().String())
			errc <- metricsSrv.Serve(metricsLn)
		}()
	}
	var serveErr error
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			serveErr = err
		}
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s.logger.Info("shutting down")
	errs := []error{serveErr, srv.Shutdown(shutdownCtx)}
	if metricsSrv != nil {
		errs = append(errs, metricsSrv.Shutdown(shutdownCtx))
	}
	return errors.Join(errs...)
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
		path := r.URL.Path
		if strings.HasPrefix(path, "/passkeys/enroll/") {
			path = "/passkeys/enroll/[redacted]" // one-time enrollment token
		}
		logger.Debug("http", "method", r.Method, "path", path, "status", rec.status, "duration", time.Since(start))
	})
}
