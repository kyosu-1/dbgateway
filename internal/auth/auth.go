// Package auth is the OAuth 2.1 authorization server of dbgateway and the
// resource-server side token verification for the MCP endpoint.
//
// Humans log in through the upstream OIDC provider (or a dev-only form).
// MCP clients obtain agent tokens with the authorization code flow + PKCE,
// after the human consents on a page served here. The dbgw CLI obtains a
// human token with the device authorization grant (RFC 8628).
//
// Every token is an opaque random value; only its SHA-256 is stored. The
// principal is rebuilt from the store and the current configuration on every
// verification, so revocations and group changes take effect immediately.
package auth

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/policy"
	"github.com/kyosu-1/dbgateway/internal/store"
	"github.com/kyosu-1/dbgateway/internal/web/i18n"
)

const (
	// CLIClientID is the built-in public client used by the dbgw CLI for
	// the device authorization grant.
	CLIClientID = "dbgw-cli"
	// CLIClientName is the display name of the built-in CLI client.
	CLIClientName = "dbgw CLI"

	// GrantTypeDeviceCode is the RFC 8628 grant type URN.
	GrantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

	// AccessTokenPrefix and RefreshTokenPrefix make tokens recognizable
	// (for example by secret scanners).
	AccessTokenPrefix  = "dbgw_at_"
	RefreshTokenPrefix = "dbgw_rt_"

	authCodeTTL       = 60 * time.Second
	deviceCodeTTL     = 10 * time.Minute
	deviceInterval    = 5 * time.Second
	refreshFamilyTTL  = 7 * 24 * time.Hour
	loginStateTTL     = 10 * time.Minute
	maxFormBytes      = 64 << 10
	sessionCookieName = "dbgw_session"
	loginCookieName   = "dbgw_login"
)

// Options configure the auth server.
type Options struct {
	Config *config.Config
	Store  store.Store
	RBAC   *policy.RBAC
	Logger *slog.Logger
}

// Server is the authorization server and token verifier.
type Server struct {
	cfg    *config.Config
	store  store.Store
	rbac   *policy.RBAC
	log    *slog.Logger
	issuer string // public URL without trailing slash
	secure bool   // public URL is https: set Secure on cookies
	oidc   *oidcLogin
	cimd   *cimdFetcher
	pages  map[string]*template.Template
	i18n   *i18n.Catalog
	now    func() time.Time
}

// New returns a Server. It does not contact the IdP; OIDC discovery happens
// on the first login.
func New(ctx context.Context, opts Options) (*Server, error) {
	if opts.Config == nil || opts.Store == nil || opts.RBAC == nil {
		return nil, errors.New("auth: Config, Store and RBAC are required")
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	cfg := opts.Config
	issuer := strings.TrimRight(cfg.Server.PublicURL, "/")
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("auth: invalid server.public_url %q", cfg.Server.PublicURL)
	}
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:    cfg,
		store:  opts.Store,
		rbac:   opts.RBAC,
		log:    log,
		issuer: issuer,
		secure: u.Scheme == "https",
		cimd:   newCIMDFetcher(cfg.Auth.AllowInsecureClientMetadata),
		pages:  pages,
		i18n:   i18n.Default(),
		now:    time.Now,
	}
	if cfg.Auth.OIDC != nil {
		o, err := newOIDCLogin(cfg.Auth.OIDC, issuer+"/oidc/callback")
		if err != nil {
			return nil, err
		}
		s.oidc = o
	}
	if cfg.Auth.DevLogin {
		log.Warn("auth: dev_login is enabled; anyone can log in as any email. Never use this in production.")
	}
	if s.oidc == nil && !cfg.Auth.DevLogin {
		return nil, errors.New("auth: no login method configured (auth.oidc or auth.dev_login)")
	}
	return s, nil
}

// ResourceURL is the canonical URL of the MCP resource (the audience of
// agent tokens).
func (s *Server) ResourceURL() string { return s.issuer + "/mcp" }

// ResourceMetadataURL is the RFC 9728 protected resource metadata URL for
// the MCP resource, advertised in WWW-Authenticate.
func (s *Server) ResourceMetadataURL() string {
	return s.issuer + "/.well-known/oauth-protected-resource/mcp"
}

// Issuer is the authorization server issuer identifier (the public URL).
func (s *Server) Issuer() string { return s.issuer }

// Register adds every authorization server endpoint to mux.
func (s *Server) Register(mux *http.ServeMux) {
	// Public JSON endpoints: CORS-enabled (no cookies are involved).
	prm := s.cors(http.HandlerFunc(s.handleProtectedResourceMetadata))
	mux.Handle("/.well-known/oauth-protected-resource", prm)
	mux.Handle("/.well-known/oauth-protected-resource/mcp", prm)
	mux.Handle("/.well-known/oauth-authorization-server", s.cors(http.HandlerFunc(s.handleASMetadata)))
	for path, h := range map[string]http.HandlerFunc{
		"/token":                s.handleToken,
		"/register":             s.handleRegister,
		"/device_authorization": s.handleDeviceAuthorization,
		"/revoke":               s.handleRevoke,
	} {
		mux.Handle(path, s.cors(postOnly(h)))
	}

	// Browser pages.
	mux.Handle("GET /authorize", s.page(s.handleAuthorize))
	mux.Handle("POST /authorize", s.page(s.handleConsent))
	mux.Handle("GET /device", s.page(s.handleDevicePage))
	mux.Handle("POST /device", s.page(s.handleDeviceDecision))
	mux.Handle("GET /login", s.page(s.handleLogin))
	mux.Handle("POST /login", s.page(s.handleDevLogin))
	mux.Handle("GET /login/sso", s.page(s.handleSSOLogin))
	mux.Handle("GET /oidc/callback", s.page(s.handleOIDCCallback))
	mux.Handle("GET /account", s.page(s.handleAccount))
	mux.Handle("POST /account/revoke", s.page(s.handleAccountRevoke))
	mux.Handle("POST /logout", s.page(s.handleLogout))
	mux.Handle("GET /static/dbgw.css", securityHeaders(http.HandlerFunc(serveCSS)))
}

// securityHeaders sets headers that every response should carry.
func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		// No form-action: the consent form legitimately redirects to the
		// client's redirect_uri.
		hd.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

// page wraps an HTML handler.
func (s *Server) page(h http.HandlerFunc) http.Handler {
	return securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if s.i18n.SwitchLanguage(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		h(w, r)
	}))
}

// cors wraps a public JSON endpoint.
func (s *Server) cors(h http.Handler) http.Handler {
	return securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, MCP-Protocol-Version")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		h.ServeHTTP(w, r)
	}))
}

func postOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		h(w, r)
	}
}

// cleanupGrace keeps expired rows for a while so that replayed codes and
// refresh tokens are still recognized (and their families revoked).
const cleanupGrace = 24 * time.Hour

// RunCleanup deletes expired sessions, codes and tokens every interval
// until ctx is done. Run it in its own goroutine.
func (s *Server) RunCleanup(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		n, err := s.store.DeleteExpired(ctx, s.now().Add(-cleanupGrace))
		if err != nil && ctx.Err() == nil {
			s.log.Error("auth: cleanup", "err", err)
		} else if n > 0 {
			s.log.Debug("auth: cleanup", "deleted", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
