// Package web serves the browser pages of dbgateway beyond sign-in and
// consent (which live in internal/auth): approvals, the requester's
// requests, the SQL console, the audit log, users and role-change
// proposals, and break-glass elevation.
//
// Every page uses the shared renderer of the auth server (internal/web/ui)
// and the logged-in browser session (humans only; agents never get web
// sessions). Every handler checks the session and the caller's permissions
// itself, fails closed, and never trusts hidden form fields: databases,
// roles and eligibility are re-checked on the server, and the approval
// service and the gateway enforce their own rules again.
//
// Wiring (see internal/server):
//
//	app, err := web.New(web.Options{Config: cfg, Store: st, Auth: authSrv, Gateway: gw, Approvals: svc})
//	app.Register(mux)
package web

import (
	"context"
	"embed"
	"errors"
	"github.com/kyosu-1/dbgateway/internal/audit"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/auth"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/policy"
	"github.com/kyosu-1/dbgateway/internal/store"
	"github.com/kyosu-1/dbgateway/internal/web/ui"
)

//go:embed templates/*.html
var templateFS embed.FS

// ConsoleClientID is the client ID recorded for statements run from the
// SQL console (audit log, approval requests).
const ConsoleClientID = "dbgw-console"

// Options configure the web app.
type Options struct {
	Config  *config.Config   // required
	Store   store.Store      // required
	Auth    *auth.Server     // required: sessions, step-up, renderer
	Gateway *gateway.Gateway // required: SQL console
	// Approvals is nil when approvals are disabled; the approval, request
	// and break-glass pages then say so.
	Approvals *approval.Service
	// RBAC defaults to policy.NewRBAC(Config).
	RBAC   *policy.RBAC
	Logger *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
	// AuditSearch searches the audit log. Nil means: the file sink in
	// audit.dir when audit.output is file, otherwise unavailable.
	AuditSearch func(ctx context.Context, f audit.Filter) (audit.Page, error)
}

// App serves the pages.
type App struct {
	cfg  *config.Config
	st   store.Store
	auth *auth.Server
	gw   *gateway.Gateway
	svc  *approval.Service
	rbac *policy.RBAC
	ui   *ui.Renderer
	log  *slog.Logger
	now  func() time.Time
	// search is nil when the audit log cannot be searched (stdout).
	search func(ctx context.Context, f audit.Filter) (audit.Page, error)
}

// New builds the app, adds its pages to the auth server's renderer, and
// installs the header navigation and the account page's break-glass hook
// on the auth server.
func New(opts Options) (*App, error) {
	if opts.Config == nil || opts.Store == nil || opts.Auth == nil || opts.Gateway == nil {
		return nil, errors.New("web: Config, Store, Auth and Gateway are required")
	}
	a := &App{cfg: opts.Config, st: opts.Store, auth: opts.Auth, gw: opts.Gateway, svc: opts.Approvals, rbac: opts.RBAC,
		ui: opts.Auth.UI(), log: opts.Logger, now: opts.Now}
	if a.rbac == nil {
		a.rbac = policy.NewRBAC(a.cfg)
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	if a.now == nil {
		a.now = time.Now
	}
	a.search = opts.AuditSearch
	if a.search == nil && a.cfg.Audit.Output == config.AuditOutputFile {
		dir := a.cfg.Audit.Dir
		a.search = func(_ context.Context, f audit.Filter) (audit.Page, error) { return audit.Search(dir, f) }
	}
	if err := a.ui.Add(templateFS, ui.LayoutApp, "notice", "approvals", "approval", "requests", "console", "audit", "audit_entry",
		"users", "user", "propose", "breakglass"); err != nil {
		return nil, err
	}
	a.ui.SetNav(a.nav)
	a.auth.SetApprovals(a.svc)
	return a, nil
}

// Register adds the pages to mux.
func (a *App) Register(mux *http.ServeMux) {
	for pattern, h := range map[string]http.HandlerFunc{
		"GET /{$}":                        a.handleRoot,
		"GET /approvals":                  a.handleApprovals,
		"GET /approvals/{id}":             a.handleApproval,
		"POST /approvals/{id}/approve":    a.handleApprove,
		"POST /approvals/{id}/reject":     a.handleReject,
		"GET /requests":                   a.handleRequests,
		"POST /requests/{id}/cancel":      a.handleCancel,
		"GET /console":                    a.handleConsole,
		"POST /console":                   a.handleConsoleRun,
		"POST /console/saved/{id}/delete": a.handleSavedDelete,
		"GET /audit":                      a.handleAudit,
		"GET /audit/{request_id}":         a.handleAuditEntry,
		"GET /users":                      a.handleUsers,
		"GET /users/{email}":              a.handleUser,
		"GET /users/{email}/propose":      a.handlePropose,
		"GET /breakglass":                 a.handleBreakGlass,
		"POST /breakglass":                a.handleElevate,
	} {
		mux.Handle(pattern, a.ui.Wrap(h))
	}
}

// viewer is the logged-in human of a request.
type viewer struct {
	ws *auth.WebSession
	p  *identity.Principal
}

// viewer returns the logged-in human, or writes a response (login redirect
// or error page) and returns false.
func (a *App) viewer(w http.ResponseWriter, r *http.Request) (*viewer, bool) {
	ws, err := a.auth.Session(r)
	if err != nil {
		a.serverError(w, r, "", err)
		return nil, false
	}
	if ws == nil {
		if r.Method == http.MethodGet {
			a.auth.RedirectToLogin(w, r)
		} else {
			a.notice(w, r, "", http.StatusUnauthorized, "error.session_expired")
		}
		return nil, false
	}
	p, err := a.auth.HumanPrincipal(r.Context(), ws.Email)
	if errors.Is(err, auth.ErrUserInactive) {
		a.notice(w, r, "", http.StatusForbidden, "error.user_inactive")
		return nil, false
	}
	if err != nil {
		a.serverError(w, r, ws.Email, err)
		return nil, false
	}
	return &viewer{ws: ws, p: p}, true
}

// post returns the logged-in human of a form submission with a valid CSRF
// token.
func (a *App) post(w http.ResponseWriter, r *http.Request) (*viewer, bool) {
	v, ok := a.viewer(w, r)
	if !ok {
		return nil, false
	}
	if !v.ws.CheckCSRF(r) {
		a.notice(w, r, v.ws.Email, http.StatusBadRequest, "error.form_expired")
		return nil, false
	}
	return v, true
}

// notice renders a message inside the app frame (errors, disabled
// features, missing permissions).
func (a *App) notice(w http.ResponseWriter, r *http.Request, email string, status int, msgKey string) {
	heading := "error.heading"
	switch status {
	case http.StatusForbidden:
		heading = "notice.forbidden_heading"
	case http.StatusNotFound:
		heading = "notice.not_found_heading"
	}
	page := ui.Page{Name: "notice", Title: "title.error", Status: status, User: email,
		Data: map[string]any{"Heading": heading, "Message": msgKey}}
	if email == "" {
		// Not logged in: no navigation, but keep the frame.
		page.Data["Anonymous"] = true
	}
	a.ui.Render(w, r, page)
}

func (a *App) serverError(w http.ResponseWriter, r *http.Request, email string, err error) {
	a.log.Error("web: internal error", "path", r.URL.Path, "err", err)
	a.notice(w, r, email, http.StatusInternalServerError, "error.internal")
}

func (a *App) forbidden(w http.ResponseWriter, r *http.Request, v *viewer, msgKey string) {
	a.notice(w, r, v.ws.Email, http.StatusForbidden, msgKey)
}

// render renders an app page for v.
func (a *App) render(w http.ResponseWriter, r *http.Request, v *viewer, status int, name, title, active, width string, data map[string]any, scripts ...string) {
	if data == nil {
		data = map[string]any{}
	}
	data["CSRF"] = v.ws.CSRF
	a.ui.Render(w, r, ui.Page{Name: name, Title: title, Status: status, User: v.ws.Email, Active: active, Width: width,
		Scripts: scripts, Data: data})
}

// ---------------------------------------------------------------------------
// Permissions

// hasRoleAnywhere reports whether p holds role on any database.
func (a *App) hasRoleAnywhere(p *identity.Principal, role identity.Role) bool {
	for i := range a.cfg.Databases {
		if a.rbac.Has(p, &a.cfg.Databases[i], role) {
			return true
		}
	}
	return false
}

// isAdmin: the admin role on any database.
func (a *App) isAdmin(p *identity.Principal) bool { return a.hasRoleAnywhere(p, identity.RoleAdmin) }

// isAuditor: listed in auditors, or an admin.
func (a *App) isAuditor(p *identity.Principal) bool {
	return a.cfg.IsAuditor(p.Human, p.Groups) || a.isAdmin(p)
}

// isApprover reports whether p could approve some request: a role used by
// an approval step on some database, or membership of a step's group.
func (a *App) isApprover(p *identity.Principal) bool {
	if a.svc == nil {
		return false
	}
	for _, rule := range a.cfg.ApprovalRules {
		for _, st := range rule.Steps {
			if st.Group != "" && slices.Contains(p.Groups, st.Group) {
				return true
			}
			if st.Role != "" && a.hasRoleAnywhere(p, st.Role) {
				return true
			}
		}
	}
	return false
}

// breakGlassDatabases are the databases p may elevate on.
func (a *App) breakGlassDatabases(p *identity.Principal) []*config.Database {
	bg := a.cfg.BreakGlass
	if a.svc == nil || bg == nil {
		return nil
	}
	var out []*config.Database
	for i := range a.cfg.Databases {
		db := &a.cfg.Databases[i]
		if bg.Databases.Matches(db) && a.rbac.Has(p, db, identity.RoleApprover) {
			out = append(out, db)
		}
	}
	return out
}

// readableDatabases are the databases p may query (console).
func (a *App) readableDatabases(p *identity.Principal) []gateway.DatabaseInfo {
	var out []gateway.DatabaseInfo
	for _, d := range a.gw.ListDatabases(p) {
		if d.CanRead {
			out = append(out, d)
		}
	}
	return out
}

// nav lists the sections the user may use.
func (a *App) nav(r *http.Request, email string) []ui.NavItem {
	p, err := a.auth.HumanPrincipal(r.Context(), email)
	if err != nil {
		return nil
	}
	var items []ui.NavItem
	if a.isApprover(p) {
		n := 0
		if list, err := a.svc.List(r.Context(), p, approval.ListFilter{Scope: approval.ScopeAwaitingMe, Limit: 200}); err == nil {
			n = len(list)
		}
		items = append(items, ui.NavItem{Key: "approvals", Label: "nav.approvals", Href: "/approvals", Badge: n})
	}
	if a.svc != nil && a.hasRoleAnywhere(p, identity.RoleWriter) {
		items = append(items, ui.NavItem{Key: "requests", Label: "nav.requests", Href: "/requests"})
	}
	if len(a.readableDatabases(p)) > 0 {
		items = append(items, ui.NavItem{Key: "console", Label: "nav.console", Href: "/console"})
	}
	if a.isAuditor(p) {
		items = append(items,
			ui.NavItem{Key: "audit", Label: "nav.audit", Href: "/audit"},
			ui.NavItem{Key: "users", Label: "nav.users", Href: "/users"})
	}
	return items
}

// handleRoot sends the user to the first section they may use.
func (a *App) handleRoot(w http.ResponseWriter, r *http.Request) {
	v, ok := a.viewer(w, r)
	if !ok {
		return
	}
	if items := a.nav(r, v.ws.Email); len(items) > 0 {
		http.Redirect(w, r, items[0].Href, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/account", http.StatusFound)
}

func sameHuman(a, b string) bool { return a != "" && strings.EqualFold(a, b) }
