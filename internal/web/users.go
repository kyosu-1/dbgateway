package web

import (
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/auth"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
	"github.com/kyosu-1/dbgateway/internal/web/i18n"
	"github.com/kyosu-1/dbgateway/internal/web/ui"
)

// knownUser is a person known to dbgateway: someone who logged in (or was
// provisioned) and/or is named in the configuration.
type knownUser struct {
	Email     string
	Groups    []string
	Admin     bool
	Active    bool
	LastLogin *time.Time
	InConfig  bool
}

// knownUsers lists store users and people named in the configuration.
func (a *App) knownUsers(r *http.Request) ([]*knownUser, error) {
	ctx := r.Context()
	users, err := a.st.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	byEmail := map[string]*knownUser{}
	idp := map[string][]string{}
	for _, u := range users {
		e := strings.ToLower(u.Email)
		last := u.LastLoginAt
		byEmail[e] = &knownUser{Email: e, LastLogin: &last}
		idp[e] = u.IDPGroups
	}
	for _, e := range a.rbac.KnownHumans() {
		if ku, ok := byEmail[e]; ok {
			ku.InConfig = true
			continue
		}
		byEmail[e] = &knownUser{Email: e, InConfig: true}
	}
	var out []*knownUser
	for e, ku := range byEmail {
		ku.Groups = a.rbac.ResolveGroups(e, idp[e])
		p := &identity.Principal{Kind: identity.KindHuman, Human: e, Groups: ku.Groups}
		ku.Admin = a.isAdmin(p)
		active, err := a.st.UserActive(ctx, e)
		if err != nil {
			return nil, err
		}
		ku.Active = active
		out = append(out, ku)
	}
	slices.SortFunc(out, func(x, y *knownUser) int { return strings.Compare(x.Email, y.Email) })
	return out, nil
}

// handleUsers lists people (auditors and admins).
func (a *App) handleUsers(w http.ResponseWriter, r *http.Request) {
	v, ok := a.viewer(w, r)
	if !ok {
		return
	}
	if !a.isAuditor(v.p) {
		a.forbidden(w, r, v, "users.forbidden")
		return
	}
	users, err := a.knownUsers(r)
	if err != nil {
		a.serverError(w, r, v.ws.Email, err)
		return
	}
	q := strings.ToLower(clip(r.URL.Query().Get("q"), 254))
	group := r.URL.Query().Get("group")
	var rows []*knownUser
	for _, u := range users {
		if q != "" && !strings.Contains(u.Email, q) {
			continue
		}
		if group != "" && !slices.Contains(u.Groups, group) {
			continue
		}
		rows = append(rows, u)
	}
	var groups []string
	for _, g := range a.cfg.Groups {
		groups = append(groups, g.Name)
	}
	a.render(w, r, v, http.StatusOK, "users", "title.users", "users", ui.WidthWide, map[string]any{
		"Users": rows, "Q": q, "Group": group, "Groups": groups, "IdP": a.cfg.Auth.OIDC != nil,
	})
}

// bindingView is one role binding that applies to a person on a database.
type bindingView struct {
	Roles   string
	Group   string // empty for a personal (user:) binding
	Expires *time.Time
	Soon    bool // expires within 7 days
}

type dbRolesView struct {
	Name     string
	Roles    string
	Bindings []bindingView
	Unmask   bool
}

// lookupUser finds a known person by the e-mail in the path.
func (a *App) lookupUser(r *http.Request) (*knownUser, bool, error) {
	email := strings.ToLower(r.PathValue("email"))
	users, err := a.knownUsers(r)
	if err != nil {
		return nil, false, err
	}
	i := slices.IndexFunc(users, func(u *knownUser) bool { return u.Email == email })
	if i < 0 {
		return nil, false, nil
	}
	return users[i], true, nil
}

// handleUser shows one person: groups, roles per database, agents,
// passkeys and recent activity.
func (a *App) handleUser(w http.ResponseWriter, r *http.Request) {
	v, ok := a.viewer(w, r)
	if !ok {
		return
	}
	if !a.isAuditor(v.p) {
		a.forbidden(w, r, v, "users.forbidden")
		return
	}
	u, found, err := a.lookupUser(r)
	if err != nil {
		a.serverError(w, r, v.ws.Email, err)
		return
	}
	if !found {
		a.notice(w, r, v.ws.Email, http.StatusNotFound, "users.not_found")
		return
	}
	ctx := r.Context()
	now := a.now()
	person := &identity.Principal{Kind: identity.KindHuman, Human: u.Email, Groups: u.Groups}
	var dbs []dbRolesView
	for i := range a.cfg.Databases {
		db := &a.cfg.Databases[i]
		roles := a.rbac.Roles(person, db)
		row := dbRolesView{Name: db.Name, Unmask: a.rbac.HasUnmask(person, db)}
		var names []string
		for _, role := range roles {
			names = append(names, string(role))
		}
		row.Roles = strings.Join(names, ", ")
		for _, rb := range a.cfg.RoleBindings {
			if !rb.Databases.Matches(db) || !auth.BindingCovers(rb.Group, rb.User, u.Email, u.Groups) {
				continue
			}
			if rb.ExpiresAt != nil && !now.Before(*rb.ExpiresAt) {
				continue
			}
			var rs []string
			for _, role := range rb.Roles {
				rs = append(rs, string(role))
			}
			bv := bindingView{Roles: strings.Join(rs, ", "), Group: rb.Group, Expires: rb.ExpiresAt}
			bv.Soon = rb.ExpiresAt != nil && rb.ExpiresAt.Sub(now) < 7*24*time.Hour
			row.Bindings = append(row.Bindings, bv)
		}
		if len(roles) > 0 || row.Unmask {
			dbs = append(dbs, row)
		}
	}
	tokens, err := a.st.ListTokens(ctx, u.Email)
	if err != nil {
		a.serverError(w, r, v.ws.Email, err)
		return
	}
	pks, err := a.st.ListPasskeys(ctx, u.Email)
	if err != nil {
		a.serverError(w, r, v.ws.Email, err)
		return
	}
	data := map[string]any{
		"U": u, "Databases": dbs, "Agents": activeAgents(tokens, now), "Passkeys": len(pks),
		"ProposeURL": "/users/" + url.PathEscape(u.Email) + "/propose",
		"AuditURL":   "/audit?" + url.Values{"principal": {u.Email}, "period": {"30d"}}.Encode(),
		"IdP":        a.cfg.Auth.OIDC != nil,
	}
	if a.cfg.Audit.Output == "file" {
		page, err := audit.Search(a.cfg.Audit.Dir, audit.Filter{Principal: u.Email, Limit: 40})
		if err != nil {
			a.log.Warn("web: recent activity", "err", err)
		}
		p := a.ui.Printer(r)
		var rows []auditRow
		for i := range page.Entries {
			e := &page.Entries[i]
			if !strings.EqualFold(e.Principal.Human, u.Email) {
				continue
			}
			sub := auditPrincipal(p, e.Principal)
			if e.Database != "" {
				sub += " · " + e.Database
			}
			rows = append(rows, auditRow{Href: "/audit/" + url.PathEscape(e.RequestID), Time: entryTime(e), Decision: decisionPill(e.Decision),
				Title: auditTitle(p, e), Sub: sub})
			if len(rows) == 10 {
				break
			}
		}
		data["Activity"] = rows
		data["ActivityEnabled"] = true
	}
	a.render(w, r, v, http.StatusOK, "user", "title.user", "users", ui.WidthDefault, data)
}

// agentRow is an active agent grant of a person.
type agentRow struct {
	Agent     string
	Manual    bool
	Databases []string
	Expires   time.Time
}

// activeAgents groups a person's active agent tokens by grant.
func activeAgents(tokens []*store.Token, now time.Time) []agentRow {
	var out []agentRow
	seen := map[string]int{}
	for _, t := range tokens {
		if t.Kind != identity.KindAgent || !t.Active(now) {
			continue
		}
		key := t.FamilyID
		if key == "" {
			key = t.ID
		}
		if i, ok := seen[key]; ok {
			if t.ExpiresAt.After(out[i].Expires) {
				out[i].Expires = t.ExpiresAt
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, agentRow{Agent: t.Agent, Manual: t.ClientID == auth.CLIClientID, Databases: t.Databases, Expires: t.ExpiresAt})
	}
	return out
}

// ---------------------------------------------------------------------------
// Role change proposals

// proposalRoles are the roles offered on the proposal form.
var proposalRoles = []identity.Role{identity.RoleViewer, identity.RoleQuerier, identity.RoleWriter, identity.RoleApprover, identity.RoleAdmin}

// proposal is a generated role_bindings entry and PR text.
type proposal struct {
	YAML      string
	YAMLLines []string // added lines (for the diff view)
	PRTitle   string
	PRBody    string
}

var plainYAML = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._%+\-@]*$`)

func yamlScalar(s string) string {
	if plainYAML.MatchString(s) {
		return s
	}
	return strconv.Quote(s)
}

// buildProposal renders the role binding for email (validated input).
func buildProposal(p *i18n.Printer, email, proposer string, dbs []string, roles []identity.Role, expires *time.Time, reason string) proposal {
	quoted := make([]string, len(dbs))
	for i, d := range dbs {
		quoted[i] = strconv.Quote(d)
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = string(r)
	}
	lines := []string{
		"  - user: " + yamlScalar(email),
		"    databases: [" + strings.Join(quoted, ", ") + "]",
		"    roles: [" + strings.Join(roleNames, ", ") + "]",
	}
	until := p.T("propose.no_expiry")
	if expires != nil {
		lines = append(lines, "    expires_at: "+expires.Format(time.RFC3339))
		until = expires.Format("2006-01-02 15:04 (Z07:00)")
	}
	pr := proposal{YAMLLines: lines, YAML: "role_bindings:\n" + strings.Join(lines, "\n") + "\n"}
	pr.PRTitle = p.T("propose.pr_title", email, strings.Join(roleNames, ", "), strings.Join(dbs, ", "))
	body := []string{
		p.T("propose.pr_changes"),
		p.T("propose.pr_user", email),
		p.T("propose.pr_databases", strings.Join(dbs, ", ")),
		p.T("propose.pr_roles", strings.Join(roleNames, ", ")),
		p.T("propose.pr_expires", until),
		"",
		p.T("propose.pr_reason"),
		reason,
		"",
		p.T("propose.pr_footer", proposer),
	}
	pr.PRBody = strings.Join(body, "\n") + "\n"
	return pr
}

// handlePropose shows the role change proposal form and, with generate=1,
// the YAML for role_bindings and a PR description. Nothing is written by
// the server: changes go through the configuration repository.
func (a *App) handlePropose(w http.ResponseWriter, r *http.Request) {
	v, ok := a.viewer(w, r)
	if !ok {
		return
	}
	if !a.isAuditor(v.p) {
		a.forbidden(w, r, v, "users.forbidden")
		return
	}
	u, found, err := a.lookupUser(r)
	if err != nil {
		a.serverError(w, r, v.ws.Email, err)
		return
	}
	if !found {
		a.notice(w, r, v.ws.Email, http.StatusNotFound, "users.not_found")
		return
	}
	q := r.URL.Query()
	var dbNames []string
	for _, db := range a.cfg.Databases {
		dbNames = append(dbNames, db.Name)
	}
	data := map[string]any{
		"U": u, "Databases": dbNames, "Roles": proposalRoles, "SelDBs": q["db"], "SelRoles": q["role"],
		"Expires": clip(q.Get("expires"), 32), "Reason": clip(q.Get("reason"), 1000), "Zone": a.now().Format("MST (Z07:00)"),
		"UserURL": "/users/" + url.PathEscape(u.Email), "FormURL": "/users/" + url.PathEscape(u.Email) + "/propose",
	}
	status := http.StatusOK
	if q.Get("generate") == "1" {
		var errs []string
		var dbs []string
		for _, d := range q["db"] {
			if a.cfg.Database(d) == nil {
				errs = append(errs, "propose.error_database")
				break
			}
			if !slices.Contains(dbs, d) {
				dbs = append(dbs, d)
			}
		}
		if len(dbs) == 0 && len(errs) == 0 {
			errs = append(errs, "propose.error_no_database")
		}
		var roles []identity.Role
		for _, role := range proposalRoles { // keep the canonical order
			if slices.Contains(q["role"], string(role)) {
				roles = append(roles, role)
			}
		}
		for _, raw := range q["role"] {
			if !identity.Role(raw).Valid() {
				errs = append(errs, "propose.error_role")
				break
			}
		}
		if len(roles) == 0 {
			errs = append(errs, "propose.error_no_role")
		}
		var expires *time.Time
		if s := strings.TrimSpace(q.Get("expires")); s != "" {
			t, err := time.ParseInLocation("2006-01-02T15:04", s, a.now().Location())
			switch {
			case err != nil:
				errs = append(errs, "propose.error_expires")
			case !t.After(a.now()):
				errs = append(errs, "propose.error_expires_past")
			default:
				expires = &t
			}
		}
		reason := strings.TrimSpace(data["Reason"].(string))
		if reason == "" {
			errs = append(errs, "propose.error_reason")
		}
		if _, err := mail.ParseAddress(u.Email); err != nil {
			errs = append(errs, "users.not_found")
		}
		if len(errs) > 0 {
			data["Errors"] = errs
			status = http.StatusBadRequest
		} else {
			pr := buildProposal(a.ui.Printer(r), u.Email, v.p.Human, dbs, roles, expires, ui.InertText(reason))
			data["Proposal"] = pr
		}
	}
	a.render(w, r, v, status, "propose", "title.propose", "users", ui.WidthNarrow, data, "/static/copy.js")
}
