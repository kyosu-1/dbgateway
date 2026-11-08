package policy

import (
	"slices"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

// RBAC answers "which roles does this principal have on this database".
//
// Roles come from group × database × role bindings. An agent never exceeds
// the human it acts for: its roles are the human's roles, narrowed by the
// token's scopes and database restriction, and never include approver or
// admin.
type RBAC struct {
	cfg *config.Config
	now func() time.Time
}

// NewRBAC returns an RBAC evaluator for cfg.
func NewRBAC(cfg *config.Config) *RBAC {
	return &RBAC{cfg: cfg, now: time.Now}
}

// ResolveGroups maps an identity to dbgateway group names, using the IdP
// groups (matched against groups[].oidc_group) and static members.
func (r *RBAC) ResolveGroups(email string, idpGroups []string) []string {
	var out []string
	for _, g := range r.cfg.Groups {
		if g.OIDCGroup != "" && slices.Contains(idpGroups, g.OIDCGroup) {
			out = append(out, g.Name)
			continue
		}
		if slices.ContainsFunc(g.Members, func(m string) bool { return strings.EqualFold(m, email) }) {
			out = append(out, g.Name)
		}
	}
	return out
}

// humanRoles returns the roles granted on db to the human with the given
// e-mail, through group bindings or user bindings.
func (r *RBAC) humanRoles(email string, groups []string, db *config.Database) []identity.Role {
	now := r.now()
	var out []identity.Role
	for _, rb := range r.cfg.RoleBindings {
		if !bindingApplies(rb.Group, rb.User, email, groups) || !rb.Databases.Matches(db) {
			continue
		}
		if rb.ExpiresAt != nil && !now.Before(*rb.ExpiresAt) {
			continue
		}
		for _, role := range rb.Roles {
			if !slices.Contains(out, role) {
				out = append(out, role)
			}
		}
	}
	// querier implies viewer.
	if slices.Contains(out, identity.RoleQuerier) && !slices.Contains(out, identity.RoleViewer) {
		out = append(out, identity.RoleViewer)
	}
	return out
}

// Roles returns the effective roles of p on db.
func (r *RBAC) Roles(p *identity.Principal, db *config.Database) []identity.Role {
	if p == nil || db == nil || !p.AllowsDatabase(db.Name) {
		return nil
	}
	roles := r.humanRoles(p.Human, p.Groups, db)
	if !p.IsAgent() {
		return roles
	}
	// Agents: narrow by token scope; never approver/admin.
	var allowed []identity.Role
	if p.HasScope(identity.ScopeRead) {
		allowed = append(allowed, identity.RoleViewer, identity.RoleQuerier)
	}
	if p.HasScope(identity.ScopeWrite) {
		allowed = append(allowed, identity.RoleWriter)
	}
	var out []identity.Role
	for _, role := range roles {
		if slices.Contains(allowed, role) {
			out = append(out, role)
		}
	}
	return out
}

// Has reports whether p has role on db.
func (r *RBAC) Has(p *identity.Principal, db *config.Database, role identity.Role) bool {
	return slices.Contains(r.Roles(p, db), role)
}

// bindingApplies reports whether a binding for group or user covers the
// human with the given e-mail and groups.
func bindingApplies(group, user, email string, groups []string) bool {
	if user != "" {
		return email != "" && strings.EqualFold(user, email)
	}
	return group != "" && slices.Contains(groups, group)
}

// HumanHas reports whether the human with the given e-mail and dbgateway
// groups holds role on db (no token narrowing). Used to find approvers.
func (r *RBAC) HumanHas(email string, groups []string, db *config.Database, role identity.Role) bool {
	return slices.Contains(r.humanRoles(email, groups, db), role)
}

// HasUnmask reports whether p may see masked columns of db unmasked.
// Unmask is granted separately from roles and only ever to humans.
func (r *RBAC) HasUnmask(p *identity.Principal, db *config.Database) bool {
	if p == nil || db == nil || p.Kind != identity.KindHuman {
		return false
	}
	now := r.now()
	for _, u := range r.cfg.Unmask {
		if !bindingApplies(u.Group, u.User, p.Human, p.Groups) || !u.Databases.Matches(db) {
			continue
		}
		if u.ExpiresAt != nil && !now.Before(*u.ExpiresAt) {
			continue
		}
		return true
	}
	return false
}

// KnownHumans returns the e-mail addresses named in the configuration
// (static group members and user bindings), lower-cased and sorted.
func (r *RBAC) KnownHumans() []string {
	var out []string
	add := func(e string) {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" && !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	for _, g := range r.cfg.Groups {
		for _, m := range g.Members {
			add(m)
		}
	}
	for _, rb := range r.cfg.RoleBindings {
		add(rb.User)
	}
	slices.Sort(out)
	return out
}

// Accessible returns the databases on which p has at least one role.
func (r *RBAC) Accessible(p *identity.Principal) []*config.Database {
	var out []*config.Database
	for i := range r.cfg.Databases {
		db := &r.cfg.Databases[i]
		if len(r.Roles(p, db)) > 0 {
			out = append(out, db)
		}
	}
	return out
}
