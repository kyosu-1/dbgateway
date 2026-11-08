// Package identity defines who is making a request (the principal) and the
// fixed set of roles. It has no dependencies so every layer can share it.
package identity

import (
	"context"
	"slices"
)

// Kind distinguishes humans from AI agents acting on behalf of a human.
type Kind string

const (
	KindHuman Kind = "human"
	KindAgent Kind = "agent"
)

// Role is one of the fixed MVP roles.
type Role string

const (
	RoleViewer   Role = "viewer"   // schema only
	RoleQuerier  Role = "querier"  // read queries (masked)
	RoleWriter   Role = "writer"   // request writes (approval required)
	RoleApprover Role = "approver" // approve/reject writes for a database
	RoleAdmin    Role = "admin"    // operational actions
)

// AllRoles lists every valid role.
var AllRoles = []Role{RoleViewer, RoleQuerier, RoleWriter, RoleApprover, RoleAdmin}

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return slices.Contains(AllRoles, r) }

// OAuth scopes understood by dbgateway.
const (
	ScopeRead  = "db:read"  // schema exploration and read queries
	ScopeWrite = "db:write" // write requests (phase 2)
)

// Principal is the authenticated caller.
//
// For agents, Human is the person on whose behalf the agent acts, and the
// agent can never exceed that person's permissions. Databases and Scopes
// narrow the agent further.
type Principal struct {
	Kind     Kind     `json:"kind"`
	Human    string   `json:"human"`               // email / subject of the human
	Groups   []string `json:"groups,omitempty"`    // dbgateway group names
	Agent    string   `json:"agent,omitempty"`     // name registered at consent time
	ClientID string   `json:"client_id,omitempty"` // OAuth client ID
	// ClientName is the self-reported client name. Informational only; it is
	// recorded in the audit log but never used for decisions.
	ClientName string   `json:"client_name,omitempty"`
	Scopes     []string `json:"-"`
	// Databases restricts which databases the token may touch. Nil or empty
	// means "no extra restriction" (role bindings still apply).
	Databases []string `json:"-"`
	TokenID   string   `json:"-"`
}

// IsAgent reports whether the principal is an AI agent.
func (p *Principal) IsAgent() bool { return p.Kind == KindAgent }

// HasScope reports whether the token carries scope s.
func (p *Principal) HasScope(s string) bool { return slices.Contains(p.Scopes, s) }

// AllowsDatabase reports whether the token's database restriction permits db.
func (p *Principal) AllowsDatabase(db string) bool {
	if len(p.Databases) == 0 {
		return true
	}
	return slices.Contains(p.Databases, db) || slices.Contains(p.Databases, "*")
}

type ctxKey struct{}

// WithPrincipal returns a context carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the principal stored in ctx, or nil.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}
