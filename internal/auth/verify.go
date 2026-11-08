package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// principalKey is the TokenInfo.Extra key holding the *identity.Principal.
const principalKey = "principal"

// maxTokenLen bounds the bearer value before it is hashed and looked up.
const maxTokenLen = 256

// VerifyToken verifies a bearer token presented to the MCP endpoint. It
// matches mcpauth.TokenVerifier. Only tokens whose audience is the MCP
// resource are accepted (agent tokens); human CLI tokens are rejected here so
// that an AI client can never act with a human's unrestricted identity.
//
// Token problems return an error wrapping mcpauth.ErrInvalidToken; internal
// errors (for example the store being unavailable) are returned as is.
func (s *Server) VerifyToken(ctx context.Context, token string, _ *http.Request) (*mcpauth.TokenInfo, error) {
	t, p, err := s.verify(ctx, token)
	if err != nil {
		return nil, err
	}
	if t.Audience != s.ResourceURL() {
		return nil, fmt.Errorf("%w: token audience is not %s", mcpauth.ErrInvalidToken, s.ResourceURL())
	}
	return &mcpauth.TokenInfo{
		Scopes:     p.Scopes,
		Expiration: t.ExpiresAt,
		UserID:     p.Human,
		Extra:      map[string]any{principalKey: p},
	}, nil
}

// Authenticate verifies a bearer token presented to the dbgateway API and
// returns the principal. Both human (CLI) and agent tokens are accepted;
// callers decide which kinds they allow.
func (s *Server) Authenticate(ctx context.Context, bearer string) (*identity.Principal, error) {
	_, p, err := s.verify(ctx, bearer)
	return p, err
}

// PrincipalFromTokenInfo returns the principal stored by VerifyToken, or nil.
func PrincipalFromTokenInfo(ti *mcpauth.TokenInfo) *identity.Principal {
	if ti == nil {
		return nil
	}
	p, _ := ti.Extra[principalKey].(*identity.Principal)
	return p
}

// BearerToken extracts the token from an "Authorization: Bearer" header
// value. It returns "" if there is none.
func BearerToken(header string) string {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

func invalid(reason string) error {
	return fmt.Errorf("%w: %s", mcpauth.ErrInvalidToken, reason)
}

// verify loads and checks an access token and builds its principal.
func (s *Server) verify(ctx context.Context, raw string) (*store.Token, *identity.Principal, error) {
	if !strings.HasPrefix(raw, AccessTokenPrefix) || len(raw) > maxTokenLen {
		return nil, nil, invalid("malformed token")
	}
	t, err := s.store.GetTokenByHash(ctx, store.HashSecret(raw))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, invalid("unknown token")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("auth: load token: %w", err)
	}
	now := s.now()
	switch {
	case t.Type != store.TokenAccess:
		return nil, nil, invalid("not an access token")
	case t.RevokedAt != nil:
		return nil, nil, invalid("token revoked")
	case !now.Before(t.ExpiresAt):
		return nil, nil, invalid("token expired")
	}
	switch t.Kind {
	case identity.KindAgent:
		// Agent tokens are always bound to the MCP resource and to an
		// explicit set of databases.
		if t.Audience != s.ResourceURL() {
			return nil, nil, invalid("audience mismatch")
		}
		if len(t.Databases) == 0 || t.Agent == "" {
			return nil, nil, invalid("agent token without databases")
		}
	case identity.KindHuman:
		if t.Audience != s.issuer && t.Audience != s.ResourceURL() {
			return nil, nil, invalid("audience mismatch")
		}
	default:
		return nil, nil, invalid("unknown token kind")
	}
	p, err := s.principal(ctx, t)
	if err != nil {
		return nil, nil, err
	}
	return t, p, nil
}

// principal builds the principal of a token. Groups are resolved now, from
// the IdP groups snapshot and the current configuration.
func (s *Server) principal(ctx context.Context, t *store.Token) (*identity.Principal, error) {
	groups, err := s.groupsOf(ctx, t.Human)
	if err != nil {
		return nil, err
	}
	return &identity.Principal{
		Kind:       t.Kind,
		Human:      t.Human,
		Groups:     groups,
		Agent:      t.Agent,
		ClientID:   t.ClientID,
		ClientName: t.ClientName,
		Scopes:     append([]string(nil), t.Scopes...),
		Databases:  append([]string(nil), t.Databases...),
		TokenID:    t.ID,
	}, nil
}

// humanPrincipal is the principal of a logged-in human (browser session).
func (s *Server) humanPrincipal(ctx context.Context, email string) (*identity.Principal, error) {
	groups, err := s.groupsOf(ctx, email)
	if err != nil {
		return nil, err
	}
	return &identity.Principal{Kind: identity.KindHuman, Human: email, Groups: groups, Scopes: []string{identity.ScopeRead}}, nil
}

func (s *Server) groupsOf(ctx context.Context, email string) ([]string, error) {
	var idpGroups []string
	u, err := s.store.GetUser(ctx, email)
	switch {
	case err == nil:
		idpGroups = u.IDPGroups
	case errors.Is(err, store.ErrNotFound):
		// Static group members still resolve by email.
	default:
		return nil, fmt.Errorf("auth: load user: %w", err)
	}
	return s.rbac.ResolveGroups(email, idpGroups), nil
}
