package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

var (
	// ErrInvalidRequest is returned by MintAgentToken for malformed input.
	ErrInvalidRequest = errors.New("invalid request")
	// ErrPermissionDenied is returned by MintAgentToken when the caller may
	// not mint the requested token.
	ErrPermissionDenied = errors.New("permission denied")
)

// tokenResponse is the RFC 6749 §5.1 token response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// issue stores a new access token built from tmpl (and a refresh token when
// refreshExpiry is non-zero) and returns the token response.
func (s *Server) issue(ctx context.Context, tmpl store.Token, ttl time.Duration, refreshExpiry time.Time) (*tokenResponse, error) {
	now := s.now()
	at := tmpl
	raw, hash := newSecret(AccessTokenPrefix)
	at.ID, at.Hash, at.Type = newID("tok_"), hash, store.TokenAccess
	at.CreatedAt, at.ExpiresAt = now, now.Add(ttl)
	at.UsedAt, at.RevokedAt = nil, nil
	if err := s.store.CreateToken(ctx, &at); err != nil {
		return nil, fmt.Errorf("auth: store access token: %w", err)
	}
	resp := &tokenResponse{
		AccessToken: raw,
		TokenType:   "Bearer",
		ExpiresIn:   int64(ttl / time.Second),
		Scope:       strings.Join(at.Scopes, " "),
	}
	if !refreshExpiry.IsZero() && now.Before(refreshExpiry) {
		rt := tmpl
		rraw, rhash := newSecret(RefreshTokenPrefix)
		rt.ID, rt.Hash, rt.Type = newID("tok_"), rhash, store.TokenRefresh
		rt.CreatedAt, rt.ExpiresAt = now, refreshExpiry
		rt.UsedAt, rt.RevokedAt = nil, nil
		if err := s.store.CreateToken(ctx, &rt); err != nil {
			return nil, fmt.Errorf("auth: store refresh token: %w", err)
		}
		resp.RefreshToken = rraw
	}
	return resp, nil
}

// AgentTokenRequest describes an agent token minted directly by a human
// (without the OAuth consent flow), e.g. by `dbgw token create` or
// `dbgw mcp stdio`.
type AgentTokenRequest struct {
	AgentName string
	Databases []string
	// TTL is capped to auth.agent_tokens.max_ttl. Zero means the maximum.
	TTL    time.Duration
	Scopes []string
}

// MintAgentToken issues an agent access token on behalf of caller, who must
// be a human authenticated with a token. The agent is restricted to a subset
// of the databases the human can access, and never outlives the caller's
// token. It returns the raw token and its stored record.
func (s *Server) MintAgentToken(ctx context.Context, caller *identity.Principal, req AgentTokenRequest) (string, *store.Token, error) {
	if caller == nil || caller.Kind != identity.KindHuman || caller.TokenID == "" {
		return "", nil, fmt.Errorf("%w: only humans can mint agent tokens", ErrPermissionDenied)
	}
	name, err := validAgentName(req.AgentName)
	if err != nil {
		return "", nil, err
	}
	scopes, err := grantableScopes(req.Scopes)
	if err != nil {
		return "", nil, err
	}
	dbs, err := s.allowedDatabases(caller, req.Databases)
	if err != nil {
		return "", nil, err
	}
	parent, err := s.store.GetToken(ctx, caller.TokenID)
	if err != nil {
		return "", nil, fmt.Errorf("auth: load caller token: %w", err)
	}
	maxTTL := s.cfg.Auth.AgentTokens.MaxTTL.D()
	ttl := req.TTL
	if ttl <= 0 || ttl > maxTTL {
		ttl = maxTTL
	}
	if remaining := parent.ExpiresAt.Sub(s.now()); remaining < ttl {
		ttl = remaining
	}
	if ttl < time.Second {
		return "", nil, fmt.Errorf("%w: caller token is about to expire", ErrPermissionDenied)
	}
	resp, err := s.issue(ctx, store.Token{
		Kind:       identity.KindAgent,
		Human:      caller.Human,
		Agent:      name,
		ClientID:   CLIClientID,
		ClientName: CLIClientName,
		Scopes:     scopes,
		Databases:  dbs,
		Audience:   s.ResourceURL(),
		ParentID:   parent.ID,
	}, ttl, time.Time{})
	if err != nil {
		return "", nil, err
	}
	t, err := s.store.GetTokenByHash(ctx, store.HashSecret(resp.AccessToken))
	if err != nil {
		return "", nil, fmt.Errorf("auth: reload token: %w", err)
	}
	return resp.AccessToken, t, nil
}

// allowedDatabases validates that requested is a non-empty subset of the
// databases the human can read, and returns it deduplicated.
func (s *Server) allowedDatabases(human *identity.Principal, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return nil, fmt.Errorf("%w: at least one database is required", ErrInvalidRequest)
	}
	accessible := s.accessibleNames(human)
	var out []string
	for _, db := range requested {
		if db == "" || db == "*" {
			return nil, fmt.Errorf("%w: invalid database name %q", ErrInvalidRequest, db)
		}
		if !slices.Contains(accessible, db) {
			return nil, fmt.Errorf("%w: no access to database %q", ErrPermissionDenied, db)
		}
		if !slices.Contains(out, db) {
			out = append(out, db)
		}
	}
	return out, nil
}

// accessibleNames lists the databases an agent of this human could read.
func (s *Server) accessibleNames(human *identity.Principal) []string {
	probe := *human
	probe.Kind = identity.KindAgent
	probe.Scopes = []string{identity.ScopeRead}
	probe.Databases = nil
	var out []string
	for _, db := range s.rbac.Accessible(&probe) {
		out = append(out, db.Name)
	}
	return out
}

// grantableScopes validates requested scopes. Phase 1 grants db:read only.
func grantableScopes(requested []string) ([]string, error) {
	for _, sc := range requested {
		if sc != identity.ScopeRead {
			return nil, fmt.Errorf("%w: unsupported scope %q (only %s is available)", ErrInvalidRequest, sc, identity.ScopeRead)
		}
	}
	return []string{identity.ScopeRead}, nil
}

const maxAgentNameLen = 64

// validAgentName trims and validates an agent name.
func validAgentName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("%w: agent name is required", ErrInvalidRequest)
	}
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > maxAgentNameLen {
		return "", fmt.Errorf("%w: agent name must be at most %d characters", ErrInvalidRequest, maxAgentNameLen)
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return "", fmt.Errorf("%w: agent name contains invalid characters", ErrInvalidRequest)
		}
	}
	return name, nil
}
