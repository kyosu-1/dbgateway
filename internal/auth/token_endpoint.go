package auth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// handleToken is the token endpoint (public clients only).
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		errInvalidRequest(w, "malformed request body")
		return
	}
	f := r.PostForm
	for k, v := range f {
		if len(v) > 1 {
			errInvalidRequest(w, "parameter "+k+" is repeated")
			return
		}
	}
	if _, _, ok := r.BasicAuth(); ok || f.Get("client_secret") != "" {
		errInvalidClient(w, "only public clients (token_endpoint_auth_method=none) are supported")
		return
	}
	clientID := f.Get("client_id")
	if clientID == "" {
		errInvalidClient(w, "client_id is required")
		return
	}
	if res := f.Get("resource"); res != "" && res != s.ResourceURL() {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "unknown resource")
		return
	}
	switch f.Get("grant_type") {
	case "authorization_code":
		s.grantAuthorizationCode(w, r, clientID)
	case "refresh_token":
		s.grantRefreshToken(w, r, clientID)
	case GrantTypeDeviceCode:
		s.grantDeviceCode(w, r, clientID)
	case "":
		errInvalidRequest(w, "grant_type is required")
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (s *Server) grantAuthorizationCode(w http.ResponseWriter, r *http.Request, clientID string) {
	ctx := r.Context()
	f := r.PostForm
	code, verifier, redirectURI := f.Get("code"), f.Get("code_verifier"), f.Get("redirect_uri")
	if code == "" || verifier == "" {
		errInvalidRequest(w, "code and code_verifier are required")
		return
	}
	if len(code) > maxTokenLen || len(verifier) < 43 || len(verifier) > 128 {
		errInvalidGrant(w, "invalid code or code_verifier")
		return
	}
	now := s.now()
	ac, err := s.store.ConsumeAuthCode(ctx, store.HashSecret(code), now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		errInvalidGrant(w, "invalid authorization code")
		return
	case errors.Is(err, store.ErrAlreadyUsed):
		// A replayed code may have been stolen: revoke what it issued.
		n, rerr := s.store.RevokeFamily(ctx, ac.FamilyID, now)
		s.log.Warn("auth: authorization code reused; tokens revoked", "client_id", ac.ClientID, "email", ac.Email, "revoked", n, "err", rerr)
		errInvalidGrant(w, "authorization code already used")
		return
	case err != nil:
		s.log.Error("auth: consume code", "err", err)
		errServer(w)
		return
	}
	switch {
	case !now.Before(ac.ExpiresAt):
		errInvalidGrant(w, "authorization code expired")
		return
	case !secureEqual(ac.ClientID, clientID):
		errInvalidGrant(w, "authorization code was issued to another client")
		return
	case !secureEqual(ac.RedirectURI, redirectURI):
		errInvalidGrant(w, "redirect_uri does not match the authorization request")
		return
	case !secureEqual(s256(verifier), ac.CodeChallenge):
		errInvalidGrant(w, "PKCE verification failed")
		return
	case ac.Resource != "" && r.PostForm.Get("resource") != "" && r.PostForm.Get("resource") != ac.Resource:
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource does not match the authorization request")
		return
	}
	var refreshExpiry time.Time
	if s.cfg.Auth.AgentTokens.Refresh {
		refreshExpiry = now.Add(refreshFamilyTTL)
	}
	resp, err := s.issue(ctx, store.Token{
		Kind:       identity.KindAgent,
		Human:      ac.Email,
		Agent:      ac.AgentName,
		ClientID:   ac.ClientID,
		ClientName: ac.ClientName,
		Scopes:     ac.Scopes,
		Databases:  ac.Databases,
		Audience:   s.ResourceURL(),
		FamilyID:   ac.FamilyID,
	}, s.cfg.Auth.AgentTokens.MaxTTL.D(), refreshExpiry)
	if err != nil {
		s.log.Error("auth: issue tokens", "err", err)
		errServer(w)
		return
	}
	s.log.Info("auth: agent token issued", "email", ac.Email, "agent", ac.AgentName, "client_id", ac.ClientID)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) grantRefreshToken(w http.ResponseWriter, r *http.Request, clientID string) {
	ctx := r.Context()
	raw := r.PostForm.Get("refresh_token")
	if raw == "" {
		errInvalidRequest(w, "refresh_token is required")
		return
	}
	if !strings.HasPrefix(raw, RefreshTokenPrefix) || len(raw) > maxTokenLen {
		errInvalidGrant(w, "invalid refresh token")
		return
	}
	now := s.now()
	old, err := s.store.GetTokenByHash(ctx, store.HashSecret(raw))
	if errors.Is(err, store.ErrNotFound) {
		errInvalidGrant(w, "invalid refresh token")
		return
	}
	if err != nil {
		s.log.Error("auth: load refresh token", "err", err)
		errServer(w)
		return
	}
	if old.Type != store.TokenRefresh || !secureEqual(old.ClientID, clientID) {
		errInvalidGrant(w, "invalid refresh token")
		return
	}
	if old.RevokedAt != nil || !now.Before(old.ExpiresAt) {
		errInvalidGrant(w, "refresh token expired or revoked")
		return
	}
	if scope := r.PostForm.Get("scope"); scope != "" {
		for _, sc := range strings.Fields(scope) {
			if !slices.Contains(old.Scopes, sc) {
				writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "scope exceeds the original grant")
				return
			}
		}
	}
	fresh, err := s.store.MarkTokenUsed(ctx, old.ID, now)
	if err != nil {
		s.log.Error("auth: rotate refresh token", "err", err)
		errServer(w)
		return
	}
	if !fresh {
		// Reuse of a rotated refresh token: assume theft, kill the family.
		n, rerr := s.store.RevokeFamily(ctx, old.FamilyID, now)
		s.log.Warn("auth: refresh token reused; family revoked", "client_id", old.ClientID, "email", old.Human, "revoked", n, "err", rerr)
		errInvalidGrant(w, "refresh token already used")
		return
	}
	tmpl := *old
	tmpl.ParentID = old.ID
	resp, err := s.issue(ctx, tmpl, s.cfg.Auth.AgentTokens.MaxTTL.D(), old.ExpiresAt)
	if err != nil {
		s.log.Error("auth: issue tokens", "err", err)
		errServer(w)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRevoke is the RFC 7009 revocation endpoint. Revoking a token also
// revokes its family and the tokens derived from it.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		errInvalidRequest(w, "malformed request body")
		return
	}
	raw, clientID := r.PostForm.Get("token"), r.PostForm.Get("client_id")
	if raw == "" {
		errInvalidRequest(w, "token is required")
		return
	}
	if clientID == "" {
		errInvalidClient(w, "client_id is required")
		return
	}
	if len(raw) <= maxTokenLen && (strings.HasPrefix(raw, AccessTokenPrefix) || strings.HasPrefix(raw, RefreshTokenPrefix)) {
		if err := s.revokeByValue(r.Context(), raw, clientID); err != nil {
			s.log.Error("auth: revoke", "err", err)
			errServer(w)
			return
		}
	}
	// Invalid or foreign tokens are not an error (RFC 7009 §2.2).
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) revokeByValue(ctx context.Context, raw, clientID string) error {
	t, err := s.store.GetTokenByHash(ctx, store.HashSecret(raw))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !secureEqual(t.ClientID, clientID) {
		return nil
	}
	n, err := s.store.RevokeToken(ctx, t.ID, s.now())
	if err == nil {
		s.log.Info("auth: token revoked", "token_id", t.ID, "email", t.Human, "revoked", n)
	}
	return err
}
