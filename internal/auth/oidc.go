package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/kyosu-1/dbgateway/internal/config"
)

// oidcLogin logs humans in with the upstream OIDC provider. Discovery is
// lazy so that dbgateway starts even if the IdP is briefly unavailable.
type oidcLogin struct {
	cfg          *config.OIDC
	clientID     string
	clientSecret string
	redirectURL  string

	mu       sync.Mutex
	provider *oidc.Provider
}

func newOIDCLogin(cfg *config.OIDC, redirectURL string) (*oidcLogin, error) {
	id := os.Getenv(cfg.ClientIDEnv)
	if id == "" {
		return nil, fmt.Errorf("auth: environment variable %s (auth.oidc.client_id_env) is empty", cfg.ClientIDEnv)
	}
	var secret string
	if cfg.ClientSecretEnv != "" {
		secret = os.Getenv(cfg.ClientSecretEnv)
	}
	return &oidcLogin{cfg: cfg, clientID: id, clientSecret: secret, redirectURL: redirectURL}, nil
}

// issuerHost is shown on the login page so users know where they go.
func (o *oidcLogin) issuerHost() string {
	if u, err := url.Parse(o.cfg.Issuer); err == nil && u.Host != "" {
		return u.Host
	}
	return o.cfg.Issuer
}

func (o *oidcLogin) setup(ctx context.Context) (*oidc.Provider, *oauth2.Config, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider == nil {
		p, err := oidc.NewProvider(context.WithoutCancel(ctx), o.cfg.Issuer)
		if err != nil {
			return nil, nil, fmt.Errorf("auth: OIDC discovery: %w", err)
		}
		o.provider = p
	}
	return o.provider, &oauth2.Config{
		ClientID:     o.clientID,
		ClientSecret: o.clientSecret,
		RedirectURL:  o.redirectURL,
		Endpoint:     o.provider.Endpoint(),
		Scopes:       o.cfg.Scopes,
	}, nil
}

// startOIDCLogin redirects to the IdP's authorization endpoint.
func (s *Server) startOIDCLogin(w http.ResponseWriter, r *http.Request, ls *loginState, forcePrompt bool) {
	_, oc, err := s.oidc.setup(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	opts := []oauth2.AuthCodeOption{
		oidc.Nonce(derive("nonce", ls.secret)),
		oauth2.S256ChallengeOption(derive("pkce", ls.secret)),
	}
	if forcePrompt {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"))
	}
	http.Redirect(w, r, oc.AuthCodeURL(derive("state", ls.secret), opts...), http.StatusFound)
}

// handleOIDCCallback completes the upstream login.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.NotFound(w, r)
		return
	}
	ls := s.readLoginState(r)
	q := r.URL.Query()
	if ls == nil || !secureEqual(q.Get("state"), derive("state", ls.secret)) {
		s.errorPage(w, r, http.StatusBadRequest, "error.login_expired")
		return
	}
	if e := q.Get("error"); e != "" {
		s.log.Info("auth: IdP returned an error", "error", e)
		s.errorPage(w, r, http.StatusForbidden, "error.idp_failed")
		return
	}
	email, groups, err := s.oidcIdentity(r.Context(), q.Get("code"), ls)
	if err != nil {
		s.log.Warn("auth: OIDC login rejected", "err", err)
		s.errorPage(w, r, http.StatusForbidden, "error.login_rejected")
		return
	}
	s.completeLogin(w, r, ls, email, groups)
}

// oidcIdentity exchanges the code and validates the ID token.
func (s *Server) oidcIdentity(ctx context.Context, code string, ls *loginState) (string, []string, error) {
	if code == "" {
		return "", nil, errors.New("missing code")
	}
	provider, oc, err := s.oidc.setup(ctx)
	if err != nil {
		return "", nil, err
	}
	tok, err := oc.Exchange(ctx, code, oauth2.VerifierOption(derive("pkce", ls.secret)))
	if err != nil {
		return "", nil, fmt.Errorf("code exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return "", nil, errors.New("no id_token in token response")
	}
	idt, err := provider.Verifier(&oidc.Config{ClientID: oc.ClientID}).Verify(ctx, rawID)
	if err != nil {
		return "", nil, fmt.Errorf("verify id_token: %w", err)
	}
	if !secureEqual(idt.Nonce, derive("nonce", ls.secret)) {
		return "", nil, errors.New("nonce mismatch")
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return "", nil, fmt.Errorf("decode claims: %w", err)
	}
	emailClaim, _ := claims["email"].(string)
	email, ok := normalizeEmail(emailClaim)
	if !ok {
		return "", nil, errors.New("id_token has no valid email claim")
	}
	if v, present := claims["email_verified"]; present {
		if b, isBool := v.(bool); !isBool || !b {
			return "", nil, errors.New("email is not verified")
		}
	}
	groups, found := stringList(claims[s.oidc.cfg.GroupsClaim])
	if !found {
		// Some IdPs only expose groups at the userinfo endpoint.
		if ui, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tok)); err == nil {
			var uc map[string]any
			if ui.Claims(&uc) == nil {
				groups, _ = stringList(uc[s.oidc.cfg.GroupsClaim])
			}
		}
	}
	return email, groups, nil
}

// stringList converts a JSON claim (array of strings, or a single string)
// to a list. found reports whether the claim was present.
func stringList(v any) (out []string, found bool) {
	switch x := v.(type) {
	case nil:
		return nil, false
	case string:
		return []string{x}, true
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out, true
	}
	return nil, true
}
