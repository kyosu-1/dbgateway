package auth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"github.com/kyosu-1/dbgateway/internal/store"
)

// The login cookie holds a random secret plus the post-login path. The OIDC
// state, nonce and PKCE verifier, and the dev form's CSRF token, are all
// derived from that secret, so no login state is stored server-side. A
// trailing ".s" marks an IdP step-up (re-authentication of the session's
// person) instead of a login.
type loginState struct {
	secret string
	next   string
	stepUp bool
}

func (s *Server) newLoginState(w http.ResponseWriter, next string, stepUp bool) *loginState {
	ls := &loginState{secret: randomToken(32), next: safeNext(next), stepUp: stepUp}
	v := ls.secret + "." + base64.RawURLEncoding.EncodeToString([]byte(ls.next))
	if stepUp {
		v += ".s"
	}
	s.setCookie(w, loginCookieName, v, loginStateTTL)
	return ls
}

func (s *Server) readLoginState(r *http.Request) *loginState {
	c, err := r.Cookie(loginCookieName)
	if err != nil {
		return nil
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) < 2 || len(parts) > 3 || len(parts[0]) < 43 || (len(parts) == 3 && parts[2] != "s") {
		return nil
	}
	next, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	return &loginState{secret: parts[0], next: safeNext(string(next)), stepUp: len(parts) == 3}
}

// handleLogin shows the login page (the dev form, or an SSO button). With
// an existing session it continues to next (default: the account page).
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	next, prompt := q.Get("next"), q.Get("prompt")
	sess, err := s.currentSession(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess != nil && prompt != "login" {
		http.Redirect(w, r, safeNext(next), http.StatusFound)
		return
	}
	data := map[string]any{"Dev": s.cfg.Auth.DevLogin}
	if s.cfg.Auth.DevLogin {
		ls := s.newLoginState(w, next, false)
		data["CSRF"] = derive("csrf", ls.secret)
	}
	if s.cfg.Auth.Passkeys && s.wa != nil {
		data["Passkey"] = true
		data["PasskeyFinish"] = "/passkeys/login/finish?" + url.Values{"next": {safeNext(next)}}.Encode()
	}
	if s.oidc != nil {
		v := url.Values{"next": {safeNext(next)}}
		if prompt == "login" {
			v.Set("prompt", "login")
		}
		data["SSOURL"] = "/login/sso?" + v.Encode()
		data["IdPHost"] = s.oidc.issuerHost()
	}
	s.render(w, r, http.StatusOK, "login", "title.login", data)
}

// handleSSOLogin starts the upstream OIDC login.
func (s *Server) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	ls := s.newLoginState(w, q.Get("next"), false)
	s.startOIDCLogin(w, r, ls, q.Get("prompt") == "login", false)
}

// handleDevLogin accepts the dev login form. Development only.
func (s *Server) handleDevLogin(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Auth.DevLogin {
		http.NotFound(w, r)
		return
	}
	ls := s.readLoginState(r)
	if ls == nil || !secureEqual(r.PostFormValue("csrf"), derive("csrf", ls.secret)) {
		s.errorPage(w, r, http.StatusBadRequest, "error.login_expired")
		return
	}
	email, ok := normalizeEmail(r.PostFormValue("email"))
	if !ok {
		data := map[string]any{"Dev": true, "CSRF": derive("csrf", ls.secret), "Error": "login.error_email"}
		if s.cfg.Auth.Passkeys && s.wa != nil {
			data["Passkey"] = true
			data["PasskeyFinish"] = "/passkeys/login/finish?" + url.Values{"next": {ls.next}}.Encode()
		}
		if s.oidc != nil {
			data["SSOURL"] = "/login/sso?" + url.Values{"next": {ls.next}}.Encode()
			data["IdPHost"] = s.oidc.issuerHost()
		}
		s.render(w, r, http.StatusBadRequest, "login", "title.login", data)
		return
	}
	s.completeLogin(w, r, ls, email, nil)
}

// completeLogin records the user and starts a session.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, ls *loginState, email string, idpGroups []string) {
	ctx := r.Context()
	if err := s.store.RecordLogin(ctx, email, idpGroups, s.now(), s.cfg.SCIM.Enabled); err != nil {
		if errors.Is(err, store.ErrUserInactive) {
			s.log.Warn("auth: login refused for deactivated user", "email", email)
			s.errorPage(w, r, http.StatusForbidden, "error.user_inactive")
			return
		}
		s.serverError(w, r, err)
		return
	}
	if err := s.startSession(ctx, w, r, email); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.clearCookie(w, loginCookieName)
	s.log.Info("auth: login", "email", email)
	http.Redirect(w, r, ls.next, http.StatusFound)
}

// handleLogout ends the browser session.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, err := s.currentSession(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess != nil {
		if !sess.checkCSRF(r) {
			s.errorPage(w, r, http.StatusBadRequest, "error.form_expired")
			return
		}
		if err := s.store.DeleteSession(r.Context(), store.HashSecret(sess.raw)); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	s.clearCookie(w, sessionCookieName)
	s.render(w, r, http.StatusOK, "message", "title.signed_out", map[string]any{
		"Heading": "logout.heading", "Message": "logout.message", "LoginLink": true,
	})
}

// normalizeEmail validates a bare email address and lower-cases it.
func normalizeEmail(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 254 {
		return "", false
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" {
		return "", false
	}
	return strings.ToLower(s), true
}
