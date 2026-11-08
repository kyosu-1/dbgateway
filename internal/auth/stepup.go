package auth

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Step-up authentication: re-verifying the logged-in person right before a
// sensitive operation (approving a write, break-glass, adding a passkey).
// The time and method are recorded on the browser session; handlers read
// them with StepUp and send the user to /stepup?next=... when they are
// missing or older than approvals.step_up_max_age.
//
// Methods: a passkey (if the person has one), an IdP re-authentication
// (prompt=login, max_age=0, with a recent auth_time in the ID token), or,
// with dev_login (loopback only), a development confirmation button.

// idpStepUpMaxAge bounds how old the ID token's auth_time may be.
const idpStepUpMaxAge = 5 * time.Minute

// handleStepUpPage shows the ways to re-verify.
func (s *Server) handleStepUpPage(w http.ResponseWriter, r *http.Request) {
	sess, err := s.currentSession(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess == nil {
		s.redirectToLogin(w, r)
		return
	}
	next := safeNext(r.URL.Query().Get("next"))
	hasPasskeys := false
	if s.wa != nil {
		pks, err := s.store.ListPasskeys(r.Context(), sess.email)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		hasPasskeys = len(pks) > 0
	}
	data := map[string]any{
		"Email":    sess.email,
		"Next":     next,
		"Passkey":  hasPasskeys,
		"IdP":      s.oidc != nil,
		"Dev":      s.cfg.Auth.DevLogin,
		"CSRF":     sess.csrf(),
		"Fresh":    s.stepUpFresh(sessionStepUp(sess)),
		"MaxAge":   s.cfg.Approvals.StepUpMaxAge.D(),
		"Finish":   "/passkeys/stepup/finish?" + url.Values{"next": {next}}.Encode(),
		"IdPURL":   "/stepup/idp?" + url.Values{"next": {next}}.Encode(),
		"NoMethod": !hasPasskeys && s.oidc == nil && !s.cfg.Auth.DevLogin,
	}
	if s.oidc != nil {
		data["IdPHost"] = s.oidc.issuerHost()
	}
	s.render(w, r, http.StatusOK, "stepup", "title.stepup", data)
}

// handleStepUpIdP starts an IdP re-authentication.
func (s *Server) handleStepUpIdP(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.NotFound(w, r)
		return
	}
	sess, err := s.currentSession(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess == nil {
		s.redirectToLogin(w, r)
		return
	}
	ls := s.newLoginState(w, r.URL.Query().Get("next"), true)
	s.startOIDCLogin(w, r, ls, true, true)
}

// completeIdPStepUp records an IdP re-authentication on the current
// session: the IdP account must be the session's person and auth_time
// must be recent (max_age=0 asked the IdP to authenticate again).
func (s *Server) completeIdPStepUp(w http.ResponseWriter, r *http.Request, ls *loginState, email string, authTime time.Time) {
	sess, err := s.currentSession(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess == nil {
		s.errorPage(w, r, http.StatusUnauthorized, "error.session_expired")
		return
	}
	if !strings.EqualFold(email, sess.email) {
		s.log.Warn("auth: step-up with a different IdP account", "email", sess.email)
		s.errorPage(w, r, http.StatusForbidden, "stepup.error_other_account")
		return
	}
	now := s.now()
	if authTime.IsZero() || authTime.After(now.Add(30*time.Second)) || now.Sub(authTime) > idpStepUpMaxAge {
		s.log.Warn("auth: IdP step-up without a recent auth_time", "email", sess.email)
		s.errorPage(w, r, http.StatusForbidden, "stepup.error_not_recent")
		return
	}
	if err := s.store.SetSessionStepUp(r.Context(), sess.hash(), StepUpIdP, authTime); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.clearCookie(w, loginCookieName)
	s.log.Info("auth: step-up", "email", sess.email, "method", StepUpIdP)
	http.Redirect(w, r, ls.next, http.StatusFound)
}

// handleStepUpDev is the development confirmation (dev_login only, which
// is itself restricted to loopback listeners).
func (s *Server) handleStepUpDev(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Auth.DevLogin || !loopbackRemote(r) {
		http.NotFound(w, r)
		return
	}
	sess, err := s.currentSession(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess == nil {
		s.errorPage(w, r, http.StatusUnauthorized, "error.session_expired")
		return
	}
	if !sess.checkCSRF(r) {
		s.errorPage(w, r, http.StatusBadRequest, "error.form_expired")
		return
	}
	if err := s.store.SetSessionStepUp(r.Context(), sess.hash(), StepUpDev, s.now()); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("auth: step-up", "email", sess.email, "method", StepUpDev)
	http.Redirect(w, r, safeNext(r.PostFormValue("next")), http.StatusSeeOther)
}

// loopbackRemote reports whether the request comes from a loopback address.
func loopbackRemote(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
