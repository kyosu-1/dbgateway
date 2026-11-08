package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/web/ui"
)

// This file is the API for pages served outside this package (internal/web):
// the logged-in browser user, CSRF, step-up and the shared renderer. Agents
// never get browser sessions: sessions are only created by a human login.

// WebSession is the logged-in browser user.
type WebSession struct {
	Email string
	// CSRF is the token to put in forms (field "csrf") or in the
	// X-CSRF-Token header of script requests.
	CSRF string
	// StepUp is the last re-authentication of this session (zero if none).
	StepUp approval.StepUp
}

// CheckCSRF validates the CSRF token of a form submission.
func (ws *WebSession) CheckCSRF(r *http.Request) bool {
	got := r.PostFormValue("csrf")
	return got != "" && secureEqual(got, ws.CSRF)
}

// Session returns the logged-in browser user, or nil if there is none.
func (s *Server) Session(r *http.Request) (*WebSession, error) {
	sess, err := s.currentSession(r)
	if err != nil || sess == nil {
		return nil, err
	}
	return &WebSession{Email: sess.email, CSRF: sess.csrf(), StepUp: approval.StepUp{Method: sess.stepUpMethod, At: sess.stepUpAt}}, nil
}

// ErrUserInactive is returned by HumanPrincipal for a person deactivated
// through SCIM.
var ErrUserInactive = errors.New("auth: user deactivated")

// HumanPrincipal is the principal of a logged-in human, with groups
// resolved now from the IdP groups snapshot and the configuration.
func (s *Server) HumanPrincipal(ctx context.Context, email string) (*identity.Principal, error) {
	p, err := s.humanPrincipal(ctx, email)
	if errors.Is(err, mcpauth.ErrInvalidToken) {
		return nil, ErrUserInactive
	}
	return p, err
}

// StepUp returns the session's re-authentication if it is recent enough
// for approvals.step_up_max_age. Handlers that need a step-up redirect to
// StepUpURL when ok is false.
func (s *Server) StepUp(r *http.Request) (approval.StepUp, bool) {
	sess, err := s.currentSession(r)
	if err != nil || sess == nil {
		return approval.StepUp{}, false
	}
	su := approval.StepUp{Method: sess.stepUpMethod, At: sess.stepUpAt}
	return su, s.stepUpFresh(su)
}

// stepUpFresh reports whether su is no older than approvals.step_up_max_age
// (with a small allowance for clock skew in the future).
func (s *Server) stepUpFresh(su approval.StepUp) bool {
	if su.Method == "" || su.At.IsZero() {
		return false
	}
	now := s.now()
	return !su.At.After(now.Add(30*time.Second)) && now.Sub(su.At) <= s.cfg.Approvals.StepUpMaxAge.D()
}

// StepUpURL is the step-up page returning to next (a local path).
func StepUpURL(next string) string {
	return "/stepup?next=" + url.QueryEscape(safeNext(next))
}

// RedirectToLogin sends the browser to the login page, returning to the
// current URL afterwards.
func (s *Server) RedirectToLogin(w http.ResponseWriter, r *http.Request) { s.redirectToLogin(w, r) }

// UI returns the shared page renderer (pages of other packages are added
// to it, and it carries the header navigation).
func (s *Server) UI() *ui.Renderer { return s.ui }

// SetApprovals lets the account page show active break-glass elevations.
// Call it during setup, before serving.
func (s *Server) SetApprovals(svc *approval.Service) { s.approvals = svc }

// PasskeysEnabled reports whether passkeys can be used (the public URL has
// a host name usable as a WebAuthn relying party ID).
func (s *Server) PasskeysEnabled() bool { return s.wa != nil }
