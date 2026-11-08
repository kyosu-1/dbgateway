package auth

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// authzRequest holds the authorization request parameters. On the consent
// POST they come back from hidden form fields and are validated again.
type authzRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	Scope               string
	Resource            string
}

var authzParams = []string{"response_type", "client_id", "redirect_uri", "code_challenge", "code_challenge_method", "state", "scope", "resource"}

func parseAuthzRequest(v url.Values) (authzRequest, bool) {
	for _, k := range authzParams {
		if len(v[k]) > 1 { // RFC 6749 §3.1: parameters must not repeat
			return authzRequest{}, false
		}
	}
	return authzRequest{
		ResponseType:        v.Get("response_type"),
		ClientID:            v.Get("client_id"),
		RedirectURI:         v.Get("redirect_uri"),
		CodeChallenge:       v.Get("code_challenge"),
		CodeChallengeMethod: v.Get("code_challenge_method"),
		State:               v.Get("state"),
		Scope:               v.Get("scope"),
		Resource:            v.Get("resource"),
	}, true
}

// authzError is an error reported to the client via its redirect URI.
type authzError struct{ code, desc string }

// validate checks everything except the client and redirect URI.
func (s *Server) validateAuthz(ar authzRequest) *authzError {
	switch {
	case ar.ResponseType != "code":
		return &authzError{"unsupported_response_type", "response_type must be code"}
	case ar.CodeChallengeMethod != "S256":
		return &authzError{"invalid_request", "PKCE with code_challenge_method=S256 is required"}
	case !validChallenge(ar.CodeChallenge):
		return &authzError{"invalid_request", "invalid code_challenge"}
	case ar.Resource != "" && ar.Resource != s.ResourceURL():
		return &authzError{"invalid_target", "unknown resource"}
	case len(ar.State) > 1024 || len(ar.Scope) > 1024:
		return &authzError{"invalid_request", "parameter too long"}
	}
	return nil
}

// validChallenge accepts a base64url SHA-256 (43 characters).
func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	for _, r := range c {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// checkClient resolves the client and validates the redirect URI. Errors
// here are shown on a page: we never redirect to an unvalidated URI.
func (s *Server) checkClient(w http.ResponseWriter, r *http.Request, ar authzRequest) *client {
	c, err := s.resolveClient(r.Context(), ar.ClientID)
	if err != nil {
		s.log.Info("auth: authorize with unknown client", "client_id", ar.ClientID, "err", err)
		s.errorPage(w, r, http.StatusBadRequest, "error.unknown_client")
		return nil
	}
	if c.Kind == clientBuiltin || !c.allowsRedirect(ar.RedirectURI) {
		s.errorPage(w, r, http.StatusBadRequest, "error.redirect_mismatch")
		return nil
	}
	return c
}

// handleAuthorize validates the request and shows the consent page.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ar, ok := parseAuthzRequest(r.URL.Query())
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "error.duplicate_params")
		return
	}
	c := s.checkClient(w, r, ar)
	if c == nil {
		return
	}
	if e := s.validateAuthz(ar); e != nil {
		s.redirectError(w, r, ar, e.code, e.desc)
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
	s.renderConsent(w, r, http.StatusOK, sess, c, ar, c.Name, nil, "")
}

// handleConsent processes the consent form.
func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "error.bad_request")
		return
	}
	ar, ok := parseAuthzRequest(r.PostForm)
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "error.bad_request")
		return
	}
	sess, err := s.currentSession(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess == nil {
		s.errorPage(w, r, http.StatusUnauthorized, "error.authz_session_expired")
		return
	}
	if !sess.checkCSRF(r) {
		s.errorPage(w, r, http.StatusBadRequest, "error.authz_form_expired")
		return
	}
	c := s.checkClient(w, r, ar)
	if c == nil {
		return
	}
	if e := s.validateAuthz(ar); e != nil {
		s.redirectError(w, r, ar, e.code, e.desc)
		return
	}
	if r.PostFormValue("action") != "approve" {
		s.log.Info("auth: consent denied", "email", sess.email, "client_id", c.ID)
		s.redirectError(w, r, ar, "access_denied", "the user denied the request")
		return
	}
	human, err := s.humanPrincipal(r.Context(), sess.email)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	selected := r.PostForm["database"]
	agentName, err := validAgentName(r.PostFormValue("agent_name"))
	if err != nil {
		s.renderConsent(w, r, http.StatusBadRequest, sess, c, ar, r.PostFormValue("agent_name"), selected,
			"consent.error_agent_name")
		return
	}
	if len(selected) == 0 {
		s.log.Info("auth: consent with no database selected", "email", sess.email, "client_id", c.ID)
		s.redirectError(w, r, ar, "access_denied", "no database was selected")
		return
	}
	dbs, err := s.allowedDatabases(human, selected)
	if err != nil {
		s.renderConsent(w, r, http.StatusForbidden, sess, c, ar, agentName, nil, "consent.error_database")
		return
	}

	scopes := []string{identity.ScopeRead}
	if r.PostFormValue("write") == "1" && s.canRequestWrites(human, dbs) {
		scopes = append(scopes, identity.ScopeWrite)
	}

	raw, hash := newSecret("")
	now := s.now()
	if err := s.store.CreateAuthCode(r.Context(), &store.AuthCode{
		CodeHash:      hash,
		ClientID:      c.ID,
		ClientName:    c.Name,
		RedirectURI:   ar.RedirectURI,
		CodeChallenge: ar.CodeChallenge,
		Scopes:        scopes,
		Resource:      ar.Resource,
		Email:         sess.email,
		AgentName:     agentName,
		Databases:     dbs,
		FamilyID:      newID("fam_"),
		CreatedAt:     now,
		ExpiresAt:     now.Add(authCodeTTL),
	}); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("auth: consent granted", "email", sess.email, "client_id", c.ID, "agent", agentName, "databases", dbs)
	s.redirectClient(w, r, ar, url.Values{"code": {raw}})
}

// redirectError sends an error to the (validated) redirect URI.
func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, ar authzRequest, code, desc string) {
	s.redirectClient(w, r, ar, url.Values{"error": {code}, "error_description": {desc}})
}

// redirectClient redirects to the validated redirect URI with params, state
// and iss (RFC 9207).
func (s *Server) redirectClient(w http.ResponseWriter, r *http.Request, ar authzRequest, params url.Values) {
	u, err := url.Parse(ar.RedirectURI)
	if err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "error.bad_redirect")
		return
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	if ar.State != "" {
		q.Set("state", ar.State)
	}
	q.Set("iss", s.issuer)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// canRequestWrites reports whether an agent of human may be granted the
// write-request scope for any of dbs: approvals must be enabled and the
// human must hold the writer role there. Writes still always need a human
// approval; the scope only lets the agent submit them.
func (s *Server) canRequestWrites(human *identity.Principal, dbs []string) bool {
	if !s.cfg.Approvals.Enabled {
		return false
	}
	for _, name := range dbs {
		if db := s.cfg.Database(name); db != nil && s.rbac.Has(human, db, identity.RoleWriter) {
			return true
		}
	}
	return false
}

// consentDB is one database row on the consent page.
type consentDB struct {
	Name     string
	Labels   string
	Enabled  bool
	Selected bool
}

func (s *Server) renderConsent(w http.ResponseWriter, r *http.Request, status int, sess *session, c *client, ar authzRequest, agentName string, selected []string, errMsg string) {
	human, err := s.humanPrincipal(r.Context(), sess.email)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	accessible := s.accessibleNames(human)
	var dbs []consentDB
	for _, db := range s.cfg.Databases {
		enabled := slices.Contains(accessible, db.Name)
		sel := enabled && (slices.Contains(selected, db.Name) || (selected == nil && len(accessible) == 1))
		dbs = append(dbs, consentDB{Name: db.Name, Labels: formatLabels(db.Labels), Enabled: enabled, Selected: sel})
	}
	// Enabled databases first.
	slices.SortStableFunc(dbs, func(a, b consentDB) int {
		switch {
		case a.Enabled == b.Enabled:
			return 0
		case a.Enabled:
			return -1
		}
		return 1
	})
	redirectHost := ""
	if u, err := url.Parse(ar.RedirectURI); err == nil {
		redirectHost = u.Host
	}
	switchURL := "/login?prompt=login&next=" + url.QueryEscape("/authorize?"+authzQuery(ar).Encode())
	s.render(w, r, status, "consent", "title.consent", map[string]any{
		"Client":       c,
		"Verified":     c.Kind == clientCIMD,
		"RedirectHost": redirectHost,
		"Email":        sess.email,
		"SwitchURL":    switchURL,
		"AgentName":    agentName,
		"Databases":    dbs,
		"HasAny":       len(accessible) > 0,
		"CanWrite":     s.canRequestWrites(human, accessible),
		"WriteChecked": r.PostFormValue("write") == "1" || (r.Method == http.MethodGet && slices.Contains(strings.Fields(ar.Scope), identity.ScopeWrite)),
		"MaxTTL":       s.cfg.Auth.AgentTokens.MaxTTL.D(),
		"Hidden":       authzQuery(ar),
		"CSRF":         sess.csrf(),
		"Error":        errMsg,
	})
}

// authzQuery re-encodes the authorization request.
func authzQuery(ar authzRequest) url.Values {
	v := url.Values{}
	for k, val := range map[string]string{
		"response_type": ar.ResponseType, "client_id": ar.ClientID, "redirect_uri": ar.RedirectURI,
		"code_challenge": ar.CodeChallenge, "code_challenge_method": ar.CodeChallengeMethod,
		"state": ar.State, "scope": ar.Scope, "resource": ar.Resource,
	} {
		if val != "" {
			v.Set(k, val)
		}
	}
	return v
}

func formatLabels(labels map[string]string) string {
	var parts []string
	for k, v := range labels {
		parts = append(parts, k+": "+v)
	}
	slices.Sort(parts)
	return strings.Join(parts, ", ")
}
