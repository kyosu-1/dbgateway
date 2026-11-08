package auth

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
	"github.com/kyosu-1/dbgateway/internal/web/i18n"
	"github.com/kyosu-1/dbgateway/internal/web/ui"
)

// agentGrant is one row of the account page: an OAuth grant (a token
// family) or a manually minted agent token.
type agentGrant struct {
	ID         string // a token of the grant; revoking it revokes the grant
	Agent      string
	ClientName string
	Manual     bool
	Databases  []string
	ExpiresAt  time.Time
}

type roleRow struct {
	Name  string
	Roles string
	Notes []roleNote
}

// roleNote marks roles granted by a binding that expires.
type roleNote struct {
	Roles string
	Until time.Time
}

// passkeyRow is one passkey on the account page.
type passkeyRow struct {
	ID         string
	Name       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// grantRow is an active break-glass elevation.
type grantRow struct {
	Databases string
	ExpiresAt time.Time
}

// SlackLinker connects dbgateway users to their Slack accounts (phase 2
// notifications). It is optional: the account page shows the Slack section
// only when one is set with SetSlackLinker. Implementations must be safe
// for concurrent use.
type SlackLinker interface {
	// Linked returns the linked Slack user (e.g. "@taro") of a person.
	Linked(email string) (slackUser string, ok bool)
	// IssueCode returns a one-time code the person enters in Slack
	// (`/dbgw link <code>`) and its expiry.
	IssueCode(email string) (code string, expires time.Time, err error)
	// Unlink removes the person's link.
	Unlink(email string) error
}

// SetSlackLinker enables the Slack section of the account page. Call it
// during setup, before serving.
func (s *Server) SetSlackLinker(l SlackLinker) { s.slack = l }

// handleAccount shows the user's agents, roles, passkeys and more.
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	sess, err := s.currentSession(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess == nil {
		s.redirectToLogin(w, r)
		return
	}
	var notice string
	switch {
	case r.URL.Query().Get("revoked") == "1":
		notice = "account.revoked_notice"
	case r.URL.Query().Get("passkey") == "added":
		notice = "account.passkey_added"
	case r.URL.Query().Get("passkey") == "enrolled":
		notice = "account.passkey_enrolled"
	case r.URL.Query().Get("passkey") == "deleted":
		notice = "account.passkey_deleted"
	case r.URL.Query().Get("slack") == "unlinked":
		notice = "account.slack_unlinked"
	}
	s.renderAccount(w, r, http.StatusOK, sess, notice, nil)
}

// renderAccount renders the account page; extra adds or overrides data
// (for example a freshly issued Slack code).
func (s *Server) renderAccount(w http.ResponseWriter, r *http.Request, status int, sess *session, notice string, extra map[string]any) {
	ctx := r.Context()
	human, err := s.humanPrincipal(ctx, sess.email)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	tokens, err := s.store.ListTokens(ctx, sess.email)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	pks, err := s.store.ListPasskeys(ctx, sess.email)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var passkeys []passkeyRow
	for _, pk := range pks {
		passkeys = append(passkeys, passkeyRow{ID: pk.ID, Name: pk.Name, CreatedAt: pk.CreatedAt, LastUsedAt: pk.LastUsedAt})
	}
	method := "account.method_sso"
	switch {
	case s.cfg.Auth.DevLogin:
		method = "account.method_dev"
	case s.oidc == nil:
		method = "account.method_passkey"
	}
	data := map[string]any{
		"Email":           sess.email,
		"Groups":          strings.Join(human.Groups, ", "),
		"LoginMethod":     method,
		"Agents":          agentGrants(tokens, s.now()),
		"Roles":           s.roleRows(human),
		"CSRF":            sess.csrf(),
		"Notice":          notice,
		"PasskeysEnabled": s.wa != nil,
		"Passkeys":        passkeys,
		"CanAddPasskey":   s.stepUpFresh(sessionStepUp(sess)),
		"AddPasskeyStep":  StepUpURL("/account#passkeys"),
		"Lang":            s.langChoice(r),
	}
	if s.approvals != nil {
		grants, err := s.approvals.ActiveGrants(ctx, human)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		var rows []grantRow
		for _, g := range grants {
			rows = append(rows, grantRow{Databases: strings.Join(g.Databases, ", "), ExpiresAt: g.ExpiresAt})
		}
		data["Grants"] = rows
		data["BreakGlass"] = s.breakGlassEligible(human)
	}
	if s.slack != nil {
		slack := map[string]any{"Enabled": true}
		if u, ok := s.slack.Linked(sess.email); ok {
			slack["Linked"], slack["User"] = true, u
		}
		data["Slack"] = slack
	}
	for k, v := range extra {
		data[k] = v
	}
	s.ui.Render(w, r, ui.Page{Name: "account", Title: "title.account", Status: status, User: sess.email, Active: "account",
		Scripts: []string{"/static/webauthn.js"}, Data: data})
}

// langChoice is the language selected with the lang cookie ("auto" if the
// browser's preference is used).
func (s *Server) langChoice(r *http.Request) string {
	if c, err := r.Cookie(i18n.CookieName); err == nil && s.ui.Catalog().Supported(c.Value) {
		return c.Value
	}
	return "auto"
}

// breakGlassEligible reports whether the human may use break-glass on at
// least one database.
func (s *Server) breakGlassEligible(human *identity.Principal) bool {
	bg := s.cfg.BreakGlass
	if bg == nil || !s.cfg.Approvals.Enabled {
		return false
	}
	for i := range s.cfg.Databases {
		db := &s.cfg.Databases[i]
		if bg.Databases.Matches(db) && s.rbac.Has(human, db, identity.RoleApprover) {
			return true
		}
	}
	return false
}

// agentGrants groups active agent tokens by grant, newest first.
func agentGrants(tokens []*store.Token, now time.Time) []agentGrant {
	var out []agentGrant
	index := map[string]int{}
	for _, t := range tokens {
		if t.Kind != identity.KindAgent || !t.Active(now) {
			continue
		}
		key := t.FamilyID
		if key == "" {
			key = t.ID
		}
		if i, ok := index[key]; ok {
			if t.ExpiresAt.After(out[i].ExpiresAt) {
				out[i].ExpiresAt = t.ExpiresAt
			}
			continue
		}
		index[key] = len(out)
		out = append(out, agentGrant{
			ID:         t.ID,
			Agent:      t.Agent,
			ClientName: t.ClientName,
			Manual:     t.ClientID == CLIClientID,
			Databases:  t.Databases,
			ExpiresAt:  t.ExpiresAt,
		})
	}
	return out
}

// roleRows lists the human's roles per database, with notes for bindings
// (group or personal) that expire.
func (s *Server) roleRows(human *identity.Principal) []roleRow {
	now := s.now()
	var out []roleRow
	for i := range s.cfg.Databases {
		db := &s.cfg.Databases[i]
		roles := s.rbac.Roles(human, db)
		if len(roles) == 0 {
			continue
		}
		names := make([]string, len(roles))
		for j, r := range roles {
			names[j] = string(r)
		}
		row := roleRow{Name: db.Name, Roles: strings.Join(names, ", ")}
		for _, rb := range s.cfg.RoleBindings {
			if rb.ExpiresAt == nil || !now.Before(*rb.ExpiresAt) || !rb.Databases.Matches(db) {
				continue
			}
			if !BindingCovers(rb.Group, rb.User, human.Human, human.Groups) {
				continue
			}
			var rs []string
			for _, r := range rb.Roles {
				rs = append(rs, string(r))
			}
			row.Notes = append(row.Notes, roleNote{Roles: strings.Join(rs, ", "), Until: *rb.ExpiresAt})
		}
		out = append(out, row)
	}
	return out
}

// BindingCovers reports whether a role binding for group or user (an
// e-mail) applies to the human with the given e-mail and groups.
func BindingCovers(group, user, email string, groups []string) bool {
	if user != "" {
		return email != "" && strings.EqualFold(user, email)
	}
	return group != "" && slices.Contains(groups, group)
}

// handleAccountRevoke revokes one of the user's agent grants.
func (s *Server) handleAccountRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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
	t, err := s.store.GetToken(ctx, r.PostFormValue("id"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && t.Human != sess.email) {
		s.errorPage(w, r, http.StatusNotFound, "error.token_not_found")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	n, err := s.store.RevokeToken(ctx, t.ID, s.now())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("auth: grant revoked from account page", "email", sess.email, "token_id", t.ID, "revoked", n)
	http.Redirect(w, r, "/account?revoked=1", http.StatusSeeOther)
}

// handleSlackLink issues a one-time Slack link code and shows it.
func (s *Server) handleSlackLink(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.accountPost(w, r)
	if !ok {
		return
	}
	if s.slack == nil {
		http.NotFound(w, r)
		return
	}
	code, expires, err := s.slack.IssueCode(sess.email)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	slack := map[string]any{"Enabled": true, "Code": code, "CodeExpires": expires}
	s.renderAccount(w, r, http.StatusOK, sess, "", map[string]any{"Slack": slack})
}

// handleSlackUnlink removes the user's Slack link.
func (s *Server) handleSlackUnlink(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.accountPost(w, r)
	if !ok {
		return
	}
	if s.slack == nil {
		http.NotFound(w, r)
		return
	}
	if err := s.slack.Unlink(sess.email); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/account?slack=unlinked", http.StatusSeeOther)
}

// accountPost checks the session and CSRF token of an account page form.
func (s *Server) accountPost(w http.ResponseWriter, r *http.Request) (*session, bool) {
	sess, err := s.currentSession(r)
	if err != nil {
		s.serverError(w, r, err)
		return nil, false
	}
	if sess == nil {
		s.errorPage(w, r, http.StatusUnauthorized, "error.session_expired")
		return nil, false
	}
	if !sess.checkCSRF(r) {
		s.errorPage(w, r, http.StatusBadRequest, "error.form_expired")
		return nil, false
	}
	return sess, true
}
