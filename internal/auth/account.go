package auth

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
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

// handleAccount shows the user's agents and roles.
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, err := s.currentSession(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess == nil {
		s.redirectToLogin(w, r)
		return
	}
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
	method := "account.method_sso"
	if s.cfg.Auth.DevLogin {
		method = "account.method_dev"
	}
	var notice string
	if r.URL.Query().Get("revoked") == "1" {
		notice = "account.revoked_notice"
	}
	s.render(w, r, http.StatusOK, "account", "title.account", map[string]any{
		"Email":       sess.email,
		"Initials":    initials(sess.email),
		"Groups":      strings.Join(human.Groups, ", "),
		"LoginMethod": method,
		"Agents":      agentGrants(tokens, s.now()),
		"Roles":       s.roleRows(human),
		"CSRF":        sess.csrf(),
		"Notice":      notice,
	})
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
// that expire.
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
			if rb.ExpiresAt == nil || !now.Before(*rb.ExpiresAt) || !slices.Contains(human.Groups, rb.Group) || !rb.Databases.Matches(db) {
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

func initials(email string) string {
	local, _, _ := strings.Cut(email, "@")
	r := []rune(strings.ToUpper(local))
	if len(r) > 2 {
		r = r[:2]
	}
	return string(r)
}
