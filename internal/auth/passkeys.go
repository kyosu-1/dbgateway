package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// Passkeys (WebAuthn).
//
// Every ceremony is a begin request (returns the options) and a finish
// request (verifies the authenticator's response), both JSON, called by
// /static/webauthn.js. The library's session data (challenge, allowed
// credentials) is kept in the store under the hash of a random ID held in
// an HttpOnly cookie, and is consumed by the finish request: a challenge
// can be answered once, on the server that issued it or any other sharing
// the store.
//
// Purposes:
//   - login:    discoverable credential sign-in (auth.passkeys only)
//   - register: add a passkey on the account page (needs a fresh step-up)
//   - stepup:   re-verify the logged-in user before approving etc.
//   - enroll:   first passkey through a one-time link from
//     `dbgw passkey enroll` (auth.passkeys only); signs the person in
//
// User verification is required for every ceremony.

const (
	purposeLogin    = "login"
	purposeRegister = "register"
	purposeStepUp   = "stepup"
	purposeEnroll   = "enroll"

	webauthnCookieName = "dbgw_webauthn"
	enrollCookieName   = "dbgw_enroll"
	webauthnTTL        = 5 * time.Minute
	enrollCookieTTL    = 30 * time.Minute

	// EnrollmentTTL is how long a passkey enrollment link stays valid.
	EnrollmentTTL = 24 * time.Hour
	// EnrollTokenPrefix makes enrollment tokens recognizable.
	EnrollTokenPrefix = "dbgw_pe_"

	// StepUpPasskey, StepUpIdP and StepUpDev are the step-up methods
	// recorded on sessions (approval.StepUp.Method).
	StepUpPasskey = "passkey"
	StepUpIdP     = "idp"
	StepUpDev     = "dev"

	maxPasskeyName = 64
)

// newRelyingParty configures WebAuthn for the public URL. The relying party
// ID is the host name, which must not be an IP address.
func newRelyingParty(issuer string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("auth: passkeys: %w", err)
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		return nil, fmt.Errorf("auth: passkeys need a host name in server.public_url, not the IP address %s", host)
	}
	required := true
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          host,
		RPDisplayName: "dbgateway",
		RPOrigins:     []string{u.Scheme + "://" + u.Host},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: &required,
			UserVerification:   protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: webauthnTTL, TimeoutUVD: webauthnTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: webauthnTTL, TimeoutUVD: webauthnTTL},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("auth: passkeys: %w", err)
	}
	return wa, nil
}

// waUser is a person as seen by the WebAuthn library.
type waUser struct {
	email  string
	handle []byte
	creds  []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return u.handle }
func (u *waUser) WebAuthnName() string                       { return u.email }
func (u *waUser) WebAuthnDisplayName() string                { return u.email }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// loadUser returns the person's passkeys. handle is nil if they have none.
func (s *Server) loadUser(ctx context.Context, email string) (*waUser, error) {
	pks, err := s.store.ListPasskeys(ctx, email)
	if err != nil {
		return nil, err
	}
	u := &waUser{email: email}
	for _, pk := range pks {
		var c webauthn.Credential
		if err := json.Unmarshal(pk.Credential, &c); err != nil {
			return nil, fmt.Errorf("auth: decode passkey %s: %w", pk.ID, err)
		}
		if u.handle == nil {
			u.handle = pk.UserHandle
		}
		u.creds = append(u.creds, c)
	}
	return u, nil
}

func credentialID(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

// jsonError reports a ceremony failure to the script (a translated message).
func (s *Server) jsonError(w http.ResponseWriter, r *http.Request, status int, msgKey string) {
	writeJSON(w, status, map[string]string{"error": s.ui.Printer(r).T(msgKey)})
}

// scriptSession returns the session of a script request, checking the
// X-CSRF-Token header.
func (s *Server) scriptSession(r *http.Request) (*session, bool) {
	sess, err := s.currentSession(r)
	if err != nil || sess == nil {
		return nil, false
	}
	got := r.Header.Get("X-CSRF-Token")
	return sess, got != "" && secureEqual(got, sess.csrf())
}

// enrollment returns the valid enrollment link held in the enroll cookie.
func (s *Server) enrollment(r *http.Request) (string, *store.PasskeyEnrollment) {
	c, err := r.Cookie(enrollCookieName)
	if err != nil || !strings.HasPrefix(c.Value, EnrollTokenPrefix) || len(c.Value) > maxTokenLen {
		return "", nil
	}
	e, err := s.store.GetPasskeyEnrollment(r.Context(), store.HashSecret(c.Value), s.now())
	if err != nil {
		return "", nil
	}
	return c.Value, e
}

// passkeyBegin starts a ceremony and returns the options.
func (s *Server) passkeyBegin(purpose string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if s.wa == nil || ((purpose == purposeLogin || purpose == purposeEnroll) && !s.cfg.Auth.Passkeys) {
			s.jsonError(w, r, http.StatusNotFound, "passkey.error_unavailable")
			return
		}
		var (
			opts  any
			sd    *webauthn.SessionData
			email string
			err   error
		)
		uv := webauthn.WithUserVerification(protocol.VerificationRequired)
		switch purpose {
		case purposeLogin:
			opts, sd, err = s.wa.BeginDiscoverableLogin(uv)
		case purposeStepUp, purposeRegister:
			sess, ok := s.scriptSession(r)
			if !ok {
				s.jsonError(w, r, http.StatusForbidden, "error.form_expired")
				return
			}
			email = sess.email
			u, lerr := s.loadUser(ctx, email)
			if lerr != nil {
				s.log.Error("auth: load passkeys", "err", lerr)
				s.jsonError(w, r, http.StatusInternalServerError, "error.internal")
				return
			}
			if purpose == purposeStepUp {
				if len(u.creds) == 0 {
					s.jsonError(w, r, http.StatusBadRequest, "passkey.error_none")
					return
				}
				opts, sd, err = s.wa.BeginLogin(u, uv)
				break
			}
			// Adding a passkey gives lasting access: require a fresh
			// re-authentication first.
			if !s.stepUpFresh(sessionStepUp(sess)) {
				s.jsonError(w, r, http.StatusForbidden, "passkey.error_stepup")
				return
			}
			opts, sd, err = s.beginRegistration(u)
		case purposeEnroll:
			token, e := s.enrollment(r)
			if e == nil || !secureEqual(r.Header.Get("X-CSRF-Token"), derive("csrf-enroll", token)) {
				s.jsonError(w, r, http.StatusForbidden, "passkey.error_enroll_invalid")
				return
			}
			email = e.Email
			u, lerr := s.loadUser(ctx, email)
			if lerr != nil {
				s.log.Error("auth: load passkeys", "err", lerr)
				s.jsonError(w, r, http.StatusInternalServerError, "error.internal")
				return
			}
			opts, sd, err = s.beginRegistration(u)
		}
		if err != nil {
			s.log.Error("auth: begin passkey ceremony", "purpose", purpose, "err", err)
			s.jsonError(w, r, http.StatusInternalServerError, "error.internal")
			return
		}
		data, _ := json.Marshal(sd)
		id := randomToken(32)
		now := s.now()
		if err := s.store.CreateWebAuthnSession(ctx, &store.WebAuthnSession{IDHash: store.HashSecret(id), Purpose: purpose, Email: email,
			Data: data, CreatedAt: now, ExpiresAt: now.Add(webauthnTTL)}); err != nil {
			s.log.Error("auth: store passkey ceremony", "err", err)
			s.jsonError(w, r, http.StatusInternalServerError, "error.internal")
			return
		}
		s.setCookie(w, webauthnCookieName, id, webauthnTTL)
		writeJSON(w, http.StatusOK, opts)
	}
}

// beginRegistration starts a registration for u, excluding the passkeys
// they already have. A person's first passkey gets a new random handle.
func (s *Server) beginRegistration(u *waUser) (any, *webauthn.SessionData, error) {
	if u.handle == nil {
		u.handle = make([]byte, 32)
		_, _ = rand.Read(u.handle)
	}
	var exclude []protocol.CredentialDescriptor
	for _, c := range u.creds {
		exclude = append(exclude, c.Descriptor())
	}
	return s.wa.BeginRegistration(u, webauthn.WithExclusions(exclude))
}

func sessionStepUp(sess *session) approval.StepUp {
	return approval.StepUp{Method: sess.stepUpMethod, At: sess.stepUpAt}
}

// passkeyFinish verifies the authenticator's response.
func (s *Server) passkeyFinish(purpose string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if s.wa == nil || ((purpose == purposeLogin || purpose == purposeEnroll) && !s.cfg.Auth.Passkeys) {
			s.jsonError(w, r, http.StatusNotFound, "passkey.error_unavailable")
			return
		}
		c, err := r.Cookie(webauthnCookieName)
		if err != nil || c.Value == "" || len(c.Value) > maxTokenLen {
			s.jsonError(w, r, http.StatusBadRequest, "passkey.error_expired")
			return
		}
		s.clearCookie(w, webauthnCookieName)
		now := s.now()
		ws, err := s.store.ConsumeWebAuthnSession(ctx, store.HashSecret(c.Value), now)
		if err != nil || ws.Purpose != purpose {
			s.jsonError(w, r, http.StatusBadRequest, "passkey.error_expired")
			return
		}
		var sd webauthn.SessionData
		if err := json.Unmarshal(ws.Data, &sd); err != nil {
			s.jsonError(w, r, http.StatusBadRequest, "passkey.error_expired")
			return
		}
		switch purpose {
		case purposeLogin:
			s.finishLogin(w, r, sd)
		case purposeStepUp:
			sess, ok := s.scriptSession(r)
			if !ok || !strings.EqualFold(sess.email, ws.Email) {
				s.jsonError(w, r, http.StatusForbidden, "error.form_expired")
				return
			}
			u, err := s.loadUser(ctx, sess.email)
			if err != nil {
				s.serverJSONError(w, r, err)
				return
			}
			cred, err := s.wa.FinishLogin(u, sd, r)
			if err != nil {
				s.log.Info("auth: passkey step-up rejected", "email", sess.email, "err", err)
				s.jsonError(w, r, http.StatusForbidden, "passkey.error_failed")
				return
			}
			s.recordUse(ctx, cred, now)
			if err := s.store.SetSessionStepUp(ctx, sess.hash(), StepUpPasskey, now); err != nil {
				s.serverJSONError(w, r, err)
				return
			}
			s.log.Info("auth: step-up", "email", sess.email, "method", StepUpPasskey)
			writeJSON(w, http.StatusOK, map[string]string{"redirect": safeNext(r.URL.Query().Get("next"))})
		case purposeRegister:
			sess, ok := s.scriptSession(r)
			if !ok || !strings.EqualFold(sess.email, ws.Email) {
				s.jsonError(w, r, http.StatusForbidden, "error.form_expired")
				return
			}
			if !s.stepUpFresh(sessionStepUp(sess)) {
				s.jsonError(w, r, http.StatusForbidden, "passkey.error_stepup")
				return
			}
			if !s.register(w, r, sess.email, sd, now) {
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"redirect": "/account?passkey=added"})
		case purposeEnroll:
			token, e := s.enrollment(r)
			if e == nil || !strings.EqualFold(e.Email, ws.Email) || !secureEqual(r.Header.Get("X-CSRF-Token"), derive("csrf-enroll", token)) {
				s.jsonError(w, r, http.StatusForbidden, "passkey.error_enroll_invalid")
				return
			}
			// Verify the authenticator before using up the link.
			u, err := s.loadUser(ctx, e.Email)
			if err != nil {
				s.serverJSONError(w, r, err)
				return
			}
			if u.handle == nil {
				u.handle = sd.UserID
			}
			cred, err := s.wa.FinishRegistration(u, sd, r)
			if err != nil {
				s.log.Info("auth: passkey enrollment rejected", "email", e.Email, "err", err)
				s.jsonError(w, r, http.StatusBadRequest, "passkey.error_failed")
				return
			}
			if _, err := s.store.ConsumePasskeyEnrollment(ctx, e.TokenHash, now); err != nil {
				s.jsonError(w, r, http.StatusForbidden, "passkey.error_enroll_invalid")
				return
			}
			if !s.savePasskey(w, r, u, cred, now) {
				return
			}
			s.clearCookie(w, enrollCookieName)
			if !s.passkeySignIn(w, r, e.Email, now) {
				return
			}
			s.log.Info("auth: passkey enrolled", "email", e.Email)
			writeJSON(w, http.StatusOK, map[string]string{"redirect": "/account?passkey=enrolled"})
		}
	}
}

// finishLogin completes a discoverable sign-in.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, sd webauthn.SessionData) {
	ctx := r.Context()
	var email string
	_, cred, err := s.wa.FinishPasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		pk, err := s.store.GetPasskey(ctx, credentialID(rawID))
		if err != nil {
			return nil, errors.New("unknown credential")
		}
		if !bytes.Equal(pk.UserHandle, userHandle) {
			return nil, errors.New("user handle mismatch")
		}
		u, err := s.loadUser(ctx, pk.Email)
		if err != nil {
			return nil, err
		}
		email = pk.Email
		return u, nil
	}, sd, r)
	if err != nil {
		s.log.Info("auth: passkey sign-in rejected", "err", err)
		s.jsonError(w, r, http.StatusForbidden, "passkey.error_failed")
		return
	}
	now := s.now()
	s.recordUse(ctx, cred, now)
	if !s.passkeySignIn(w, r, email, now) {
		return
	}
	s.clearCookie(w, loginCookieName)
	writeJSON(w, http.StatusOK, map[string]string{"redirect": safeNext(r.URL.Query().Get("next"))})
}

// passkeySignIn starts a session for email, stepped up with the passkey
// just used. The IdP groups snapshot of a known user is kept.
func (s *Server) passkeySignIn(w http.ResponseWriter, r *http.Request, email string, now time.Time) bool {
	ctx := r.Context()
	var groups []string
	if u, err := s.store.GetUser(ctx, email); err == nil {
		groups = u.IDPGroups
	}
	if err := s.store.RecordLogin(ctx, email, groups, now, s.cfg.SCIM.Enabled); err != nil {
		if errors.Is(err, store.ErrUserInactive) {
			s.log.Warn("auth: passkey sign-in refused for deactivated user", "email", email)
			s.jsonError(w, r, http.StatusForbidden, "error.user_inactive")
			return false
		}
		s.serverJSONError(w, r, err)
		return false
	}
	raw, err := s.startSessionRaw(ctx, w, r, email)
	if err != nil {
		s.serverJSONError(w, r, err)
		return false
	}
	if err := s.store.SetSessionStepUp(ctx, store.HashSecret(raw), StepUpPasskey, now); err != nil {
		s.serverJSONError(w, r, err)
		return false
	}
	s.log.Info("auth: login", "email", email, "method", "passkey")
	return true
}

// register verifies a new passkey of email and stores it.
func (s *Server) register(w http.ResponseWriter, r *http.Request, email string, sd webauthn.SessionData, now time.Time) bool {
	u, err := s.loadUser(r.Context(), email)
	if err != nil {
		s.serverJSONError(w, r, err)
		return false
	}
	if u.handle == nil {
		u.handle = sd.UserID
	}
	cred, err := s.wa.FinishRegistration(u, sd, r)
	if err != nil {
		s.log.Info("auth: passkey registration rejected", "email", email, "err", err)
		s.jsonError(w, r, http.StatusBadRequest, "passkey.error_failed")
		return false
	}
	if !s.savePasskey(w, r, u, cred, now) {
		return false
	}
	s.log.Info("auth: passkey added", "email", email)
	return true
}

// savePasskey stores a verified credential with the requested name.
func (s *Server) savePasskey(w http.ResponseWriter, r *http.Request, u *waUser, cred *webauthn.Credential, now time.Time) bool {
	data, err := json.Marshal(cred)
	if err != nil {
		s.serverJSONError(w, r, err)
		return false
	}
	name := cleanPasskeyName(r.URL.Query().Get("name"))
	if name == "" {
		name = s.ui.Printer(r).T("passkey.default_name", len(u.creds)+1)
	}
	err = s.store.CreatePasskey(r.Context(), &store.Passkey{ID: credentialID(cred.ID), Email: u.email, UserHandle: u.handle,
		Name: name, Credential: data, CreatedAt: now})
	if errors.Is(err, store.ErrConflict) {
		s.jsonError(w, r, http.StatusConflict, "passkey.error_duplicate")
		return false
	}
	if err != nil {
		s.serverJSONError(w, r, err)
		return false
	}
	return true
}

// recordUse stores the updated counter and flags of a used credential.
func (s *Server) recordUse(ctx context.Context, cred *webauthn.Credential, now time.Time) {
	data, err := json.Marshal(cred)
	if err == nil {
		err = s.store.UpdatePasskeyUse(ctx, credentialID(cred.ID), data, now)
	}
	if err != nil {
		s.log.Warn("auth: record passkey use", "err", err)
	}
}

func (s *Server) serverJSONError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("auth: internal error", "path", r.URL.Path, "err", err)
	s.jsonError(w, r, http.StatusInternalServerError, "error.internal")
}

// cleanPasskeyName trims a user-supplied label and drops control and
// formatting characters.
func cleanPasskeyName(name string) string {
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F || (r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			return -1
		}
		return r
	}, strings.TrimSpace(name))
	for utf8.RuneCountInString(name) > maxPasskeyName {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	return strings.TrimSpace(name)
}

// ---------------------------------------------------------------------------
// Enrollment links

// CreatePasskeyEnrollment stores a one-time passkey enrollment link for
// email, valid for EnrollmentTTL, and returns its URL. It requires
// auth.passkeys. Only the hash of the token is stored.
func CreatePasskeyEnrollment(ctx context.Context, st store.Store, cfg *config.Config, email string, now time.Time) (link string, expires time.Time, err error) {
	if !cfg.Auth.Passkeys {
		return "", time.Time{}, errors.New("passkey enrollment links need auth.passkeys: true in the configuration")
	}
	addr, ok := normalizeEmail(email)
	if !ok {
		return "", time.Time{}, fmt.Errorf("invalid e-mail address %q", email)
	}
	token, hash := newSecret(EnrollTokenPrefix)
	expires = now.Add(EnrollmentTTL)
	if err := st.CreatePasskeyEnrollment(ctx, &store.PasskeyEnrollment{TokenHash: hash, Email: addr, CreatedAt: now, ExpiresAt: expires}); err != nil {
		return "", time.Time{}, err
	}
	return strings.TrimRight(cfg.Server.PublicURL, "/") + "/passkeys/enroll/" + token, expires, nil
}

// handleEnrollLink accepts an enrollment link: it moves the token into a
// cookie and redirects, so that the token leaves the address bar and the
// browser history.
func (s *Server) handleEnrollLink(w http.ResponseWriter, r *http.Request) {
	if s.wa == nil || !s.cfg.Auth.Passkeys {
		http.NotFound(w, r)
		return
	}
	token := r.PathValue("token")
	if !strings.HasPrefix(token, EnrollTokenPrefix) || len(token) > maxTokenLen {
		s.errorPage(w, r, http.StatusNotFound, "passkey.error_enroll_invalid")
		return
	}
	if _, err := s.store.GetPasskeyEnrollment(r.Context(), store.HashSecret(token), s.now()); err != nil {
		s.errorPage(w, r, http.StatusNotFound, "passkey.error_enroll_invalid")
		return
	}
	s.setCookie(w, enrollCookieName, token, enrollCookieTTL)
	http.Redirect(w, r, "/passkeys/enroll", http.StatusSeeOther)
}

// handleEnrollPage shows the enrollment page.
func (s *Server) handleEnrollPage(w http.ResponseWriter, r *http.Request) {
	if s.wa == nil || !s.cfg.Auth.Passkeys {
		http.NotFound(w, r)
		return
	}
	token, e := s.enrollment(r)
	if e == nil {
		s.errorPage(w, r, http.StatusNotFound, "passkey.error_enroll_invalid")
		return
	}
	s.render(w, r, http.StatusOK, "enroll", "title.enroll", map[string]any{
		"Email": e.Email, "ExpiresAt": e.ExpiresAt, "CSRF": derive("csrf-enroll", token),
	})
}

// handlePasskeyDelete removes one of the user's passkeys.
func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
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
	err = s.store.DeletePasskey(r.Context(), sess.email, r.PostFormValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "passkey.error_not_found")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("auth: passkey removed", "email", sess.email)
	http.Redirect(w, r, "/account?passkey=deleted", http.StatusSeeOther)
}
