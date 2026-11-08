package auth

import (
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// userCodeAlphabet avoids vowels and look-alike characters (RFC 8628 §6.1).
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// newUserCode returns a code like "BCDF-GHJK".
func newUserCode() string {
	var b strings.Builder
	max := big.NewInt(int64(len(userCodeAlphabet)))
	for i := range 8 {
		if i == 4 {
			b.WriteByte('-')
		}
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err) // crypto/rand does not fail
		}
		b.WriteByte(userCodeAlphabet[n.Int64()])
	}
	return b.String()
}

// normalizeUserCode upper-cases and strips separators. It returns "" if the
// result is not a well-formed code.
func normalizeUserCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == '-' || r == ' ':
		case strings.ContainsRune(userCodeAlphabet, r):
			b.WriteRune(r)
		default:
			return ""
		}
	}
	if b.Len() != 8 {
		return ""
	}
	c := b.String()
	return c[:4] + "-" + c[4:]
}

// handleDeviceAuthorization starts the device flow (RFC 8628 §3.1). Only
// the built-in CLI client may use it.
func (s *Server) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		errInvalidRequest(w, "malformed request body")
		return
	}
	if r.PostForm.Get("client_id") != CLIClientID {
		errInvalidClient(w, "the device flow is only available to "+CLIClientID)
		return
	}
	for _, sc := range strings.Fields(r.PostForm.Get("scope")) {
		if sc != identity.ScopeRead {
			writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "unsupported scope "+sc)
			return
		}
	}
	deviceCode, deviceHash := newSecret("")
	userCode := newUserCode()
	now := s.now()
	if err := s.store.CreateDeviceCode(r.Context(), &store.DeviceCode{
		DeviceCodeHash: deviceHash,
		UserCodeHash:   store.HashSecret(userCode),
		ClientID:       CLIClientID,
		Scopes:         []string{identity.ScopeRead},
		Status:         store.DevicePending,
		Interval:       deviceInterval,
		CreatedAt:      now,
		ExpiresAt:      now.Add(deviceCodeTTL),
	}); err != nil {
		// A user code collision is astronomically unlikely; fail closed.
		s.log.Error("auth: create device code", "err", err)
		errServer(w)
		return
	}
	writeJSON(w, http.StatusOK, deviceAuthResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         s.issuer + "/device",
		VerificationURIComplete: s.issuer + "/device?user_code=" + url.QueryEscape(userCode),
		ExpiresIn:               int64(deviceCodeTTL / time.Second),
		Interval:                int64(deviceInterval / time.Second),
	})
}

// grantDeviceCode handles token polling (RFC 8628 §3.4-3.5).
func (s *Server) grantDeviceCode(w http.ResponseWriter, r *http.Request, clientID string) {
	ctx := r.Context()
	raw := r.PostForm.Get("device_code")
	if raw == "" {
		errInvalidRequest(w, "device_code is required")
		return
	}
	if clientID != CLIClientID {
		errInvalidGrant(w, "invalid device code")
		return
	}
	if len(raw) > maxTokenLen {
		errInvalidGrant(w, "invalid device code")
		return
	}
	hash := store.HashSecret(raw)
	now := s.now()
	d, err := s.store.PollDeviceCode(ctx, hash, now)
	if errors.Is(err, store.ErrNotFound) {
		errInvalidGrant(w, "invalid device code")
		return
	}
	if err != nil {
		s.log.Error("auth: poll device code", "err", err)
		errServer(w)
		return
	}
	if d.ClientID != clientID {
		errInvalidGrant(w, "invalid device code")
		return
	}
	if !now.Before(d.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "expired_token", "the device code has expired")
		return
	}
	switch d.Status {
	case store.DeviceDenied:
		writeOAuthError(w, http.StatusBadRequest, "access_denied", "the user denied the request")
		return
	case store.DeviceConsumed:
		errInvalidGrant(w, "the device code was already used")
		return
	case store.DevicePending:
		if d.LastPolledAt != nil && now.Sub(*d.LastPolledAt) < d.Interval {
			if err := s.store.SetDeviceCodeInterval(ctx, hash, d.Interval+5*time.Second); err != nil {
				s.log.Error("auth: slow down device code", "err", err)
			}
			writeOAuthError(w, http.StatusBadRequest, "slow_down", "polling too frequently")
			return
		}
		writeOAuthError(w, http.StatusBadRequest, "authorization_pending", "waiting for the user")
		return
	}
	d, err = s.store.ConsumeDeviceCode(ctx, hash, now)
	if errors.Is(err, store.ErrNotFound) {
		errInvalidGrant(w, "invalid device code")
		return
	}
	if err != nil {
		s.log.Error("auth: consume device code", "err", err)
		errServer(w)
		return
	}
	resp, err := s.issue(ctx, store.Token{
		Kind:       identity.KindHuman,
		Human:      d.Email,
		ClientID:   CLIClientID,
		ClientName: CLIClientName,
		Scopes:     d.Scopes,
		Audience:   s.issuer,
	}, s.cfg.Auth.CLITokenTTL.D(), time.Time{})
	if err != nil {
		s.log.Error("auth: issue CLI token", "err", err)
		errServer(w)
		return
	}
	s.log.Info("auth: CLI token issued", "email", d.Email)
	writeJSON(w, http.StatusOK, resp)
}

// handleDevicePage shows the code entry/confirmation page.
func (s *Server) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	sess, err := s.currentSession(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess == nil {
		s.redirectToLogin(w, r)
		return
	}
	code := normalizeUserCode(r.URL.Query().Get("user_code"))
	s.render(w, r, http.StatusOK, "device", "title.device", s.deviceData(sess, code, "", ""))
}

// handleDeviceDecision approves or denies a device code.
func (s *Server) handleDeviceDecision(w http.ResponseWriter, r *http.Request) {
	sess, err := s.currentSession(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess == nil {
		s.errorPage(w, r, http.StatusUnauthorized, "error.login_expired")
		return
	}
	if !sess.checkCSRF(r) {
		s.errorPage(w, r, http.StatusBadRequest, "error.form_expired")
		return
	}
	entered := r.PostFormValue("user_code")
	code := normalizeUserCode(entered)
	approve := r.PostFormValue("action") == "approve"
	if code != "" {
		err = s.store.DecideDeviceCode(r.Context(), store.HashSecret(code), sess.email, approve, s.now())
	}
	if code == "" || errors.Is(err, store.ErrNotFound) {
		s.render(w, r, http.StatusBadRequest, "device", "title.device", s.deviceData(sess, entered, "device.error_code", ""))
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("auth: device code decided", "email", sess.email, "approved", approve)
	result := "denied"
	if approve {
		result = "approved"
	}
	s.render(w, r, http.StatusOK, "device", "title.device", s.deviceData(sess, code, "", result))
}

// deviceData is the data of the device page. result is "", "approved" or
// "denied".
func (s *Server) deviceData(sess *session, code, errKey, result string) map[string]any {
	return map[string]any{
		"Email":    sess.email,
		"UserCode": code,
		"CSRF":     sess.csrf(),
		"TTL":      s.cfg.Auth.CLITokenTTL.D(),
		"AgentTTL": s.cfg.Auth.AgentTokens.MaxTTL.D(),
		"Error":    errKey,
		"Result":   result,
	}
}
