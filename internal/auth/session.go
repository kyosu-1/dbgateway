package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/store"
)

// session is the logged-in browser user.
type session struct {
	email string
	raw   string // raw session ID; used to derive the CSRF token
	// stepUpMethod and stepUpAt record the last re-authentication.
	stepUpMethod string
	stepUpAt     time.Time
}

// hash is the stored session key.
func (s *session) hash() string { return store.HashSecret(s.raw) }

// csrf returns the CSRF token bound to this session.
func (s *session) csrf() string { return derive("csrf", s.raw) }

// checkCSRF validates a submitted CSRF token.
func (s *session) checkCSRF(r *http.Request) bool {
	got := r.PostFormValue("csrf")
	return got != "" && secureEqual(got, s.csrf())
}

// currentSession returns the logged-in user, or nil if there is none.
func (s *Server) currentSession(r *http.Request) (*session, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" || len(c.Value) > maxTokenLen {
		return nil, nil
	}
	hash := store.HashSecret(c.Value)
	sess, err := s.store.GetSession(r.Context(), hash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("auth: load session: %w", err)
	}
	if !s.now().Before(sess.ExpiresAt) {
		_ = s.store.DeleteSession(r.Context(), hash)
		return nil, nil
	}
	out := &session{email: sess.Email, raw: c.Value, stepUpMethod: sess.StepUpMethod}
	if sess.StepUpAt != nil {
		out.stepUpAt = *sess.StepUpAt
	}
	return out, nil
}

// startSession creates a new session for email (replacing any existing
// one, to prevent session fixation) and sets the session cookie.
func (s *Server) startSession(ctx context.Context, w http.ResponseWriter, r *http.Request, email string) error {
	_, err := s.startSessionRaw(ctx, w, r, email)
	return err
}

// startSessionRaw is startSession returning the raw session ID.
func (s *Server) startSessionRaw(ctx context.Context, w http.ResponseWriter, r *http.Request, email string) (string, error) {
	if old, err := r.Cookie(sessionCookieName); err == nil && old.Value != "" {
		_ = s.store.DeleteSession(ctx, store.HashSecret(old.Value))
	}
	raw := randomToken(32)
	now := s.now()
	ttl := s.cfg.Auth.SessionTTL.D()
	if err := s.store.CreateSession(ctx, &store.Session{
		IDHash:    store.HashSecret(raw),
		Email:     email,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}); err != nil {
		return "", fmt.Errorf("auth: create session: %w", err)
	}
	s.setCookie(w, sessionCookieName, raw, ttl)
	return raw, nil
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl / time.Second),
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// redirectToLogin sends the browser to the login page, returning to the
// current URL afterwards.
func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
}

// safeNext returns next if it is a local absolute path, otherwise "/account"
// (the account page). It prevents open redirects after login.
func safeNext(next string) string {
	if next == "" || len(next) > 4096 || !strings.HasPrefix(next, "/") ||
		strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n\t") {
		return "/account"
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/account"
	}
	return next
}
