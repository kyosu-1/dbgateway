package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/kyosu-1/dbgateway/internal/store"
)

// A user deactivated through SCIM loses existing tokens and cannot log in.
func TestSCIMDeactivatedUser(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	_, tok := e.authCodeTokens()
	at := tok["access_token"].(string)
	if _, err := e.auth.VerifyToken(context.Background(), at, nil); err != nil {
		t.Fatalf("token should be valid: %v", err)
	}

	sq := e.store.(*store.SQLite)
	u := &store.SCIMUser{UserName: "taro@example.com", Email: "taro@example.com", Active: true}
	if err := sq.CreateSCIMUser(context.Background(), u, e.clock.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := sq.UpdateSCIMUser(context.Background(), u.ID, e.clock.now(), func(x *store.SCIMUser) error {
		x.Active = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := e.auth.VerifyToken(context.Background(), at, nil); !errors.Is(err, mcpauth.ErrInvalidToken) {
		t.Fatalf("deactivated user's token accepted: %v", err)
	}

	b := e.browser()
	_, page := do(t, b, "GET", e.url("/login"), nil)
	resp, _ := do(t, b, "POST", e.url("/login"), map[string][]string{"csrf": {csrfFrom(t, page)}, "email": {"taro@example.com"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("login of deactivated user: status %d", resp.StatusCode)
	}
}
