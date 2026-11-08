package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
)

func openTest(t *testing.T) *SQLite {
	t.Helper()
	s, err := OpenSQLite(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenFileAndReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sub", "dbgw.db")
	s, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertUser(ctx, &User{Email: "a@example.com", IDPGroups: []string{"g"}}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = OpenSQLite(ctx, path) // migrations must be idempotent
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u, err := s.GetUser(ctx, "a@example.com")
	if err != nil || len(u.IDPGroups) != 1 || u.IDPGroups[0] != "g" {
		t.Fatalf("GetUser = %+v, %v", u, err)
	}
}

func TestUserUpsert(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.GetUser(ctx, "x@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	t1 := time.Now().Add(-time.Hour)
	s.UpsertUser(ctx, &User{Email: "x@example.com", IDPGroups: []string{"a"}, LastLoginAt: t1})
	s.UpsertUser(ctx, &User{Email: "x@example.com", IDPGroups: []string{"b", "c"}})
	u, _ := s.GetUser(ctx, "x@example.com")
	if len(u.IDPGroups) != 2 || u.CreatedAt.UnixMilli() != t1.UnixMilli() || !u.LastLoginAt.After(t1) {
		t.Fatalf("user = %+v", u)
	}
}

func TestAuthCodeConsumeOnce(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now()
	c := &AuthCode{CodeHash: HashSecret("code"), ClientID: "c", RedirectURI: "http://127.0.0.1/cb", CodeChallenge: "x",
		Scopes: []string{"db:read"}, Email: "a@example.com", Databases: []string{"db"}, FamilyID: "f", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := s.CreateAuthCode(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := s.ConsumeAuthCode(ctx, c.CodeHash, now)
	if err != nil || got.FamilyID != "f" || got.Databases[0] != "db" {
		t.Fatalf("consume = %+v, %v", got, err)
	}
	got, err = s.ConsumeAuthCode(ctx, c.CodeHash, now)
	if !errors.Is(err, ErrAlreadyUsed) || got == nil || got.FamilyID != "f" {
		t.Fatalf("second consume = %+v, %v", got, err)
	}
	if _, err := s.ConsumeAuthCode(ctx, HashSecret("nope"), now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestDeviceCodeLifecycle(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now()
	d := &DeviceCode{DeviceCodeHash: HashSecret("dc"), UserCodeHash: HashSecret("UC"), ClientID: "dbgw-cli",
		Status: DevicePending, Interval: 5 * time.Second, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	if err := s.CreateDeviceCode(ctx, d); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeDeviceCode(ctx, d.DeviceCodeHash, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consume pending: %v", err)
	}
	p, err := s.PollDeviceCode(ctx, d.DeviceCodeHash, now)
	if err != nil || p.LastPolledAt != nil {
		t.Fatalf("poll = %+v, %v", p, err)
	}
	p, _ = s.PollDeviceCode(ctx, d.DeviceCodeHash, now.Add(time.Second))
	if p.LastPolledAt == nil {
		t.Fatal("last poll not recorded")
	}
	if err := s.DecideDeviceCode(ctx, d.UserCodeHash, "a@example.com", true, now); err != nil {
		t.Fatal(err)
	}
	if err := s.DecideDeviceCode(ctx, d.UserCodeHash, "b@example.com", false, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second decide: %v", err)
	}
	got, err := s.ConsumeDeviceCode(ctx, d.DeviceCodeHash, now)
	if err != nil || got.Email != "a@example.com" || got.Status != DeviceConsumed {
		t.Fatalf("consume = %+v, %v", got, err)
	}
	if _, err := s.ConsumeDeviceCode(ctx, d.DeviceCodeHash, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double consume: %v", err)
	}
}

func tok(id, family, parent string, typ TokenType, exp time.Time) *Token {
	return &Token{ID: id, Hash: HashSecret(id), Type: typ, Kind: identity.KindAgent, Human: "a@example.com",
		ClientID: "c", Scopes: []string{"db:read"}, Audience: "aud", FamilyID: family, ParentID: parent,
		CreatedAt: time.Now(), ExpiresAt: exp}
}

func TestTokenRevokeCascade(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	exp := time.Now().Add(time.Hour)
	for _, tk := range []*Token{
		tok("human", "", "", TokenAccess, exp),
		tok("agent1", "", "human", TokenAccess, exp),
		tok("agent2", "", "agent1", TokenAccess, exp), // grandchild
		tok("at1", "fam", "", TokenAccess, exp),
		tok("rt1", "fam", "", TokenRefresh, exp),
		tok("rt2", "fam", "rt1", TokenRefresh, exp),
		tok("other", "", "", TokenAccess, exp),
	} {
		if err := s.CreateToken(ctx, tk); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateToken(ctx, tok("human", "", "", TokenAccess, exp)); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate insert: %v", err)
	}
	now := time.Now()
	n, err := s.RevokeToken(ctx, "human", now)
	if err != nil || n != 3 {
		t.Fatalf("revoke human = %d, %v", n, err)
	}
	n, err = s.RevokeFamily(ctx, "fam", now)
	if err != nil || n != 3 {
		t.Fatalf("revoke family = %d, %v", n, err)
	}
	other, _ := s.GetTokenByHash(ctx, HashSecret("other"))
	if !other.Active(now) {
		t.Fatal("unrelated token revoked")
	}
	ok, _ := s.MarkTokenUsed(ctx, "other", now)
	ok2, _ := s.MarkTokenUsed(ctx, "other", now)
	if !ok || ok2 {
		t.Fatalf("MarkTokenUsed = %v, %v", ok, ok2)
	}
	list, _ := s.ListTokens(ctx, "a@example.com")
	if len(list) != 7 {
		t.Fatalf("list = %d", len(list))
	}
}

func TestDeleteExpired(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now()
	s.CreateToken(ctx, tok("old", "", "", TokenAccess, now.Add(-time.Hour)))
	s.CreateToken(ctx, tok("new", "", "", TokenAccess, now.Add(time.Hour)))
	s.CreateSession(ctx, &Session{IDHash: "s", Email: "a", CreatedAt: now, ExpiresAt: now.Add(-time.Minute)})
	n, err := s.DeleteExpired(ctx, now)
	if err != nil || n != 2 {
		t.Fatalf("DeleteExpired = %d, %v", n, err)
	}
	if _, err := s.GetToken(ctx, "new"); err != nil {
		t.Fatal(err)
	}
}
