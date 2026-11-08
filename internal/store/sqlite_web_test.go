package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSessionStepUp(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)
	if err := s.CreateSession(ctx, &Session{IDHash: "h1", Email: "taro@example.com", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSession(ctx, "h1")
	if err != nil || got.StepUpMethod != "" || got.StepUpAt != nil {
		t.Fatalf("fresh session: %+v %v", got, err)
	}
	if err := s.SetSessionStepUp(ctx, "h1", "passkey", now); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetSession(ctx, "h1")
	if got.StepUpMethod != "passkey" || got.StepUpAt == nil || !got.StepUpAt.Equal(now) {
		t.Fatalf("stepped-up session: %+v", got)
	}
	if err := s.SetSessionStepUp(ctx, "missing", "dev", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing session: %v", err)
	}
}

func TestPasskeys(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)
	p := &Passkey{ID: "cred1", Email: "taro@example.com", UserHandle: []byte{1, 2, 3}, Name: "MacBook", Credential: []byte(`{"id":"x"}`), CreatedAt: now}
	if err := s.CreatePasskey(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePasskey(ctx, p); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := s.CreatePasskey(ctx, &Passkey{ID: "cred2", Email: "taro@example.com", UserHandle: []byte{1, 2, 3}, Name: "Phone",
		Credential: []byte(`{}`), CreatedAt: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListPasskeys(ctx, "taro@example.com")
	if err != nil || len(list) != 2 || list[0].ID != "cred1" || string(list[0].UserHandle) != "\x01\x02\x03" {
		t.Fatalf("list: %+v %v", list, err)
	}
	if err := s.UpdatePasskeyUse(ctx, "cred1", []byte(`{"id":"y"}`), now); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPasskey(ctx, "cred1")
	if err != nil || string(got.Credential) != `{"id":"y"}` || got.LastUsedAt == nil {
		t.Fatalf("get: %+v %v", got, err)
	}
	if err := s.DeletePasskey(ctx, "jiro@example.com", "cred1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete by another user: %v", err)
	}
	if err := s.DeletePasskey(ctx, "taro@example.com", "cred1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPasskey(ctx, "cred1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
}

func TestPasskeyEnrollment(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)
	if err := s.CreatePasskeyEnrollment(ctx, &PasskeyEnrollment{TokenHash: "t1", Email: "taro@example.com", CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if e, err := s.GetPasskeyEnrollment(ctx, "t1", now); err != nil || e.Email != "taro@example.com" {
		t.Fatalf("get: %+v %v", e, err)
	}
	if _, err := s.GetPasskeyEnrollment(ctx, "t1", now.Add(25*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired get: %v", err)
	}
	if _, err := s.ConsumePasskeyEnrollment(ctx, "t1", now.Add(25*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired consume: %v", err)
	}
	e, err := s.ConsumePasskeyEnrollment(ctx, "t1", now)
	if err != nil || e.UsedAt == nil {
		t.Fatalf("consume: %+v %v", e, err)
	}
	if _, err := s.ConsumePasskeyEnrollment(ctx, "t1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second consume: %v", err)
	}
	if _, err := s.GetPasskeyEnrollment(ctx, "t1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("used get: %v", err)
	}
}

func TestWebAuthnSessions(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)
	w := &WebAuthnSession{IDHash: "w1", Purpose: "login", Data: []byte(`{"challenge":"c"}`), CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if err := s.CreateWebAuthnSession(ctx, w); err != nil {
		t.Fatal(err)
	}
	got, err := s.ConsumeWebAuthnSession(ctx, "w1", now)
	if err != nil || got.Purpose != "login" || string(got.Data) != `{"challenge":"c"}` {
		t.Fatalf("consume: %+v %v", got, err)
	}
	if _, err := s.ConsumeWebAuthnSession(ctx, "w1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replay: %v", err)
	}
	w.IDHash = "w2"
	if err := s.CreateWebAuthnSession(ctx, w); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeWebAuthnSession(ctx, "w2", now.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired: %v", err)
	}
	// Expired rows are cleaned up.
	w.IDHash = "w3"
	_ = s.CreateWebAuthnSession(ctx, w)
	if n, err := s.DeleteExpired(ctx, now.Add(time.Hour)); err != nil || n < 1 {
		t.Fatalf("DeleteExpired: %d %v", n, err)
	}
}
