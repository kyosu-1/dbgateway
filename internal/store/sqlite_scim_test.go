package store

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
)

func TestSCIMMigrationApplied(t *testing.T) {
	s := openTest(t)
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 3`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("migration 3 applied = %d, %v", n, err)
	}
	for _, table := range []string{"scim_users", "scim_groups", "scim_group_members"} {
		if _, err := s.db.Exec(`SELECT COUNT(*) FROM ` + table); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
	}
}

func TestUserActiveAndRecordLogin(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now()

	// Users never provisioned through SCIM are active and keep the login
	// snapshot.
	if ok, err := s.UserActive(ctx, "nobody@example.com"); err != nil || !ok {
		t.Fatalf("unknown user: %v %v", ok, err)
	}
	if err := s.RecordLogin(ctx, "Plain@Example.com", []string{"g1"}, now, true); err != nil {
		t.Fatal(err)
	}
	if u, err := s.GetUser(ctx, "plain@example.com"); err != nil || !slices.Equal(u.IDPGroups, []string{"g1"}) {
		t.Fatalf("plain user = %+v, %v", u, err)
	}

	u := &SCIMUser{ID: "u1", Email: "Taro@Example.com", UserName: "taro", Active: true}
	if err := s.CreateSCIMUser(ctx, u, now); err != nil {
		t.Fatal(err)
	}
	if u.Email != "taro@example.com" {
		t.Fatalf("email not normalised: %q", u.Email)
	}
	if err := s.CreateSCIMGroup(ctx, &SCIMGroup{ID: "g", DisplayName: "scim-group", Members: []SCIMMember{{UserID: "u1"}}}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordLogin(ctx, "taro@example.com", []string{"oidc-group"}, now, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetUser(ctx, "taro@example.com"); !slices.Equal(got.IDPGroups, []string{"scim-group"}) {
		t.Fatalf("scim enabled: %v", got.IDPGroups)
	}
	if err := s.RecordLogin(ctx, "taro@example.com", []string{"oidc-group"}, now, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetUser(ctx, "taro@example.com"); !slices.Equal(got.IDPGroups, []string{"oidc-group"}) {
		t.Fatalf("scim disabled: %v", got.IDPGroups)
	}

	// Deactivated: locked out even when SCIM is disabled later.
	if _, err := s.UpdateSCIMUser(ctx, "u1", now, func(u *SCIMUser) error { u.Active = false; return nil }); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.UserActive(ctx, "TARO@example.com"); ok {
		t.Fatal("inactive user reported active")
	}
	for _, enabled := range []bool{true, false} {
		if err := s.RecordLogin(ctx, "taro@example.com", nil, now, enabled); !errors.Is(err, ErrUserInactive) {
			t.Fatalf("RecordLogin(scim=%v) = %v", enabled, err)
		}
	}
	if got, _ := s.GetUser(ctx, "taro@example.com"); len(got.IDPGroups) != 0 {
		t.Fatalf("inactive user keeps groups %v", got.IDPGroups)
	}

	// Deleted: tombstone keeps the lock until re-provisioned.
	if err := s.DeleteSCIMUser(ctx, "u1", now); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.UserActive(ctx, "taro@example.com"); ok {
		t.Fatal("deleted user reported active")
	}
	if _, err := s.GetSCIMUser(ctx, "u1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted user visible: %v", err)
	}
	if err := s.CreateSCIMUser(ctx, &SCIMUser{ID: "u2", Email: "taro@example.com", UserName: "TARO", Active: true}, now); err != nil {
		t.Fatalf("re-provision: %v", err)
	}
	if ok, _ := s.UserActive(ctx, "taro@example.com"); !ok {
		t.Fatal("re-provisioned user inactive")
	}
}

func TestSCIMConflictsAndMembers(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now()
	mk := func(id, email, name string) error {
		return s.CreateSCIMUser(ctx, &SCIMUser{ID: id, Email: email, UserName: name, Active: true}, now)
	}
	if err := mk("a", "a@example.com", "a"); err != nil {
		t.Fatal(err)
	}
	if err := mk("b", "A@example.com", "b"); !errors.Is(err, ErrConflict) {
		t.Fatalf("same email: %v", err)
	}
	if err := mk("c", "c@example.com", "A"); !errors.Is(err, ErrConflict) {
		t.Fatalf("same userName: %v", err)
	}
	if err := mk("d", "", "d"); err == nil {
		t.Fatal("user without email accepted")
	}
	if err := s.CreateSCIMGroup(ctx, &SCIMGroup{ID: "g", DisplayName: "G", Members: []SCIMMember{{UserID: "zzz"}}}, now); !errors.Is(err, ErrUnknownMember) {
		t.Fatalf("unknown member: %v", err)
	}
	if _, err := s.GetSCIMGroup(ctx, "g", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed create left a group: %v", err)
	}
	if err := s.CreateSCIMGroup(ctx, &SCIMGroup{ID: "g", DisplayName: "G", Members: []SCIMMember{{UserID: "a"}, {UserID: "a"}}}, now); err != nil {
		t.Fatal(err)
	}
	g, err := s.GetSCIMGroup(ctx, "g", true)
	if err != nil || len(g.Members) != 1 || g.Members[0].UserName != "a" {
		t.Fatalf("group = %+v, %v", g, err)
	}
	gs, total, err := s.ListSCIMGroups(ctx, SCIMGroupFilter{DisplayName: "g", MemberID: "a"}, 0, 10, false)
	if err != nil || total != 1 || len(gs) != 1 || gs[0].Members != nil {
		t.Fatalf("list groups = %v %d %v", gs, total, err)
	}
	us, total, err := s.ListSCIMUsers(ctx, SCIMUserFilter{Email: "A@EXAMPLE.COM"}, 0, 10)
	if err != nil || total != 1 || us[0].ID != "a" || len(us[0].Groups) != 1 || us[0].Groups[0].DisplayName != "G" {
		t.Fatalf("list users = %v %d %v", us, total, err)
	}
	// fn errors abort the update.
	boom := errors.New("boom")
	if _, err := s.UpdateSCIMGroup(ctx, "g", now, func(g *SCIMGroup) error { g.Members = nil; return boom }); !errors.Is(err, boom) {
		t.Fatalf("update err = %v", err)
	}
	if g, _ := s.GetSCIMGroup(ctx, "g", true); len(g.Members) != 1 {
		t.Fatal("aborted update changed members")
	}
}

func TestSCIMLockOutRevokesDerivedTokens(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now()
	exp := now.Add(time.Hour)
	tokens := []*Token{
		{ID: "t1", Hash: "h1", Type: TokenRefresh, Kind: identity.KindHuman, Human: "taro@example.com", FamilyID: "f1", CreatedAt: now, ExpiresAt: exp},
		{ID: "t2", Hash: "h2", Type: TokenAccess, Kind: identity.KindHuman, Human: "taro@example.com", FamilyID: "f1", CreatedAt: now, ExpiresAt: exp},
		{ID: "t3", Hash: "h3", Type: TokenAccess, Kind: identity.KindAgent, Human: "Taro@Example.com", Agent: "x", ParentID: "t2", CreatedAt: now, ExpiresAt: exp},
		{ID: "other", Hash: "h4", Type: TokenAccess, Kind: identity.KindHuman, Human: "hanako@example.com", CreatedAt: now, ExpiresAt: exp},
	}
	for _, tk := range tokens {
		if err := s.CreateToken(ctx, tk); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateSCIMUser(ctx, &SCIMUser{ID: "u", Email: "taro@example.com", UserName: "taro", Active: false}, now); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"t1", "t2", "t3"} {
		if tk, _ := s.GetToken(ctx, id); tk.RevokedAt == nil {
			t.Fatalf("%s not revoked", id)
		}
	}
	if tk, _ := s.GetToken(ctx, "other"); tk.RevokedAt != nil {
		t.Fatal("another user's token revoked")
	}
}
