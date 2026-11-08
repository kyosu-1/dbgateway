package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// SCIM provisioning (RFC 7643/7644). The IdP is the source of truth for
// SCIM-managed users:
//
//   - A SCIM user is tied to a dbgateway user by email (SCIMUser.Email,
//     lower case), the same key as users.email and tokens.human.
//   - After every change, users.idp_groups of the affected users is
//     rewritten as the display names of their SCIM groups (empty when the
//     user is inactive or deleted), so RBAC (groups[].oidc_group) sees the
//     SCIM groups instead of the login-time snapshot.
//   - Deactivating or deleting a user revokes all of their tokens (and the
//     tokens derived from them) and deletes their browser sessions in the
//     same transaction. Deleted users are kept as tombstones so that they
//     stay locked out (see UserActive).

var (
	// ErrUserInactive is returned by RecordLogin for a user deactivated or
	// deleted through SCIM.
	ErrUserInactive = errors.New("store: user is deactivated")
	// ErrUnknownMember is returned when a group member is not a provisioned
	// (and not deleted) SCIM user.
	ErrUnknownMember = errors.New("store: unknown group member")
)

// SCIMEmail is one entry of the SCIM emails attribute.
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMUser is a user provisioned by the IdP.
type SCIMUser struct {
	ID string
	// Email is the dbgateway identity (lower case). It is derived from the
	// SCIM attributes by the caller.
	Email         string
	UserName      string
	ExternalID    string
	DisplayName   string
	GivenName     string
	FamilyName    string
	FormattedName string
	Emails        []SCIMEmail
	Active        bool
	// Groups is read-only: set by the Get/List methods, ignored on writes.
	Groups    []SCIMGroupRef
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SCIMGroupRef is a group a user belongs to.
type SCIMGroupRef struct {
	ID          string
	DisplayName string
}

// SCIMGroup is a group provisioned by the IdP. Its display name is matched
// against groups[].oidc_group.
type SCIMGroup struct {
	ID          string
	DisplayName string
	ExternalID  string
	// Members is the full member list. On reads it is nil when members
	// were not requested.
	Members   []SCIMMember
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SCIMMember is a member of a group.
type SCIMMember struct {
	UserID   string
	UserName string // read-only
}

// SCIMUserFilter selects users; empty fields match everything and set
// fields are combined with AND. UserName and Email match case-insensitively.
type SCIMUserFilter struct {
	ID, UserName, ExternalID, Email string
}

// SCIMGroupFilter selects groups like SCIMUserFilter. MemberID selects
// groups that have that user as a member.
type SCIMGroupFilter struct {
	ID, DisplayName, ExternalID, MemberID string
}

const scimUserColumns = `id, email, user_name, external_id, display_name, given_name, family_name, formatted_name,
	emails, active, created_at, updated_at`

// CreateSCIMUser stores a new SCIM user. It returns ErrConflict if a live
// user with the same userName or email exists. A tombstone with the same
// userName or email is replaced. If the user is created inactive, the
// tokens and sessions of the email are revoked.
func (s *SQLite) CreateSCIMUser(ctx context.Context, u *SCIMUser, now time.Time) error {
	email, err := scimEmail(u.Email)
	if err != nil {
		return err
	}
	u.Email, u.CreatedAt, u.UpdatedAt = email, now, now
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM scim_users WHERE deleted_at IS NOT NULL AND (email = ? OR user_name = ?)`,
			u.Email, u.UserName); err != nil {
			return err
		}
		emails, err := encodeEmails(u.Emails)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO scim_users (`+scimUserColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			u.ID, u.Email, u.UserName, u.ExternalID, u.DisplayName, u.GivenName, u.FamilyName, u.FormattedName,
			emails, u.Active, ms(now), ms(now))
		if err != nil {
			return insertErr(err)
		}
		if !u.Active {
			if err := lockOut(ctx, tx, u.Email, now); err != nil {
				return err
			}
		}
		return syncIDPGroups(ctx, tx, u.ID)
	})
}

// GetSCIMUser returns a live (not deleted) SCIM user with its groups.
func (s *SQLite) GetSCIMUser(ctx context.Context, id string) (*SCIMUser, error) {
	u, err := getSCIMUser(ctx, s.db, id)
	if err != nil {
		return nil, err
	}
	if u.Groups, err = userGroups(ctx, s.db, id); err != nil {
		return nil, err
	}
	return u, nil
}

// ListSCIMUsers returns the live users matching f, oldest first, starting
// at offset (0-based), at most limit of them, and the total number of
// matches. limit 0 returns only the total.
func (s *SQLite) ListSCIMUsers(ctx context.Context, f SCIMUserFilter, offset, limit int) ([]*SCIMUser, int, error) {
	where := []string{"deleted_at IS NULL"}
	var args []any
	for _, c := range []struct{ col, v string }{
		{"id = ?", f.ID}, {"user_name = ?", f.UserName}, {"external_id = ?", f.ExternalID}, {"email = ?", strings.ToLower(f.Email)},
	} {
		if c.v != "" {
			where, args = append(where, c.col), append(args, c.v)
		}
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scim_users WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || offset >= total {
		return nil, total, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+scimUserColumns+` FROM scim_users WHERE `+cond+
		` ORDER BY created_at, id LIMIT ? OFFSET ?`, append(args, limit, max(offset, 0))...)
	if err != nil {
		return nil, 0, err
	}
	var out []*SCIMUser
	for rows.Next() {
		u, err := scanSCIMUser(rows)
		if err != nil {
			rows.Close()
			return nil, 0, err
		}
		out = append(out, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	for _, u := range out {
		if u.Groups, err = userGroups(ctx, s.db, u.ID); err != nil {
			return nil, 0, err
		}
	}
	return out, total, nil
}

// UpdateSCIMUser loads a live user, lets fn modify it and stores the
// result, all in one transaction. fn's error is returned as is. The ID,
// creation time and groups cannot be changed.
//
// If the user is (or becomes) inactive, the tokens and sessions of its
// email are revoked. If the email changes, the tokens and sessions of the
// old email are revoked and its IdP groups cleared.
func (s *SQLite) UpdateSCIMUser(ctx context.Context, id string, now time.Time, fn func(*SCIMUser) error) (*SCIMUser, error) {
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		u, err := getSCIMUser(ctx, tx, id)
		if err != nil {
			return err
		}
		old := *u
		if err := fn(u); err != nil {
			return err
		}
		if u.Email, err = scimEmail(u.Email); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM scim_users WHERE deleted_at IS NOT NULL AND id != ? AND (email = ? OR user_name = ?)`,
			id, u.Email, u.UserName); err != nil {
			return err
		}
		emails, err := encodeEmails(u.Emails)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE scim_users SET email = ?, user_name = ?, external_id = ?, display_name = ?,
			given_name = ?, family_name = ?, formatted_name = ?, emails = ?, active = ?, updated_at = ? WHERE id = ?`,
			u.Email, u.UserName, u.ExternalID, u.DisplayName, u.GivenName, u.FamilyName, u.FormattedName,
			emails, u.Active, ms(now), id)
		if err != nil {
			return insertErr(err)
		}
		if old.Email != u.Email {
			if err := lockOut(ctx, tx, old.Email, now); err != nil {
				return err
			}
			if err := setIDPGroups(ctx, tx, old.Email, nil); err != nil {
				return err
			}
		}
		if !u.Active {
			if err := lockOut(ctx, tx, u.Email, now); err != nil {
				return err
			}
		}
		return syncIDPGroups(ctx, tx, id)
	})
	if err != nil {
		return nil, err
	}
	return s.GetSCIMUser(ctx, id)
}

// DeleteSCIMUser deletes a SCIM user: it disappears from SCIM, loses its
// group memberships, its tokens and sessions are revoked, and a tombstone
// keeps the email locked out until the IdP provisions it again.
func (s *SQLite) DeleteSCIMUser(ctx context.Context, id string, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		u, err := getSCIMUser(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM scim_group_members WHERE user_id = ?`, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE scim_users SET active = 0, deleted_at = ?, updated_at = ? WHERE id = ?`,
			ms(now), ms(now), id); err != nil {
			return err
		}
		if err := lockOut(ctx, tx, u.Email, now); err != nil {
			return err
		}
		return syncIDPGroups(ctx, tx, id)
	})
}

// CreateSCIMGroup stores a new group with its members. It returns
// ErrConflict if the display name is taken and ErrUnknownMember if a
// member is not a live SCIM user.
func (s *SQLite) CreateSCIMGroup(ctx context.Context, g *SCIMGroup, now time.Time) error {
	g.CreatedAt, g.UpdatedAt = now, now
	return s.inTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO scim_groups (id, display_name, external_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
			g.ID, g.DisplayName, g.ExternalID, ms(now), ms(now))
		if err != nil {
			return insertErr(err)
		}
		ids := memberIDs(g.Members)
		if err := addMembers(ctx, tx, g.ID, ids); err != nil {
			return err
		}
		return syncUsers(ctx, tx, ids)
	})
}

// GetSCIMGroup returns a group, with its members if withMembers is set.
func (s *SQLite) GetSCIMGroup(ctx context.Context, id string, withMembers bool) (*SCIMGroup, error) {
	return getSCIMGroup(ctx, s.db, id, withMembers)
}

// ListSCIMGroups returns the groups matching f like ListSCIMUsers.
func (s *SQLite) ListSCIMGroups(ctx context.Context, f SCIMGroupFilter, offset, limit int, withMembers bool) ([]*SCIMGroup, int, error) {
	var where []string
	var args []any
	for _, c := range []struct{ col, v string }{
		{"id = ?", f.ID}, {"display_name = ?", f.DisplayName}, {"external_id = ?", f.ExternalID},
		{"id IN (SELECT group_id FROM scim_group_members WHERE user_id = ?)", f.MemberID},
	} {
		if c.v != "" {
			where, args = append(where, c.col), append(args, c.v)
		}
	}
	cond := "1 = 1"
	if len(where) > 0 {
		cond = strings.Join(where, " AND ")
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scim_groups WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || offset >= total {
		return nil, total, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM scim_groups WHERE `+cond+` ORDER BY created_at, id LIMIT ? OFFSET ?`,
		append(args, limit, max(offset, 0))...)
	if err != nil {
		return nil, 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	out := make([]*SCIMGroup, 0, len(ids))
	for _, id := range ids {
		g, err := getSCIMGroup(ctx, s.db, id, withMembers)
		if errors.Is(err, ErrNotFound) {
			continue // deleted concurrently
		}
		if err != nil {
			return nil, 0, err
		}
		out = append(out, g)
	}
	return out, total, nil
}

// UpdateSCIMGroup loads a group with its members, lets fn modify it and
// stores the result (display name, external ID and the full member list)
// in one transaction, updating the IdP groups of every affected user.
func (s *SQLite) UpdateSCIMGroup(ctx context.Context, id string, now time.Time, fn func(*SCIMGroup) error) (*SCIMGroup, error) {
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		g, err := getSCIMGroup(ctx, tx, id, true)
		if err != nil {
			return err
		}
		oldName, oldIDs := g.DisplayName, memberIDs(g.Members)
		if err := fn(g); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE scim_groups SET display_name = ?, external_id = ?, updated_at = ? WHERE id = ?`,
			g.DisplayName, g.ExternalID, ms(now), id); err != nil {
			return insertErr(err)
		}
		newIDs := memberIDs(g.Members)
		var added, removed []string
		for _, m := range newIDs {
			if !slices.Contains(oldIDs, m) {
				added = append(added, m)
			}
		}
		for _, m := range oldIDs {
			if !slices.Contains(newIDs, m) {
				removed = append(removed, m)
			}
		}
		for _, m := range removed {
			if _, err := tx.ExecContext(ctx, `DELETE FROM scim_group_members WHERE group_id = ? AND user_id = ?`, id, m); err != nil {
				return err
			}
		}
		if err := addMembers(ctx, tx, id, added); err != nil {
			return err
		}
		affected := append(added, removed...)
		if g.DisplayName != oldName {
			affected = append(oldIDs, added...)
		}
		return syncUsers(ctx, tx, affected)
	})
	if err != nil {
		return nil, err
	}
	return s.GetSCIMGroup(ctx, id, true)
}

// DeleteSCIMGroup deletes a group and updates the IdP groups of its
// members.
func (s *SQLite) DeleteSCIMGroup(ctx context.Context, id string, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		g, err := getSCIMGroup(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM scim_groups WHERE id = ?`, id); err != nil {
			return err
		}
		return syncUsers(ctx, tx, memberIDs(g.Members))
	})
}

// UserActive reports whether a user may log in and use tokens. It is false
// for a user deactivated or deleted through SCIM and true for every other
// user (including users never provisioned through SCIM). Authentication
// must check it on login, on every token verification and on every
// session use, independently of whether SCIM is currently enabled.
func (s *SQLite) UserActive(ctx context.Context, email string) (bool, error) {
	var active bool
	var deleted sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT active, deleted_at FROM scim_users WHERE email = ?`, strings.ToLower(email)).
		Scan(&active, &deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return active && !deleted.Valid, nil
}

// RecordLogin records a successful login, replacing UpsertUser in the
// login flow:
//
//   - A user deactivated or deleted through SCIM gets ErrUserInactive
//     (whether or not scimEnabled) and nothing is written.
//   - With scimEnabled, a user provisioned through SCIM keeps the IdP groups
//     computed from its SCIM groups; loginGroups (the id_token groups) are
//     ignored. SCIM-managed groups take precedence over the login snapshot.
//   - Otherwise the IdP groups snapshot is set to loginGroups.
func (s *SQLite) RecordLogin(ctx context.Context, email string, loginGroups []string, now time.Time, scimEnabled bool) error {
	email = strings.ToLower(email)
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var id string
		var active bool
		var deleted sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT id, active, deleted_at FROM scim_users WHERE email = ?`, email).
			Scan(&id, &active, &deleted)
		managed := err == nil
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return err
		case !active || deleted.Valid:
			return ErrUserInactive
		}
		groups := loginGroups
		if scimEnabled && managed {
			if groups, err = scimGroupNames(ctx, tx, id); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO users (email, idp_groups, created_at, last_login_at) VALUES (?, ?, ?, ?)
			ON CONFLICT (email) DO UPDATE SET idp_groups = excluded.idp_groups, last_login_at = excluded.last_login_at`,
			email, encodeList(groups), ms(now), ms(now))
		return err
	})
}

// --- helpers ---

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *SQLite) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func scimEmail(e string) (string, error) {
	e = strings.ToLower(strings.TrimSpace(e))
	if e == "" || !strings.Contains(e, "@") {
		return "", fmt.Errorf("store: SCIM user without a valid email")
	}
	return e, nil
}

func encodeEmails(v []SCIMEmail) (string, error) {
	if v == nil {
		v = []SCIMEmail{}
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func getSCIMUser(ctx context.Context, q queryer, id string) (*SCIMUser, error) {
	u, err := scanSCIMUser(q.QueryRowContext(ctx, `SELECT `+scimUserColumns+` FROM scim_users WHERE id = ? AND deleted_at IS NULL`, id))
	return u, notFound(err)
}

func scanSCIMUser(row scanner) (*SCIMUser, error) {
	var u SCIMUser
	var emails string
	var created, updated int64
	if err := row.Scan(&u.ID, &u.Email, &u.UserName, &u.ExternalID, &u.DisplayName, &u.GivenName, &u.FamilyName,
		&u.FormattedName, &emails, &u.Active, &created, &updated); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(emails), &u.Emails); err != nil {
		return nil, fmt.Errorf("store: decode emails: %w", err)
	}
	u.CreatedAt, u.UpdatedAt = fromMS(created), fromMS(updated)
	return &u, nil
}

func userGroups(ctx context.Context, q queryer, userID string) ([]SCIMGroupRef, error) {
	rows, err := q.QueryContext(ctx, `SELECT g.id, g.display_name FROM scim_group_members m JOIN scim_groups g ON g.id = m.group_id
		WHERE m.user_id = ? ORDER BY g.display_name, g.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SCIMGroupRef
	for rows.Next() {
		var r SCIMGroupRef
		if err := rows.Scan(&r.ID, &r.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func getSCIMGroup(ctx context.Context, q queryer, id string, withMembers bool) (*SCIMGroup, error) {
	var g SCIMGroup
	var created, updated int64
	err := q.QueryRowContext(ctx, `SELECT id, display_name, external_id, created_at, updated_at FROM scim_groups WHERE id = ?`, id).
		Scan(&g.ID, &g.DisplayName, &g.ExternalID, &created, &updated)
	if err != nil {
		return nil, notFound(err)
	}
	g.CreatedAt, g.UpdatedAt = fromMS(created), fromMS(updated)
	if !withMembers {
		return &g, nil
	}
	rows, err := q.QueryContext(ctx, `SELECT u.id, u.user_name FROM scim_group_members m JOIN scim_users u ON u.id = m.user_id
		WHERE m.group_id = ? ORDER BY u.user_name, u.id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	g.Members = []SCIMMember{}
	for rows.Next() {
		var m SCIMMember
		if err := rows.Scan(&m.UserID, &m.UserName); err != nil {
			return nil, err
		}
		g.Members = append(g.Members, m)
	}
	return &g, rows.Err()
}

// memberIDs returns the distinct member user IDs.
func memberIDs(members []SCIMMember) []string {
	var out []string
	for _, m := range members {
		if m.UserID != "" && !slices.Contains(out, m.UserID) {
			out = append(out, m.UserID)
		}
	}
	return out
}

func addMembers(ctx context.Context, tx *sql.Tx, groupID string, userIDs []string) error {
	for _, uid := range userIDs {
		res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO scim_group_members (group_id, user_id)
			SELECT ?, id FROM scim_users WHERE id = ? AND deleted_at IS NULL`, groupID, uid)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			var exists int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scim_group_members WHERE group_id = ? AND user_id = ?`, groupID, uid).Scan(&exists); err != nil {
				return err
			}
			if exists == 0 {
				return fmt.Errorf("%w: %q", ErrUnknownMember, uid)
			}
		}
	}
	return nil
}

func syncUsers(ctx context.Context, tx *sql.Tx, userIDs []string) error {
	for _, id := range userIDs {
		if err := syncIDPGroups(ctx, tx, id); err != nil {
			return err
		}
	}
	return nil
}

// syncIDPGroups rewrites users.idp_groups of a SCIM user from its SCIM
// groups (empty when inactive or deleted). A user who never logged in has
// no users row; RecordLogin computes the groups at the first login.
func syncIDPGroups(ctx context.Context, tx *sql.Tx, userID string) error {
	var email string
	var active bool
	var deleted sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT email, active, deleted_at FROM scim_users WHERE id = ?`, userID).Scan(&email, &active, &deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var groups []string
	if active && !deleted.Valid {
		if groups, err = scimGroupNames(ctx, tx, userID); err != nil {
			return err
		}
	}
	return setIDPGroups(ctx, tx, email, groups)
}

func scimGroupNames(ctx context.Context, tx *sql.Tx, userID string) ([]string, error) {
	refs, err := userGroups(ctx, tx, userID)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.DisplayName)
	}
	return names, nil
}

func setIDPGroups(ctx context.Context, tx *sql.Tx, email string, groups []string) error {
	_, err := tx.ExecContext(ctx, `UPDATE users SET idp_groups = ? WHERE email = ?`, encodeList(groups), email)
	return err
}

// lockOut revokes every token of the human (and every token derived from
// them, transitively, as RevokeToken does) and deletes their sessions.
func lockOut(ctx context.Context, tx *sql.Tx, email string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
		WITH RECURSIVE tree(id, family_id) AS (
			SELECT id, family_id FROM tokens WHERE human = ? COLLATE NOCASE
			UNION
			SELECT t.id, t.family_id FROM tokens t JOIN tree
				ON t.parent_id = tree.id OR (tree.family_id != '' AND t.family_id = tree.family_id)
		)
		UPDATE tokens SET revoked_at = ? WHERE id IN (SELECT id FROM tree) AND revoked_at IS NULL`,
		email, ms(now)); err != nil {
		return fmt.Errorf("store: revoke tokens: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE email = ? COLLATE NOCASE`, email); err != nil {
		return fmt.Errorf("store: delete sessions: %w", err)
	}
	return nil
}
