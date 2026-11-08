package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// SCIM provisioning on PostgreSQL. The semantics are those documented in
// sqlite_scim.go. SQLite serializes every write transaction; here every
// SCIM write transaction takes the SCIM advisory lock (exclusive) and
// RecordLogin takes it shared, so that the read-modify-write sequences
// (tombstone replacement, member lists, users.idp_groups recomputation)
// see a consistent state across instances. SCIM writes are rare (IdP
// synchronization), so serializing them costs nothing noticeable.

// inSCIMTx runs fn in a transaction holding the SCIM advisory lock.
func (s *Postgres) inSCIMTx(ctx context.Context, fn func(pgx.Tx) error) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, pgLockSCIM); err != nil {
			return err
		}
		return fn(tx)
	})
}

// CreateSCIMUser stores a new SCIM user (see SQLite.CreateSCIMUser).
func (s *Postgres) CreateSCIMUser(ctx context.Context, u *SCIMUser, now time.Time) error {
	email, err := scimEmail(u.Email)
	if err != nil {
		return err
	}
	now = pgTime(now)
	u.Email, u.CreatedAt, u.UpdatedAt = email, now, now
	emails, err := encodeEmails(u.Emails)
	if err != nil {
		return err
	}
	return s.inSCIMTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM scim_users WHERE deleted_at IS NOT NULL AND (email = $1 OR lower(user_name) = lower($2))`,
			u.Email, u.UserName); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO scim_users (`+scimUserColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)`,
			u.ID, u.Email, u.UserName, u.ExternalID, u.DisplayName, u.GivenName, u.FamilyName, u.FormattedName,
			emails, u.Active, now)
		if err != nil {
			return pgInsertErr(err)
		}
		if !u.Active {
			if err := pgLockOut(ctx, tx, u.Email, now); err != nil {
				return err
			}
		}
		return pgSyncIDPGroups(ctx, tx, u.ID)
	})
}

// GetSCIMUser returns a live (not deleted) SCIM user with its groups.
func (s *Postgres) GetSCIMUser(ctx context.Context, id string) (*SCIMUser, error) {
	u, err := pgGetSCIMUser(ctx, s.pool, id)
	if err != nil {
		return nil, err
	}
	if u.Groups, err = pgUserGroups(ctx, s.pool, id); err != nil {
		return nil, err
	}
	return u, nil
}

// ListSCIMUsers returns the live users matching f, oldest first (see
// SQLite.ListSCIMUsers).
func (s *Postgres) ListSCIMUsers(ctx context.Context, f SCIMUserFilter, offset, limit int) ([]*SCIMUser, int, error) {
	where := []string{"deleted_at IS NULL"}
	var args pgArgs
	if f.ID != "" {
		where = append(where, "id = "+args.add(f.ID))
	}
	if f.UserName != "" {
		where = append(where, "lower(user_name) = lower("+args.add(f.UserName)+")")
	}
	if f.ExternalID != "" {
		where = append(where, "external_id = "+args.add(f.ExternalID))
	}
	if f.Email != "" {
		where = append(where, "email = "+args.add(strings.ToLower(f.Email)))
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM scim_users WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || offset >= total {
		return nil, total, nil
	}
	q := `SELECT ` + scimUserColumns + ` FROM scim_users WHERE ` + cond +
		` ORDER BY created_at, id LIMIT ` + args.add(limit) + ` OFFSET ` + args.add(max(offset, 0))
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgCollect(rows, pgScanSCIMUser)
	if err != nil {
		return nil, 0, err
	}
	for _, u := range out {
		if u.Groups, err = pgUserGroups(ctx, s.pool, u.ID); err != nil {
			return nil, 0, err
		}
	}
	return out, total, nil
}

// UpdateSCIMUser loads a live user, lets fn modify it and stores the
// result in one transaction (see SQLite.UpdateSCIMUser).
func (s *Postgres) UpdateSCIMUser(ctx context.Context, id string, now time.Time, fn func(*SCIMUser) error) (*SCIMUser, error) {
	now = pgTime(now)
	err := s.inSCIMTx(ctx, func(tx pgx.Tx) error {
		u, err := pgGetSCIMUser(ctx, tx, id)
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
		if _, err := tx.Exec(ctx, `DELETE FROM scim_users WHERE deleted_at IS NOT NULL AND id <> $1 AND (email = $2 OR lower(user_name) = lower($3))`,
			id, u.Email, u.UserName); err != nil {
			return err
		}
		emails, err := encodeEmails(u.Emails)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE scim_users SET email = $1, user_name = $2, external_id = $3, display_name = $4,
			given_name = $5, family_name = $6, formatted_name = $7, emails = $8, active = $9, updated_at = $10 WHERE id = $11`,
			u.Email, u.UserName, u.ExternalID, u.DisplayName, u.GivenName, u.FamilyName, u.FormattedName,
			emails, u.Active, now, id)
		if err != nil {
			return pgInsertErr(err)
		}
		if old.Email != u.Email {
			if err := pgLockOut(ctx, tx, old.Email, now); err != nil {
				return err
			}
			if err := pgSetIDPGroups(ctx, tx, old.Email, nil); err != nil {
				return err
			}
		}
		if !u.Active {
			if err := pgLockOut(ctx, tx, u.Email, now); err != nil {
				return err
			}
		}
		return pgSyncIDPGroups(ctx, tx, id)
	})
	if err != nil {
		return nil, err
	}
	return s.GetSCIMUser(ctx, id)
}

// DeleteSCIMUser deletes a SCIM user, keeping a tombstone (see
// SQLite.DeleteSCIMUser).
func (s *Postgres) DeleteSCIMUser(ctx context.Context, id string, now time.Time) error {
	now = pgTime(now)
	return s.inSCIMTx(ctx, func(tx pgx.Tx) error {
		u, err := pgGetSCIMUser(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM scim_group_members WHERE user_id = $1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE scim_users SET active = false, deleted_at = $1, updated_at = $1 WHERE id = $2`,
			now, id); err != nil {
			return err
		}
		if err := pgLockOut(ctx, tx, u.Email, now); err != nil {
			return err
		}
		return pgSyncIDPGroups(ctx, tx, id)
	})
}

// CreateSCIMGroup stores a new group with its members (see
// SQLite.CreateSCIMGroup).
func (s *Postgres) CreateSCIMGroup(ctx context.Context, g *SCIMGroup, now time.Time) error {
	now = pgTime(now)
	g.CreatedAt, g.UpdatedAt = now, now
	return s.inSCIMTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO scim_groups (id, display_name, external_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $4)`,
			g.ID, g.DisplayName, g.ExternalID, now)
		if err != nil {
			return pgInsertErr(err)
		}
		ids := memberIDs(g.Members)
		if err := pgAddMembers(ctx, tx, g.ID, ids); err != nil {
			return err
		}
		return pgSyncUsers(ctx, tx, ids)
	})
}

// GetSCIMGroup returns a group, with its members if withMembers is set.
func (s *Postgres) GetSCIMGroup(ctx context.Context, id string, withMembers bool) (*SCIMGroup, error) {
	return pgGetSCIMGroup(ctx, s.pool, id, withMembers)
}

// ListSCIMGroups returns the groups matching f like ListSCIMUsers.
func (s *Postgres) ListSCIMGroups(ctx context.Context, f SCIMGroupFilter, offset, limit int, withMembers bool) ([]*SCIMGroup, int, error) {
	where := []string{"true"}
	var args pgArgs
	if f.ID != "" {
		where = append(where, "id = "+args.add(f.ID))
	}
	if f.DisplayName != "" {
		where = append(where, "lower(display_name) = lower("+args.add(f.DisplayName)+")")
	}
	if f.ExternalID != "" {
		where = append(where, "external_id = "+args.add(f.ExternalID))
	}
	if f.MemberID != "" {
		where = append(where, "id IN (SELECT group_id FROM scim_group_members WHERE user_id = "+args.add(f.MemberID)+")")
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM scim_groups WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || offset >= total {
		return nil, total, nil
	}
	q := `SELECT id FROM scim_groups WHERE ` + cond + ` ORDER BY created_at, id LIMIT ` + args.add(limit) + ` OFFSET ` + args.add(max(offset, 0))
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, 0, err
	}
	out := make([]*SCIMGroup, 0, len(ids))
	for _, id := range ids {
		g, err := pgGetSCIMGroup(ctx, s.pool, id, withMembers)
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
// stores the result in one transaction (see SQLite.UpdateSCIMGroup).
func (s *Postgres) UpdateSCIMGroup(ctx context.Context, id string, now time.Time, fn func(*SCIMGroup) error) (*SCIMGroup, error) {
	now = pgTime(now)
	err := s.inSCIMTx(ctx, func(tx pgx.Tx) error {
		g, err := pgGetSCIMGroup(ctx, tx, id, true)
		if err != nil {
			return err
		}
		oldName, oldIDs := g.DisplayName, memberIDs(g.Members)
		if err := fn(g); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE scim_groups SET display_name = $1, external_id = $2, updated_at = $3 WHERE id = $4`,
			g.DisplayName, g.ExternalID, now, id); err != nil {
			return pgInsertErr(err)
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
		if len(removed) > 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM scim_group_members WHERE group_id = $1 AND user_id = ANY($2)`, id, removed); err != nil {
				return err
			}
		}
		if err := pgAddMembers(ctx, tx, id, added); err != nil {
			return err
		}
		affected := append(added, removed...)
		if g.DisplayName != oldName {
			affected = append(oldIDs, added...)
		}
		return pgSyncUsers(ctx, tx, affected)
	})
	if err != nil {
		return nil, err
	}
	return s.GetSCIMGroup(ctx, id, true)
}

// DeleteSCIMGroup deletes a group and updates the IdP groups of its
// members.
func (s *Postgres) DeleteSCIMGroup(ctx context.Context, id string, now time.Time) error {
	return s.inSCIMTx(ctx, func(tx pgx.Tx) error {
		g, err := pgGetSCIMGroup(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM scim_groups WHERE id = $1`, id); err != nil {
			return err
		}
		return pgSyncUsers(ctx, tx, memberIDs(g.Members))
	})
}

// UserActive reports whether a user may log in and use tokens (see
// SQLite.UserActive).
func (s *Postgres) UserActive(ctx context.Context, email string) (bool, error) {
	var active bool
	var deleted *time.Time
	err := s.pool.QueryRow(ctx, `SELECT active, deleted_at FROM scim_users WHERE email = $1`, strings.ToLower(email)).
		Scan(&active, &deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return active && deleted == nil, nil
}

// RecordLogin records a successful login (see SQLite.RecordLogin). It
// holds the SCIM lock shared, so that it never computes the groups from a
// state a concurrent SCIM change is replacing.
func (s *Postgres) RecordLogin(ctx context.Context, email string, loginGroups []string, now time.Time, scimEnabled bool) error {
	email = strings.ToLower(email)
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, pgLockSCIM); err != nil {
			return err
		}
		var id string
		var active bool
		var deleted *time.Time
		err := tx.QueryRow(ctx, `SELECT id, active, deleted_at FROM scim_users WHERE email = $1`, email).
			Scan(&id, &active, &deleted)
		managed := err == nil
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		case !active || deleted != nil:
			return ErrUserInactive
		}
		groups := loginGroups
		if scimEnabled && managed {
			if groups, err = pgSCIMGroupNames(ctx, tx, id); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO users (email, idp_groups, created_at, last_login_at) VALUES ($1, $2, $3, $3)
			ON CONFLICT (email) DO UPDATE SET idp_groups = excluded.idp_groups, last_login_at = excluded.last_login_at`,
			email, encodeList(groups), pgTime(now))
		return err
	})
}

// --- helpers ---

func pgGetSCIMUser(ctx context.Context, q pgQuerier, id string) (*SCIMUser, error) {
	u, err := pgScanSCIMUser(q.QueryRow(ctx, `SELECT `+scimUserColumns+` FROM scim_users WHERE id = $1 AND deleted_at IS NULL`, id))
	return u, pgNotFound(err)
}

func pgScanSCIMUser(row scanner) (*SCIMUser, error) {
	var u SCIMUser
	var emails string
	if err := row.Scan(&u.ID, &u.Email, &u.UserName, &u.ExternalID, &u.DisplayName, &u.GivenName, &u.FamilyName,
		&u.FormattedName, &emails, &u.Active, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(emails), &u.Emails); err != nil {
		return nil, fmt.Errorf("store: decode emails: %w", err)
	}
	u.CreatedAt, u.UpdatedAt = fromPGTime(u.CreatedAt), fromPGTime(u.UpdatedAt)
	return &u, nil
}

func pgUserGroups(ctx context.Context, q pgQuerier, userID string) ([]SCIMGroupRef, error) {
	rows, err := q.Query(ctx, `SELECT g.id, g.display_name FROM scim_group_members m JOIN scim_groups g ON g.id = m.group_id
		WHERE m.user_id = $1 ORDER BY g.display_name, g.id`, userID)
	if err != nil {
		return nil, err
	}
	return pgCollect(rows, func(row scanner) (SCIMGroupRef, error) {
		var r SCIMGroupRef
		err := row.Scan(&r.ID, &r.DisplayName)
		return r, err
	})
}

func pgGetSCIMGroup(ctx context.Context, q pgQuerier, id string, withMembers bool) (*SCIMGroup, error) {
	var g SCIMGroup
	err := q.QueryRow(ctx, `SELECT id, display_name, external_id, created_at, updated_at FROM scim_groups WHERE id = $1`, id).
		Scan(&g.ID, &g.DisplayName, &g.ExternalID, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return nil, pgNotFound(err)
	}
	g.CreatedAt, g.UpdatedAt = fromPGTime(g.CreatedAt), fromPGTime(g.UpdatedAt)
	if !withMembers {
		return &g, nil
	}
	rows, err := q.Query(ctx, `SELECT u.id, u.user_name FROM scim_group_members m JOIN scim_users u ON u.id = m.user_id
		WHERE m.group_id = $1 ORDER BY u.user_name, u.id`, id)
	if err != nil {
		return nil, err
	}
	members, err := pgCollect(rows, func(row scanner) (SCIMMember, error) {
		var m SCIMMember
		err := row.Scan(&m.UserID, &m.UserName)
		return m, err
	})
	if err != nil {
		return nil, err
	}
	g.Members = append([]SCIMMember{}, members...)
	return &g, nil
}

func pgAddMembers(ctx context.Context, tx pgx.Tx, groupID string, userIDs []string) error {
	for _, uid := range userIDs {
		var live bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scim_users WHERE id = $1 AND deleted_at IS NULL)`, uid).Scan(&live); err != nil {
			return err
		}
		if !live {
			return fmt.Errorf("%w: %q", ErrUnknownMember, uid)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO scim_group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			groupID, uid); err != nil {
			return err
		}
	}
	return nil
}

func pgSyncUsers(ctx context.Context, tx pgx.Tx, userIDs []string) error {
	for _, id := range userIDs {
		if err := pgSyncIDPGroups(ctx, tx, id); err != nil {
			return err
		}
	}
	return nil
}

// pgSyncIDPGroups rewrites users.idp_groups of a SCIM user from its SCIM
// groups (empty when inactive or deleted).
func pgSyncIDPGroups(ctx context.Context, tx pgx.Tx, userID string) error {
	var email string
	var active bool
	var deleted *time.Time
	err := tx.QueryRow(ctx, `SELECT email, active, deleted_at FROM scim_users WHERE id = $1`, userID).Scan(&email, &active, &deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var groups []string
	if active && deleted == nil {
		if groups, err = pgSCIMGroupNames(ctx, tx, userID); err != nil {
			return err
		}
	}
	return pgSetIDPGroups(ctx, tx, email, groups)
}

func pgSCIMGroupNames(ctx context.Context, tx pgx.Tx, userID string) ([]string, error) {
	refs, err := pgUserGroups(ctx, tx, userID)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.DisplayName)
	}
	return names, nil
}

func pgSetIDPGroups(ctx context.Context, tx pgx.Tx, email string, groups []string) error {
	_, err := tx.Exec(ctx, `UPDATE users SET idp_groups = $1 WHERE email = $2`, encodeList(groups), email)
	return err
}

// pgLockOut revokes every token of the human (and every token derived
// from them) and deletes their sessions.
func pgLockOut(ctx context.Context, tx pgx.Tx, email string, now time.Time) error {
	if _, err := pgRevokeTree(ctx, tx, `lower(human) = lower($1)`, email, now); err != nil {
		return fmt.Errorf("store: revoke tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE lower(email) = lower($1)`, email); err != nil {
		return fmt.Errorf("store: delete sessions: %w", err)
	}
	return nil
}
