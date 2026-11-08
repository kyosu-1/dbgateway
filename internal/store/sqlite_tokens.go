package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
)

const tokenColumns = `id, hash, type, kind, human, agent, client_id, client_name, scopes, databases, audience,
	family_id, parent_id, created_at, expires_at, used_at, revoked_at`

// CreateToken stores a token.
func (s *SQLite) CreateToken(ctx context.Context, t *Token) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO tokens (`+tokenColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Hash, string(t.Type), string(t.Kind), t.Human, t.Agent, t.ClientID, t.ClientName,
		encodeList(t.Scopes), encodeList(t.Databases), t.Audience, t.FamilyID, t.ParentID,
		ms(t.CreatedAt), ms(t.ExpiresAt), nullMS(t.UsedAt), nullMS(t.RevokedAt))
	return insertErr(err)
}

// GetToken returns a token by ID.
func (s *SQLite) GetToken(ctx context.Context, id string) (*Token, error) {
	t, err := scanToken(s.db.QueryRowContext(ctx, `SELECT `+tokenColumns+` FROM tokens WHERE id = ?`, id))
	return t, notFound(err)
}

// GetTokenByHash returns a token by the hash of its secret.
func (s *SQLite) GetTokenByHash(ctx context.Context, hash string) (*Token, error) {
	t, err := scanToken(s.db.QueryRowContext(ctx, `SELECT `+tokenColumns+` FROM tokens WHERE hash = ?`, hash))
	return t, notFound(err)
}

// ListTokens returns the tokens of a human, newest first.
func (s *SQLite) ListTokens(ctx context.Context, human string) ([]*Token, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+tokenColumns+` FROM tokens WHERE human = ? ORDER BY created_at DESC, id`, human)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// MarkTokenUsed sets used_at on an unused, unrevoked token.
func (s *SQLite) MarkTokenUsed(ctx context.Context, id string, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE tokens SET used_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL`, ms(now), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// revokeTree revokes the seed tokens (selected by seedWhere) and every token
// derived from them, transitively through parent_id and family_id.
func (s *SQLite) revokeTree(ctx context.Context, seedWhere string, arg any, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		WITH RECURSIVE tree(id, family_id) AS (
			SELECT id, family_id FROM tokens WHERE `+seedWhere+`
			UNION
			SELECT t.id, t.family_id FROM tokens t JOIN tree
				ON t.parent_id = tree.id OR (tree.family_id != '' AND t.family_id = tree.family_id)
		)
		UPDATE tokens SET revoked_at = ? WHERE id IN (SELECT id FROM tree) AND revoked_at IS NULL`,
		arg, ms(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RevokeToken revokes a token, its family and every derived token.
func (s *SQLite) RevokeToken(ctx context.Context, id string, now time.Time) (int64, error) {
	return s.revokeTree(ctx, `id = ?`, id, now)
}

// RevokeFamily revokes every token of a family and every derived token.
func (s *SQLite) RevokeFamily(ctx context.Context, familyID string, now time.Time) (int64, error) {
	if familyID == "" {
		return 0, nil
	}
	return s.revokeTree(ctx, `family_id = ?`, familyID, now)
}

func scanToken(row scanner) (*Token, error) {
	var t Token
	var typ, kind, scopes, dbs string
	var created, expires int64
	var used, revoked sql.NullInt64
	if err := row.Scan(&t.ID, &t.Hash, &typ, &kind, &t.Human, &t.Agent, &t.ClientID, &t.ClientName,
		&scopes, &dbs, &t.Audience, &t.FamilyID, &t.ParentID, &created, &expires, &used, &revoked); err != nil {
		return nil, err
	}
	var err error
	if t.Scopes, err = decodeList(scopes); err != nil {
		return nil, err
	}
	if t.Databases, err = decodeList(dbs); err != nil {
		return nil, err
	}
	t.Type, t.Kind = TokenType(typ), identity.Kind(kind)
	t.CreatedAt, t.ExpiresAt = fromMS(created), fromMS(expires)
	t.UsedAt, t.RevokedAt = fromNullMS(used), fromNullMS(revoked)
	return &t, nil
}
