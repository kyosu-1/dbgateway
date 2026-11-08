package store

import (
	"context"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
)

// CreateToken stores a token.
func (s *Postgres) CreateToken(ctx context.Context, t *Token) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO tokens (`+tokenColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		t.ID, t.Hash, string(t.Type), string(t.Kind), t.Human, t.Agent, t.ClientID, t.ClientName,
		encodeList(t.Scopes), encodeList(t.Databases), t.Audience, t.FamilyID, t.ParentID,
		pgTime(t.CreatedAt), pgTime(t.ExpiresAt), pgNullTime(t.UsedAt), pgNullTime(t.RevokedAt))
	return pgInsertErr(err)
}

// GetToken returns a token by ID.
func (s *Postgres) GetToken(ctx context.Context, id string) (*Token, error) {
	t, err := pgScanToken(s.pool.QueryRow(ctx, `SELECT `+tokenColumns+` FROM tokens WHERE id = $1`, id))
	return t, pgNotFound(err)
}

// GetTokenByHash returns a token by the hash of its secret.
func (s *Postgres) GetTokenByHash(ctx context.Context, hash string) (*Token, error) {
	t, err := pgScanToken(s.pool.QueryRow(ctx, `SELECT `+tokenColumns+` FROM tokens WHERE hash = $1`, hash))
	return t, pgNotFound(err)
}

// ListTokens returns the tokens of a human, newest first.
func (s *Postgres) ListTokens(ctx context.Context, human string) ([]*Token, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+tokenColumns+` FROM tokens WHERE human = $1 ORDER BY created_at DESC, id`, human)
	if err != nil {
		return nil, err
	}
	return pgCollect(rows, pgScanToken)
}

// MarkTokenUsed sets used_at on an unused, unrevoked token.
func (s *Postgres) MarkTokenUsed(ctx context.Context, id string, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE tokens SET used_at = $1 WHERE id = $2 AND used_at IS NULL AND revoked_at IS NULL`, pgTime(now), id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// RevokeToken revokes a token, its family and every derived token.
func (s *Postgres) RevokeToken(ctx context.Context, id string, now time.Time) (int64, error) {
	return pgRevokeTree(ctx, s.pool, `id = $1`, id, now)
}

// RevokeFamily revokes every token of a family and every derived token.
func (s *Postgres) RevokeFamily(ctx context.Context, familyID string, now time.Time) (int64, error) {
	if familyID == "" {
		return 0, nil
	}
	return pgRevokeTree(ctx, s.pool, `family_id = $1`, familyID, now)
}

// pgRevokeTree revokes the seed tokens (selected by seedWhere, whose
// argument is $1) and every token derived from them, transitively through
// parent_id and family_id. The rows are locked in id order first, so that
// concurrent revocations of overlapping trees cannot deadlock.
func pgRevokeTree(ctx context.Context, q pgQuerier, seedWhere string, arg any, now time.Time) (int64, error) {
	tag, err := q.Exec(ctx, `
		WITH RECURSIVE tree(id, family_id) AS (
			SELECT id, family_id FROM tokens WHERE `+seedWhere+`
			UNION
			SELECT t.id, t.family_id FROM tokens t JOIN tree
				ON t.parent_id = tree.id OR (tree.family_id <> '' AND t.family_id = tree.family_id)
		), locked AS (
			SELECT id FROM tokens WHERE id IN (SELECT id FROM tree) AND revoked_at IS NULL ORDER BY id FOR UPDATE
		)
		UPDATE tokens SET revoked_at = $2 WHERE id IN (SELECT id FROM locked)`,
		arg, pgTime(now))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func pgScanToken(row scanner) (*Token, error) {
	var t Token
	var typ, kind, scopes, dbs string
	if err := row.Scan(&t.ID, &t.Hash, &typ, &kind, &t.Human, &t.Agent, &t.ClientID, &t.ClientName,
		&scopes, &dbs, &t.Audience, &t.FamilyID, &t.ParentID, &t.CreatedAt, &t.ExpiresAt, &t.UsedAt, &t.RevokedAt); err != nil {
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
	t.CreatedAt, t.ExpiresAt = fromPGTime(t.CreatedAt), fromPGTime(t.ExpiresAt)
	t.UsedAt, t.RevokedAt = fromPGNullTime(t.UsedAt), fromPGNullTime(t.RevokedAt)
	return &t, nil
}
