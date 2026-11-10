package store

import (
	"context"
	"strings"
	"time"
)

// AddQuotaUsage adds usage to the buckets in one upsert.
func (s *SQLite) AddQuotaUsage(ctx context.Context, usage []QuotaUsage) error {
	if len(usage) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString(`INSERT INTO quota_usage (requester, quota, bucket, query_count, row_count, expires_at) VALUES `)
	args := make([]any, 0, 6*len(usage))
	for i, u := range sortedQuotaUsage(usage) {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("(?, ?, ?, ?, ?, ?)")
		args = append(args, u.Requester, u.Quota, ms(u.Bucket), u.Queries, u.Rows, ms(u.ExpiresAt))
	}
	b.WriteString(` ON CONFLICT (requester, quota, bucket) DO UPDATE SET
		query_count = query_count + excluded.query_count,
		row_count = row_count + excluded.row_count,
		expires_at = max(expires_at, excluded.expires_at)`)
	_, err := s.db.ExecContext(ctx, b.String(), args...)
	return err
}

// ListQuotaUsage returns the buckets of requester for quotas since since.
func (s *SQLite) ListQuotaUsage(ctx context.Context, requester string, quotas []string, since time.Time) ([]QuotaUsage, error) {
	if len(quotas) == 0 {
		return nil, nil
	}
	args := []any{requester, ms(since)}
	for _, q := range quotas {
		args = append(args, q)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT requester, quota, bucket, query_count, row_count, expires_at FROM quota_usage
		WHERE requester = ? AND bucket >= ? AND quota IN (?`+strings.Repeat(", ?", len(quotas)-1)+`)
		ORDER BY quota, bucket`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QuotaUsage
	for rows.Next() {
		var u QuotaUsage
		var bucket, expires int64
		if err := rows.Scan(&u.Requester, &u.Quota, &bucket, &u.Queries, &u.Rows, &expires); err != nil {
			return nil, err
		}
		u.Bucket, u.ExpiresAt = fromMS(bucket).UTC(), fromMS(expires).UTC()
		out = append(out, u)
	}
	return out, rows.Err()
}
