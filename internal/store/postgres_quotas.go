package store

import (
	"context"
	"strings"
	"time"
)

// AddQuotaUsage adds usage to the buckets in one upsert. Concurrent
// instances add atomically (INSERT ... ON CONFLICT DO UPDATE), and the
// rows are written in key order so that concurrent upserts cannot
// deadlock.
func (s *Postgres) AddQuotaUsage(ctx context.Context, usage []QuotaUsage) error {
	if len(usage) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString(`INSERT INTO quota_usage (requester, quota, bucket, query_count, row_count, expires_at) VALUES `)
	var args pgArgs
	for i, u := range sortedQuotaUsage(usage) {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("(" + args.add(u.Requester) + ", " + args.add(u.Quota) + ", " + args.add(pgTime(u.Bucket)) + ", " +
			args.add(u.Queries) + ", " + args.add(u.Rows) + ", " + args.add(pgTime(u.ExpiresAt)) + ")")
	}
	b.WriteString(` ON CONFLICT (requester, quota, bucket) DO UPDATE SET
		query_count = quota_usage.query_count + excluded.query_count,
		row_count = quota_usage.row_count + excluded.row_count,
		expires_at = GREATEST(quota_usage.expires_at, excluded.expires_at)`)
	_, err := s.pool.Exec(ctx, b.String(), args...)
	return err
}

// ListQuotaUsage returns the buckets of requester for quotas since since.
func (s *Postgres) ListQuotaUsage(ctx context.Context, requester string, quotas []string, since time.Time) ([]QuotaUsage, error) {
	if len(quotas) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT requester, quota, bucket, query_count, row_count, expires_at FROM quota_usage
		WHERE requester = $1 AND quota = ANY($2) AND bucket >= $3
		ORDER BY quota, bucket`, requester, quotas, pgTime(since))
	if err != nil {
		return nil, err
	}
	return pgCollect(rows, func(r scanner) (QuotaUsage, error) {
		var u QuotaUsage
		err := r.Scan(&u.Requester, &u.Quota, &u.Bucket, &u.Queries, &u.Rows, &u.ExpiresAt)
		u.Bucket, u.ExpiresAt = fromPGTime(u.Bucket), fromPGTime(u.ExpiresAt)
		return u, err
	})
}
