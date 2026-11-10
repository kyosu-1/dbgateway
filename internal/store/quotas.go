package store

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"time"
)

// Quota usage (migration 0007). Usage is counted in one-minute buckets per
// requester and quota, so that every instance sharing the management
// database sees the same counts and windows slide minute by minute.

// QuotaUsage is the usage of one quota by one requester in one minute.
type QuotaUsage struct {
	Requester string
	Quota     string
	// Bucket is the start of the minute (UTC).
	Bucket  time.Time
	Queries int64
	Rows    int64
	// ExpiresAt is when no window of the quota needs the bucket any more;
	// DeleteExpired removes it after that.
	ExpiresAt time.Time
}

// QuotaStore keeps quota usage.
type QuotaStore interface {
	// AddQuotaUsage adds each entry's queries and rows to its bucket
	// (Bucket is truncated to the minute), creating the bucket if needed,
	// in one statement. A bucket's ExpiresAt is extended, never shortened.
	// Entries must have distinct (Requester, Quota, Bucket).
	AddQuotaUsage(ctx context.Context, usage []QuotaUsage) error
	// ListQuotaUsage returns the buckets of requester for the given quotas
	// that start at or after since, ordered by quota and bucket.
	ListQuotaUsage(ctx context.Context, requester string, quotas []string, since time.Time) ([]QuotaUsage, error)
}

// QuotaBucket returns the bucket (start of the minute, UTC) of t.
func QuotaBucket(t time.Time) time.Time { return t.UTC().Truncate(time.Minute) }

// sortedQuotaUsage returns usage ordered by key, so that concurrent
// upserts lock rows in the same order (no deadlocks on PostgreSQL).
func sortedQuotaUsage(usage []QuotaUsage) []QuotaUsage {
	out := make([]QuotaUsage, len(usage))
	copy(out, usage)
	for i := range out {
		out[i].Bucket = QuotaBucket(out[i].Bucket)
	}
	slices.SortFunc(out, func(a, b QuotaUsage) int {
		return cmp.Or(strings.Compare(a.Requester, b.Requester), strings.Compare(a.Quota, b.Quota), a.Bucket.Compare(b.Bucket))
	})
	return out
}
