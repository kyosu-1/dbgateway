package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// Quotas (config `quotas`) bound how much one requester may read over
// time, so that data cannot be pulled out slowly through many small
// queries that each pass the policies.
//
// Usage is kept in the management store in one-minute buckets per
// requester and quota (store.QuotaStore), so every instance sharing the
// store sees the same counts. Before an allowed read runs, the buckets of
// the matching quotas are loaded and summed per limit; a used-up limit
// denies the read (rule "quota:<name>"), and the remaining row allowance
// lowers the read's row limit, so one query cannot go past a row limit.
// After the read, one upsert adds the query and the rows returned to
// every matching quota.
//
// Check and record are not one transaction: concurrent reads of one
// requester can each pass the check, so a limit can be exceeded by the
// reads in flight at that moment (each still bounded by its row limit).
//
// Store errors fail closed: the read is not run (or its result is
// withheld when recording fails). The management store is already needed
// for every request (tokens and sessions are looked up in it), so this
// adds no new dependency.

// Errors returned when quota usage cannot be read or written.
var (
	errQuotaUnavailable = errors.New("quota usage could not be checked, so the query was not run; try again later or contact an administrator")
	errQuotaNotRecorded = errors.New("quota usage could not be recorded, so the result is withheld; try again later or contact an administrator")
)

// quotaRequester is the key quotas are counted under: the person (for
// agents, the person they act for, across all their agents and tokens),
// like anomaly detection.
func quotaRequester(p *identity.Principal) string {
	if p.Human != "" {
		return strings.ToLower(p.Human)
	}
	return "client:" + p.ClientID
}

// quotaCheck is the state of the quotas of one read.
type quotaCheck struct {
	requester string
	quotas    []*config.Quota
	// exceeded is the used-up limit that frees up last; nil when none is.
	exceeded *quotaExceeded
	// rowsLeft is the number of rows the tightest row limit still allows,
	// or -1 when no matching quota limits rows.
	rowsLeft  int64
	rowsQuota *config.Quota
	rowsLimit config.QuotaLimit
}

type quotaExceeded struct {
	quota  *config.Quota
	limit  config.QuotaLimit
	used   int64
	freeAt time.Time
}

// checkQuotas loads the usage of quotas for p and evaluates it. It returns
// nil when no quota applies.
func (g *Gateway) checkQuotas(ctx context.Context, p *identity.Principal, quotas []*config.Quota) (*quotaCheck, error) {
	if len(quotas) == 0 {
		return nil, nil
	}
	if g.quotaStore == nil {
		return nil, errQuotaUnavailable
	}
	now := g.now()
	var longest time.Duration
	names := make([]string, len(quotas))
	for i, q := range quotas {
		names[i] = q.Name
		longest = max(longest, q.Window())
	}
	requester := quotaRequester(p)
	usage, err := g.quotaStore.ListQuotaUsage(ctx, requester, names, windowStart(now, longest))
	if err != nil {
		g.logger.Error("quota usage could not be read", "err", err)
		return nil, errQuotaUnavailable
	}
	qc := evaluateQuotas(quotas, usage, now)
	qc.requester = requester
	return qc, nil
}

// windowStart is the first bucket inside a window of length w ending now.
// Windows slide by whole minutes: the window of an hour is the current
// minute and the 59 before it.
func windowStart(now time.Time, w time.Duration) time.Time {
	return store.QuotaBucket(now).Add(-w + time.Minute)
}

// evaluateQuotas sums usage per limit. usage must be ordered by bucket
// within each quota (as ListQuotaUsage returns it).
func evaluateQuotas(quotas []*config.Quota, usage []store.QuotaUsage, now time.Time) *quotaCheck {
	qc := &quotaCheck{quotas: quotas, rowsLeft: -1}
	byQuota := map[string][]store.QuotaUsage{}
	for _, u := range usage {
		byQuota[u.Quota] = append(byQuota[u.Quota], u)
	}
	for _, q := range quotas {
		for _, l := range q.Limits() {
			start := windowStart(now, l.Window)
			var inWindow []store.QuotaUsage
			var used int64
			for _, u := range byQuota[q.Name] {
				if u.Bucket.Before(start) {
					continue
				}
				inWindow = append(inWindow, u)
				used += quotaValue(u, l)
			}
			if used >= l.Max {
				free := freeAt(inWindow, l, used)
				if qc.exceeded == nil || free.After(qc.exceeded.freeAt) {
					qc.exceeded = &quotaExceeded{quota: q, limit: l, used: used, freeAt: free}
				}
				continue
			}
			if l.Rows && (qc.rowsLeft < 0 || l.Max-used < qc.rowsLeft) {
				qc.rowsLeft, qc.rowsQuota, qc.rowsLimit = l.Max-used, q, l
			}
		}
	}
	return qc
}

func quotaValue(u store.QuotaUsage, l config.QuotaLimit) int64 {
	if l.Rows {
		return u.Rows
	}
	return u.Queries
}

// freeAt returns when enough of the oldest buckets have left the window
// for usage to drop below the limit.
func freeAt(inWindow []store.QuotaUsage, l config.QuotaLimit, used int64) time.Time {
	for _, u := range inWindow {
		used -= quotaValue(u, l)
		if used < l.Max {
			return u.Bucket.Add(l.Window)
		}
	}
	// Unreachable for l.Max > 0: everything has left the window by then.
	return inWindow[len(inWindow)-1].Bucket.Add(l.Window)
}

// recordQuotas adds one query and rows returned rows to every quota of qc.
func (g *Gateway) recordQuotas(ctx context.Context, qc *quotaCheck, rows int) error {
	if qc == nil {
		return nil
	}
	if g.quotaStore == nil {
		return errQuotaNotRecorded
	}
	bucket := store.QuotaBucket(g.now())
	usage := make([]store.QuotaUsage, len(qc.quotas))
	for i, q := range qc.quotas {
		usage[i] = store.QuotaUsage{Requester: qc.requester, Quota: q.Name, Bucket: bucket, Queries: 1, Rows: int64(rows),
			ExpiresAt: bucket.Add(q.Window())}
	}
	// The read already ran: record it even if the caller went away.
	if err := g.quotaStore.AddQuotaUsage(context.WithoutCancel(ctx), usage); err != nil {
		g.logger.Error("quota usage could not be recorded", "err", err)
		return errQuotaNotRecorded
	}
	return nil
}

// ruleQuota is the rule name of a quota denial.
func ruleQuota(q *config.Quota) string { return "quota:" + q.Name }

// denial returns the reason and hint of a used-up limit.
func (e *quotaExceeded) denial(now time.Time) (reason, hint string) {
	unit, advice := "queries", "Combine what you need into fewer queries."
	if e.limit.Rows {
		unit, advice = "rows", "Narrow the conditions or aggregate so that queries return fewer rows."
	}
	reason = fmt.Sprintf("Quota %q is used up: %d of %d %s in the last %s (%s).",
		e.quota.Name, e.used, e.limit.Max, unit, windowName(e.limit.Window), e.limit.Key)
	hint = fmt.Sprintf("The quota frees up at %s (in %s); try again then (earlier attempts are denied again). %s",
		e.freeAt.UTC().Format(time.RFC3339), untilText(e.freeAt.Sub(now)), advice)
	if h := strings.TrimSpace(e.quota.Hint); h != "" {
		hint += " " + h
	}
	return reason, hint
}

func windowName(w time.Duration) string {
	switch w {
	case config.QuotaMinute:
		return "minute"
	case config.QuotaHour:
		return "hour"
	case config.QuotaDay:
		return "24 hours"
	}
	return w.String()
}

// untilText formats a wait for people: "45s", "12m", "3h05m".
func untilText(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", max(1, int(d.Round(time.Second).Seconds())))
	}
	m := int((d + time.Minute - 1) / time.Minute)
	if m < 60 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%dh%02dm", m/60, m%60)
}
