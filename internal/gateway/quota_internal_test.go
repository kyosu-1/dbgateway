package gateway

import (
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/store"
)

func TestEvaluateQuotas(t *testing.T) {
	now := time.Date(2026, 11, 11, 10, 0, 15, 0, time.UTC)
	min0 := now.Truncate(time.Minute)
	q := &config.Quota{Name: "q", RowsPerHour: 5, RowsPerDay: 100, QueriesPerHour: 10}
	at := func(ago time.Duration, queries, rows int64) store.QuotaUsage {
		return store.QuotaUsage{Quota: "q", Bucket: min0.Add(-ago), Queries: queries, Rows: rows}
	}
	usage := []store.QuotaUsage{
		at(3*time.Hour, 1, 90),    // outside the hour, inside the day
		at(60*time.Minute, 1, 50), // just outside the hour
		at(50*time.Minute, 1, 3),
		at(20*time.Minute, 1, 3),
		at(0, 1, 1),
	}
	qc := evaluateQuotas([]*config.Quota{q}, usage, now)
	// rows_per_hour (7 of 5) frees up in 10 minutes, rows_per_day (147 of
	// 100) when the 90 rows of 3 hours ago leave the day window. The one
	// that frees up last is reported.
	ex := qc.exceeded
	if ex == nil || ex.limit.Key != "rows_per_day" || ex.used != 147 || !ex.freeAt.Equal(min0.Add(21*time.Hour)) {
		t.Fatalf("exceeded = %+v", ex)
	}
	// Without the day limit: rows_per_hour 7 of 5 frees up when the bucket
	// of 50 minutes ago leaves, 10 minutes from now.
	q.RowsPerDay = 0
	qc = evaluateQuotas([]*config.Quota{q}, usage, now)
	if ex := qc.exceeded; ex == nil || ex.limit.Key != "rows_per_hour" || ex.used != 7 || !ex.freeAt.Equal(min0.Add(10*time.Minute)) {
		t.Fatalf("exceeded = %+v", qc.exceeded)
	}
	// Under the limit: the remaining rows are reported.
	q.RowsPerHour = 10
	qc = evaluateQuotas([]*config.Quota{q}, usage, now)
	if qc.exceeded != nil || qc.rowsLeft != 3 || qc.rowsQuota != q || qc.rowsLimit.Key != "rows_per_hour" {
		t.Fatalf("check = %+v", qc)
	}
	// No row limit: unlimited.
	qc = evaluateQuotas([]*config.Quota{{Name: "q", QueriesPerHour: 10}}, usage, now)
	if qc.exceeded != nil || qc.rowsLeft != -1 {
		t.Fatalf("check = %+v", qc)
	}
}

func TestUntilText(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0: "1s", 400 * time.Millisecond: "1s", 45 * time.Second: "45s", time.Minute: "1m", 61 * time.Second: "2m",
		59*time.Minute + 30*time.Second: "1h00m", 3*time.Hour + 5*time.Minute: "3h05m", 23 * time.Hour: "23h00m",
	} {
		if got := untilText(d); got != want {
			t.Errorf("untilText(%v) = %q, want %q", d, got, want)
		}
	}
}
