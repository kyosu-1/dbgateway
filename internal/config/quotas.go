package config

import (
	"fmt"
	"strings"
	"time"
)

// Quota limits how much one requester may read over time. Every quota
// whose condition matches an allowed read applies, and is counted
// separately for each requester (the person; an agent counts against the
// person it acts for).
//
//	quotas:
//	  - name: agents-prod
//	    when: principal.kind == "agent" && database.labels.env == "prod"
//	    queries_per_minute: 30
//	    rows_per_hour: 20000
//	    rows_per_day: 100000
type Quota struct {
	Name string `yaml:"name"`
	// When is an optional CEL condition over principal, database, stmt and
	// columns (the policy variables, without estimate and risk). Empty
	// means every read. A condition that fails to evaluate matches.
	When string `yaml:"when"`

	QueriesPerMinute int64 `yaml:"queries_per_minute"`
	QueriesPerHour   int64 `yaml:"queries_per_hour"`
	RowsPerHour      int64 `yaml:"rows_per_hour"`
	RowsPerDay       int64 `yaml:"rows_per_day"`

	// Hint is added to the hint of a denial (e.g. whom to ask for more).
	Hint string `yaml:"hint"`
}

// QuotaLimit is one limit of a quota.
type QuotaLimit struct {
	// Key is the configuration key, e.g. "rows_per_hour".
	Key string
	// Rows is true for a row limit, false for a query limit.
	Rows   bool
	Window time.Duration
	Max    int64
}

// Quota windows.
const (
	QuotaMinute = time.Minute
	QuotaHour   = time.Hour
	QuotaDay    = 24 * time.Hour
)

// Limits returns the configured (non-zero) limits.
func (q *Quota) Limits() []QuotaLimit {
	all := []QuotaLimit{
		{Key: "queries_per_minute", Window: QuotaMinute, Max: q.QueriesPerMinute},
		{Key: "queries_per_hour", Window: QuotaHour, Max: q.QueriesPerHour},
		{Key: "rows_per_hour", Rows: true, Window: QuotaHour, Max: q.RowsPerHour},
		{Key: "rows_per_day", Rows: true, Window: QuotaDay, Max: q.RowsPerDay},
	}
	out := all[:0]
	for _, l := range all {
		if l.Max > 0 {
			out = append(out, l)
		}
	}
	return out
}

// Window returns the longest window of the quota's limits: how long its
// usage must be kept.
func (q *Quota) Window() time.Duration {
	var w time.Duration
	for _, l := range q.Limits() {
		w = max(w, l.Window)
	}
	return w
}

func (c *Config) validateQuotas(add func(string, ...any)) {
	names := map[string]bool{}
	for i, q := range c.Quotas {
		p := fmt.Sprintf("quotas[%d]", i)
		switch {
		case strings.TrimSpace(q.Name) == "":
			add("%s.name: required", p)
		case names[q.Name]:
			add("%s.name: duplicate %q", p, q.Name)
		}
		names[q.Name] = true
		if q.QueriesPerMinute < 0 || q.QueriesPerHour < 0 || q.RowsPerHour < 0 || q.RowsPerDay < 0 {
			add("%s: limits must be positive", p)
		} else if len(q.Limits()) == 0 {
			add("%s: set at least one of queries_per_minute, queries_per_hour, rows_per_hour, rows_per_day", p)
		}
		// The condition is compiled by the policy package (see
		// policy.Compile).
	}
}
