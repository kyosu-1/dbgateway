package config

import "time"

// Console configures the web SQL editor (/console), the way people run
// SQL. Every statement goes through the same gateway as agents' queries;
// these settings only cover what the editor keeps and lets people take
// away.
//
//	console:
//	  history: true              # keep each person's executed SQL (default true)
//	  history_retention: 720h    # how long (default 30 days)
//	  export: true               # allow CSV/JSON export (default true)
//	  export_max_rows: 10000     # rows per export (default 10,000)
type Console struct {
	History          *bool    `yaml:"history"`
	HistoryRetention Duration `yaml:"history_retention"`
	Export           *bool    `yaml:"export"`
	ExportMaxRows    int      `yaml:"export_max_rows"`
}

const (
	defaultHistoryRetention = 30 * 24 * time.Hour
	defaultExportMaxRows    = 10_000
	maxExportMaxRows        = 1_000_000
)

// HistoryEnabled reports whether executed statements are kept in the
// person's history. The history holds the SQL as typed (with literals), so
// it is visible only to that person and removed after HistoryTTL.
func (c Console) HistoryEnabled() bool { return c.History == nil || *c.History }

// HistoryTTL is how long history entries are kept.
func (c Console) HistoryTTL() time.Duration {
	if c.HistoryRetention > 0 {
		return c.HistoryRetention.D()
	}
	return defaultHistoryRetention
}

// ExportEnabled reports whether results may be exported.
func (c Console) ExportEnabled() bool { return c.Export == nil || *c.Export }

// ExportRows is the row limit of one export.
func (c Console) ExportRows() int {
	if c.ExportMaxRows > 0 {
		return c.ExportMaxRows
	}
	return defaultExportMaxRows
}

func (c Console) validate(add func(string, ...any)) {
	if c.HistoryRetention < 0 {
		add("console.history_retention: must not be negative")
	}
	if c.ExportMaxRows < 0 || c.ExportMaxRows > maxExportMaxRows {
		add("console.export_max_rows: must be between 1 and %d", maxExportMaxRows)
	}
}
