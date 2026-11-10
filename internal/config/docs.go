package config

import (
	"fmt"
	"slices"
	"strings"
)

// DatabaseDocs is human-curated knowledge about a database's schema: what
// the database is for, what tables and columns mean, and example queries
// that are known to be right. It is shown to agents and people with search
// access (list_databases, search_objects) so that they write correct SQL on
// the first try. It is configuration text: it never contains or reveals
// data values, and it does not change classification or masking.
//
//	docs:
//	  description: Core OLTP database of the shop. Amounts are in JPY.
//	  tables:
//	    public.orders:
//	      description: One row per checkout. status is pending, paid or refunded.
//	      columns:
//	        total_amount: Total in JPY, tax included.
//	  examples:
//	    - title: Daily revenue
//	      sql: SELECT date_trunc('day', paid_at) AS day, sum(total_amount) FROM orders WHERE status = 'paid' GROUP BY 1
type DatabaseDocs struct {
	Description string `yaml:"description"`
	// Tables maps "schema.table" (for MySQL "database.table") to its docs.
	Tables   map[string]TableDocs `yaml:"tables"`
	Examples []ExampleQuery       `yaml:"examples"`
}

// TableDocs documents a table, view or other relation.
type TableDocs struct {
	Description string `yaml:"description"`
	// Columns maps a column name to its description.
	Columns map[string]string `yaml:"columns"`
}

// ExampleQuery is a query known to answer a common question correctly.
type ExampleQuery struct {
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	SQL         string `yaml:"sql"`
}

func (d *DatabaseDocs) validate(p string, add func(string, ...any)) {
	tables := map[string]string{}
	for _, k := range sortedKeys(d.Tables) {
		t := d.Tables[k]
		tp := p + ".tables." + k
		schema, name, ok := strings.Cut(k, ".")
		if !ok || schema == "" || name == "" || strings.Contains(name, ".") {
			add("%s: the key must be schema.table (for MySQL, database.table)", tp)
		}
		if prev, dup := tables[strings.ToLower(k)]; dup {
			add("%s: duplicate of %q (names are case-insensitive)", tp, prev)
		}
		tables[strings.ToLower(k)] = k
		if strings.TrimSpace(t.Description) == "" && len(t.Columns) == 0 {
			add("%s: description or columns is required", tp)
		}
		cols := map[string]string{}
		for _, c := range sortedKeys(t.Columns) {
			cp := tp + ".columns." + c
			if c == "" || strings.Contains(c, ".") {
				add("%s: must be a column name (without schema or table)", cp)
			}
			if prev, dup := cols[strings.ToLower(c)]; dup {
				add("%s: duplicate of %q (names are case-insensitive)", cp, prev)
			}
			cols[strings.ToLower(c)] = c
			if strings.TrimSpace(t.Columns[c]) == "" {
				add("%s: description is required", cp)
			}
		}
	}
	titles := map[string]bool{}
	for i, ex := range d.Examples {
		ep := fmt.Sprintf("%s.examples[%d]", p, i)
		title := strings.TrimSpace(ex.Title)
		switch {
		case title == "":
			add("%s.title: required", ep)
		case titles[strings.ToLower(title)]:
			add("%s.title: duplicate %q", ep, title)
		}
		titles[strings.ToLower(title)] = true
		if strings.TrimSpace(ex.SQL) == "" {
			add("%s.sql: required", ep)
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
