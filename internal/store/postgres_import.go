package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// pgImportOrder lists the tables in an order that satisfies the foreign
// keys. Tables of later migrations that are not listed are copied after
// these, in name order.
var pgImportOrder = []string{
	"users", "sessions", "oauth_clients", "auth_codes", "device_codes", "tokens",
	"approval_requests", "break_glass_grants",
	"scim_users", "scim_groups", "scim_group_members",
}

// ImportSQLite copies every row of the SQLite management database into
// dst, which must be empty (freshly migrated), in one transaction. Both
// databases must be at the same migration version (opening them migrates
// both to this binary's version). Columns are converted by their
// PostgreSQL type: unix milliseconds to timestamptz, JSON text to jsonb
// (an empty string to NULL) and integers to boolean. It returns the number
// of rows copied per table.
//
// dbgateway must not run against src during the import.
func ImportSQLite(ctx context.Context, src *SQLite, dst *Postgres) (map[string]int64, error) {
	counts := map[string]int64{}
	err := dst.inTx(ctx, func(tx pgx.Tx) error {
		tables, err := pgImportTables(ctx, tx)
		if err != nil {
			return err
		}
		for _, table := range tables {
			var nonEmpty bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+pgx.Identifier{table}.Sanitize()+`)`).Scan(&nonEmpty); err != nil {
				return err
			}
			if nonEmpty {
				return fmt.Errorf("store: import: table %s of the PostgreSQL database is not empty", table)
			}
		}
		for _, table := range tables {
			n, err := pgImportTable(ctx, src, tx, table)
			if err != nil {
				return fmt.Errorf("store: import %s: %w", table, err)
			}
			counts[table] = n
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return counts, nil
}

// pgImportTables returns the management tables of the PostgreSQL schema
// in import order.
func pgImportTables(ctx context.Context, q pgQuerier) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = current_schema()
		AND tablename <> 'schema_migrations' AND tablename NOT LIKE 'audit\_%' ORDER BY tablename`)
	if err != nil {
		return nil, err
	}
	all, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	var out []string
	for _, t := range pgImportOrder {
		if slices.Contains(all, t) {
			out = append(out, t)
		}
	}
	for _, t := range all {
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out, nil
}

type pgColumn struct {
	name, typ string
}

func pgImportTable(ctx context.Context, src *SQLite, tx pgx.Tx, table string) (int64, error) {
	rows, err := tx.Query(ctx, `SELECT column_name, data_type FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = $1 ORDER BY ordinal_position`, table)
	if err != nil {
		return 0, err
	}
	cols, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pgColumn, error) {
		var c pgColumn
		err := r.Scan(&c.name, &c.typ)
		return c, err
	})
	if err != nil {
		return 0, err
	}
	names := make([]string, len(cols))
	quoted := make([]string, len(cols))
	for i, c := range cols {
		names[i] = c.name
		quoted[i] = `"` + c.name + `"` // names come from the PostgreSQL catalog
	}
	srcRows, err := src.db.QueryContext(ctx, `SELECT `+strings.Join(quoted, ", ")+` FROM "`+table+`"`)
	if err != nil {
		return 0, fmt.Errorf("read SQLite: %w", err)
	}
	defer srcRows.Close()
	var data [][]any
	for srcRows.Next() {
		raw := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := srcRows.Scan(ptrs...); err != nil {
			return 0, err
		}
		row := make([]any, len(cols))
		for i, c := range cols {
			if row[i], err = pgImportValue(c, raw[i]); err != nil {
				return 0, err
			}
		}
		data = append(data, row)
	}
	if err := srcRows.Err(); err != nil {
		return 0, err
	}
	return tx.CopyFrom(ctx, pgx.Identifier{table}, names, pgx.CopyFromRows(data))
}

// pgImportValue converts a SQLite value to the PostgreSQL column's type.
func pgImportValue(c pgColumn, v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	if b, ok := v.([]byte); ok {
		v = string(b)
	}
	bad := func() (any, error) {
		return nil, fmt.Errorf("column %s: cannot convert %T to %s", c.name, v, c.typ)
	}
	switch c.typ {
	case "timestamp with time zone":
		ms, ok := v.(int64)
		if !ok {
			return bad()
		}
		return time.UnixMilli(ms).UTC(), nil
	case "jsonb":
		s, ok := v.(string)
		if !ok {
			return bad()
		}
		if s == "" {
			return nil, nil
		}
		return s, nil
	case "boolean":
		n, ok := v.(int64)
		if !ok {
			return bad()
		}
		return n != 0, nil
	case "double precision":
		switch n := v.(type) {
		case float64:
			return n, nil
		case int64:
			return float64(n), nil
		}
		return bad()
	case "bigint", "integer":
		if _, ok := v.(int64); !ok {
			return bad()
		}
		return v, nil
	case "text":
		if _, ok := v.(string); !ok {
			return bad()
		}
		return v, nil
	}
	return nil, errors.New("column " + c.name + ": unsupported PostgreSQL type " + c.typ)
}
