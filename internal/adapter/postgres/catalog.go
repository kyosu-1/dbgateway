package postgres

import (
	"context"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/kyosu-1/dbgateway/internal/analysis"
)

const catalogColumnsSQL = `
SELECT n.nspname, c.relname, c.relkind::text, a.attname,
       format_type(a.atttypid, a.atttypmod), NOT a.attnotnull,
       coalesce(col_description(c.oid, a.attnum), '')
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
WHERE c.relkind IN ('r', 'v', 'm', 'f', 'p')
  AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%'
ORDER BY n.nspname, c.relname, a.attnum`

// View definitions are only expanded for user schemas; system views are
// treated as base relations.
const catalogViewsSQL = `
SELECT n.nspname, c.relname, pg_catalog.pg_get_viewdef(c.oid)
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('v', 'm')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%'`

var relKinds = map[string]analysis.RelKind{
	"r": analysis.RelTable, "p": analysis.RelPartitioned, "v": analysis.RelView,
	"m": analysis.RelMatView, "f": analysis.RelForeign,
}

// SystemSchemas are hidden from exploration unless asked for explicitly.
var SystemSchemas = []string{"pg_catalog", "information_schema"}

// Catalog loads relations and columns using the configured search path, so
// view definitions are rendered relative to the same path used at
// execution time.
func (a *Adapter) Catalog(ctx context.Context, ac analysis.Conn) (*analysis.Catalog, error) {
	c := ac.(*conn)
	cat := analysis.NewCatalog(c.cfg.SearchPath, []string{"pg_catalog"})
	err := c.withReadTx(ctx, analysis.ExecOptions{ReadOnly: true}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, catalogColumnsSQL)
		if err != nil {
			return err
		}
		var cur *analysis.Relation
		for rows.Next() {
			var schema, name, kind, col, typ, comment string
			var nullable bool
			if err := rows.Scan(&schema, &name, &kind, &col, &typ, &nullable, &comment); err != nil {
				rows.Close()
				return err
			}
			if cur == nil || cur.Schema != schema || cur.Name != name {
				cur = &analysis.Relation{Schema: schema, Name: name, Kind: relKinds[kind]}
				cat.Add(cur)
			}
			cur.Columns = append(cur.Columns, analysis.Column{Name: col, Type: typ, Nullable: nullable, Comment: comment})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		rows, err = tx.Query(ctx, catalogViewsSQL)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var schema, name, def string
			if err := rows.Scan(&schema, &name, &def); err != nil {
				return err
			}
			if rel := cat.Lookup(schema, name); rel != nil {
				rel.Definition = strings.TrimSuffix(strings.TrimSpace(def), ";")
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return cat, nil
}

const indexesSQL = `
SELECT n.nspname, t.relname, i.relname, pg_catalog.pg_get_indexdef(i.oid)
FROM pg_catalog.pg_index x
JOIN pg_catalog.pg_class i ON i.oid = x.indexrelid
JOIN pg_catalog.pg_class t ON t.oid = x.indrelid
JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
WHERE n.nspname = ANY($1) AND t.relname = ANY($2)`

const relStatsSQL = `
SELECT n.nspname, c.relname, c.reltuples::bigint, coalesce(obj_description(c.oid, 'pg_class'), '')
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = ANY($1) AND c.relname = ANY($2)`

// Introspect lists relations matching the filter. Table and column lists
// come from the catalog; indexes and statistics are fetched for "full".
func (a *Adapter) Introspect(ctx context.Context, ac analysis.Conn, f analysis.ObjectFilter) ([]analysis.Object, error) {
	cat, err := a.Catalog(ctx, ac)
	if err != nil {
		return nil, err
	}
	objs := FilterObjects(cat, f)
	if f.Detail != "full" || len(objs) == 0 {
		return objs, nil
	}
	c := ac.(*conn)
	var schemas, names []string
	for _, o := range objs {
		schemas = append(schemas, o.Schema)
		names = append(names, o.Name)
	}
	idx := map[string]int{}
	for i, o := range objs {
		idx[o.Schema+"."+o.Name] = i
	}
	err = c.withReadTx(ctx, analysis.ExecOptions{ReadOnly: true}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, indexesSQL, schemas, names)
		if err != nil {
			return err
		}
		for rows.Next() {
			var s, t, n, def string
			if err := rows.Scan(&s, &t, &n, &def); err != nil {
				rows.Close()
				return err
			}
			if i, ok := idx[s+"."+t]; ok {
				objs[i].Indexes = append(objs[i].Indexes, analysis.ObjectIndex{Name: n, Definition: def})
			}
		}
		rows.Close()
		rows, err = tx.Query(ctx, relStatsSQL, schemas, names)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s, t, comment string
			var tuples int64
			if err := rows.Scan(&s, &t, &tuples, &comment); err != nil {
				return err
			}
			if i, ok := idx[s+"."+t]; ok {
				if tuples >= 0 {
					objs[i].RowEstimate = &tuples
				}
				objs[i].Comment = comment
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return objs, nil
}

// FilterObjects selects catalog relations by keyword (matching schema,
// relation or column names, case-insensitively) and schema. System schemas
// are excluded unless requested explicitly.
func FilterObjects(cat *analysis.Catalog, f analysis.ObjectFilter) []analysis.Object {
	kw := strings.ToLower(strings.TrimSpace(f.Keyword))
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	keys := make([]string, 0, len(cat.Relations))
	for k := range cat.Relations {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var out []analysis.Object
	for _, k := range keys {
		rel := cat.Relations[k]
		if f.Schema != "" {
			if !strings.EqualFold(rel.Schema, f.Schema) {
				continue
			}
		} else if slices.Contains(SystemSchemas, rel.Schema) {
			continue
		}
		relMatch := kw == "" || strings.Contains(strings.ToLower(rel.Schema+"."+rel.Name), kw)
		var cols []analysis.ObjectColumn
		colMatch := false
		for _, c := range rel.Columns {
			if kw != "" && strings.Contains(strings.ToLower(c.Name), kw) {
				colMatch = true
			}
			oc := analysis.ObjectColumn{Name: c.Name, Type: c.Type}
			if f.Detail == "full" {
				oc.Nullable = c.Nullable
				oc.Comment = c.Comment
			}
			cols = append(cols, oc)
		}
		if !relMatch && !colMatch {
			continue
		}
		o := analysis.Object{Type: string(rel.Kind), Schema: rel.Schema, Name: rel.Name}
		if f.Detail != "names" {
			o.Columns = cols
		}
		out = append(out, o)
		if len(out) >= limit {
			break
		}
	}
	return out
}
