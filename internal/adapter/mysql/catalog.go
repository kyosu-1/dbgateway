package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/kyosu-1/dbgateway/internal/analysis"
)

// INVISIBLE columns (including generated invisible primary keys) are left
// out: "SELECT *" does not return them, so including them would misalign
// star expansion with the result. Naming one explicitly is then
// unresolvable, i.e. unknown.
const catalogColumnsSQL = `
SELECT c.TABLE_SCHEMA, c.TABLE_NAME, t.TABLE_TYPE, c.COLUMN_NAME, c.COLUMN_TYPE,
       c.IS_NULLABLE = 'YES', c.COLUMN_COMMENT
FROM information_schema.COLUMNS c
JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = c.TABLE_SCHEMA AND t.TABLE_NAME = c.TABLE_NAME
WHERE c.EXTRA NOT LIKE '%INVISIBLE%'
ORDER BY c.TABLE_SCHEMA, c.TABLE_NAME, c.ORDINAL_POSITION`

// View definitions are only expanded for user schemas; system views are
// treated as base relations. VIEW_DEFINITION is empty unless the user has
// SHOW VIEW on the view, in which case the resolver marks it unknown.
const catalogViewsSQL = `
SELECT TABLE_SCHEMA, TABLE_NAME, VIEW_DEFINITION
FROM information_schema.VIEWS
WHERE TABLE_SCHEMA NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')`

func relKind(tableType string) analysis.RelKind {
	switch tableType {
	case "VIEW", "SYSTEM VIEW":
		return analysis.RelView
	default: // BASE TABLE
		return analysis.RelTable
	}
}

// addRelations adds relations to cat. analysis.Catalog keys relations by
// lower-cased name, while MySQL table and database names are case-sensitive
// on most platforms (lower_case_table_names=0), so "Users" and "users" can
// both exist. Such case-colliding relations are left out entirely: any
// reference to them is then unknown instead of being resolved to the wrong
// table.
func addRelations(cat *analysis.Catalog, rels []*analysis.Relation) {
	groups := map[string][]*analysis.Relation{}
	var keys []string
	for _, r := range rels {
		k := strings.ToLower(r.Schema + "." + r.Name)
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], r)
	}
	for _, k := range keys {
		g := groups[k]
		collides := slices.ContainsFunc(g[1:], func(r *analysis.Relation) bool {
			return r.Schema != g[0].Schema || r.Name != g[0].Name
		})
		if collides {
			delete(cat.Relations, k)
			continue
		}
		cat.Add(g[0])
	}
}

// Catalog loads relations and columns. The search path is the configured
// database: MySQL resolves unqualified names against the default database
// only.
func (a *Adapter) Catalog(ctx context.Context, ac analysis.Conn) (*analysis.Catalog, error) {
	c := ac.(*conn)
	cat := analysis.NewCatalog([]string{c.schema}, nil)
	err := c.withReadTx(ctx, analysis.ExecOptions{ReadOnly: true}, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, catalogColumnsSQL)
		if err != nil {
			return err
		}
		var rels []*analysis.Relation
		var cur *analysis.Relation
		for rows.Next() {
			var schema, name, typ, col, colType, comment string
			var nullable bool
			if err := rows.Scan(&schema, &name, &typ, &col, &colType, &nullable, &comment); err != nil {
				rows.Close()
				return err
			}
			if cur == nil || cur.Schema != schema || cur.Name != name {
				cur = &analysis.Relation{Schema: schema, Name: name, Kind: relKind(typ)}
				rels = append(rels, cur)
			}
			cur.Columns = append(cur.Columns, analysis.Column{Name: col, Type: colType, Nullable: nullable, Comment: comment})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		addRelations(cat, rels)

		rows, err = tx.QueryContext(ctx, catalogViewsSQL)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var schema, name string
			var def sql.NullString
			if err := rows.Scan(&schema, &name, &def); err != nil {
				return err
			}
			if rel := cat.Lookup(schema, name); rel != nil && rel.Schema == schema && rel.Name == name {
				rel.Definition = strings.TrimSuffix(strings.TrimSpace(def.String), ";")
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
SELECT TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, NON_UNIQUE, COLUMN_NAME, EXPRESSION, SEQ_IN_INDEX, INDEX_TYPE
FROM information_schema.STATISTICS
WHERE (TABLE_SCHEMA, TABLE_NAME) IN (%s)
ORDER BY TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX`

const relStatsSQL = `
SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_ROWS, TABLE_COMMENT
FROM information_schema.TABLES
WHERE (TABLE_SCHEMA, TABLE_NAME) IN (%s)`

// Introspect lists relations matching the filter. Table and column lists
// come from the catalog; indexes and statistics are fetched for "full".
// MySQL system schemas are hidden unless asked for explicitly.
func (a *Adapter) Introspect(ctx context.Context, ac analysis.Conn, f analysis.ObjectFilter) ([]analysis.Object, error) {
	cat, err := a.Catalog(ctx, ac)
	if err != nil {
		return nil, err
	}
	if f.Schema == "" {
		visible := analysis.NewCatalog(cat.SearchPath, cat.ImplicitSchemas)
		for k, r := range cat.Relations {
			if !isSystemSchema(r.Schema) {
				visible.Relations[k] = r
			}
		}
		cat = visible
	}
	objs := analysis.FilterObjects(cat, f)
	if f.Detail != "full" || len(objs) == 0 {
		return objs, nil
	}
	c := ac.(*conn)
	idx := map[string]int{}
	placeholders := make([]string, 0, len(objs))
	args := make([]any, 0, 2*len(objs))
	for i, o := range objs {
		idx[o.Schema+"."+o.Name] = i
		placeholders = append(placeholders, "(?, ?)")
		args = append(args, o.Schema, o.Name)
	}
	in := strings.Join(placeholders, ", ")
	err = c.withReadTx(ctx, analysis.ExecOptions{ReadOnly: true}, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, fmt.Sprintf(indexesSQL, in), args...)
		if err != nil {
			return err
		}
		type index struct {
			schema, table, name string
			unique              bool
			parts               []string
			typ                 string
		}
		var indexes []*index
		for rows.Next() {
			var s, t, name, typ string
			var nonUnique int
			var column, expr sql.NullString
			var seq int
			if err := rows.Scan(&s, &t, &name, &nonUnique, &column, &expr, &seq, &typ); err != nil {
				rows.Close()
				return err
			}
			if n := len(indexes); n == 0 || indexes[n-1].schema != s || indexes[n-1].table != t || indexes[n-1].name != name {
				indexes = append(indexes, &index{schema: s, table: t, name: name, unique: nonUnique == 0, typ: typ})
			}
			part := quoteIdent(column.String)
			if !column.Valid {
				part = "(" + expr.String + ")"
			}
			cur := indexes[len(indexes)-1]
			cur.parts = append(cur.parts, part)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, ix := range indexes {
			i, ok := idx[ix.schema+"."+ix.table]
			if !ok {
				continue
			}
			var def string
			switch {
			case ix.name == "PRIMARY":
				def = "PRIMARY KEY"
			case ix.typ == "FULLTEXT" || ix.typ == "SPATIAL":
				def = ix.typ + " INDEX " + quoteIdent(ix.name)
			case ix.unique:
				def = "UNIQUE INDEX " + quoteIdent(ix.name)
			default:
				def = "INDEX " + quoteIdent(ix.name)
			}
			def += " (" + strings.Join(ix.parts, ", ") + ")"
			if ix.typ != "BTREE" && ix.typ != "FULLTEXT" && ix.typ != "SPATIAL" {
				def += " USING " + ix.typ
			}
			objs[i].Indexes = append(objs[i].Indexes, analysis.ObjectIndex{Name: ix.name, Definition: def})
		}

		rows, err = tx.QueryContext(ctx, fmt.Sprintf(relStatsSQL, in), args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s, t string
			var tuples sql.NullInt64
			var comment sql.NullString
			if err := rows.Scan(&s, &t, &tuples, &comment); err != nil {
				return err
			}
			if i, ok := idx[s+"."+t]; ok {
				if tuples.Valid && tuples.Int64 >= 0 {
					n := tuples.Int64
					objs[i].RowEstimate = &n
				}
				if objs[i].Type == string(analysis.RelTable) {
					objs[i].Comment = comment.String
				}
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return objs, nil
}

// quoteIdent quotes a MySQL identifier with backquotes.
func quoteIdent(s string) string {
	return "`" + strings.ReplaceAll(s, "`", "``") + "`"
}
