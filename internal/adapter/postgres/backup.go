package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	pg "github.com/pganalyze/pg_query_go/v6"

	"github.com/kyosu-1/dbgateway/internal/analysis"
)

// errBackupUnsupported wraps the reasons a statement cannot be backed up.
var errBackupUnsupported = errors.New("cannot be backed up")

func unsupported(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errBackupUnsupported, fmt.Sprintf(format, args...))
}

// PlanBackup returns how to save the rows an UPDATE or DELETE will change.
// Only the plain forms are supported — one base table, a WHERE clause, no
// WITH, FROM (UPDATE) or USING (DELETE) — because only then does
// "SELECT target.* FROM target WHERE <same condition>" select exactly the
// rows the statement changes (the executor verifies the counts match).
func (a *Analyzer) PlanBackup(sql string, cat *analysis.Catalog) (*analysis.BackupPlan, error) {
	tree, err := pg.Parse(sql)
	if err != nil || len(tree.Stmts) != 1 || tree.Stmts[0].Stmt == nil {
		return nil, unsupported("the statement could not be parsed")
	}
	plan := &analysis.BackupPlan{}
	var rel *pg.RangeVar
	var where *pg.Node
	switch n := tree.Stmts[0].Stmt.Node.(type) {
	case *pg.Node_UpdateStmt:
		u := n.UpdateStmt
		switch {
		case u.WithClause != nil:
			return nil, unsupported("UPDATE with a WITH clause")
		case len(u.FromClause) > 0:
			return nil, unsupported("UPDATE ... FROM")
		}
		plan.Kind, rel, where = analysis.KindUpdate, u.Relation, u.WhereClause
		for _, t := range u.TargetList {
			rt := t.GetResTarget()
			if rt == nil || rt.Name == "" {
				return nil, unsupported("an unrecognized SET target")
			}
			if !slices.Contains(plan.SetColumns, rt.Name) {
				plan.SetColumns = append(plan.SetColumns, rt.Name)
			}
		}
	case *pg.Node_DeleteStmt:
		d := n.DeleteStmt
		switch {
		case d.WithClause != nil:
			return nil, unsupported("DELETE with a WITH clause")
		case len(d.UsingClause) > 0:
			return nil, unsupported("DELETE ... USING")
		}
		plan.Kind, rel, where = analysis.KindDelete, d.Relation, d.WhereClause
	default:
		return nil, unsupported("only UPDATE and DELETE are backed up")
	}
	if rel == nil {
		return nil, unsupported("no target table")
	}
	if where.GetCurrentOfExpr() != nil {
		return nil, unsupported("WHERE CURRENT OF")
	}
	r := cat.Lookup(rel.Schemaname, rel.Relname)
	if r == nil {
		return nil, unsupported("the target table is not in the catalog")
	}
	if r.Kind != analysis.RelTable && r.Kind != analysis.RelPartitioned {
		return nil, unsupported("the target is a %s, not a table", strings.ReplaceAll(string(r.Kind), "_", " "))
	}
	plan.Target = analysis.TableRef{Schema: r.Schema, Name: r.Name, Write: true}

	// SELECT <ref>.* FROM <relation as written> WHERE <condition>: the
	// relation keeps its ONLY flag and alias, so the condition resolves
	// exactly as it does in the statement.
	ref := rel.Relname
	if rel.Alias != nil && rel.Alias.Aliasname != "" {
		ref = rel.Alias.Aliasname
	}
	sel := &pg.SelectStmt{
		TargetList: []*pg.Node{pg.MakeResTargetNodeWithVal(
			pg.MakeColumnRefNode([]*pg.Node{pg.MakeStrNode(ref), pg.MakeAStarNode()}, -1), -1)},
		FromClause:  []*pg.Node{{Node: &pg.Node_RangeVar{RangeVar: rel}}},
		WhereClause: where,
		LimitOption: pg.LimitOption_LIMIT_OPTION_DEFAULT,
		Op:          pg.SetOperation_SETOP_NONE,
	}
	out, err := pg.Deparse(&pg.ParseResult{Version: tree.Version, Stmts: []*pg.RawStmt{{Stmt: &pg.Node{Node: &pg.Node_SelectStmt{SelectStmt: sel}}}}})
	if err != nil {
		return nil, unsupported("the backup query could not be built")
	}
	plan.Select = out
	return plan, nil
}

// takeBackup creates the backup table from the plan inside tx and returns
// the number of rows saved.
func takeBackup(ctx context.Context, tx pgx.Tx, b *analysis.BackupSpec) (int64, error) {
	tbl := pgx.Identifier{b.Schema, b.Table}.Sanitize()
	tag, err := tx.Exec(ctx, "CREATE TABLE "+tbl+" AS "+b.Plan.Select)
	if err != nil {
		return 0, &analysis.BackupError{Reason: "could not create the backup table: " + sanitizeError(err)}
	}
	if b.Comment != "" {
		if _, err := tx.Exec(ctx, "COMMENT ON TABLE "+tbl+" IS "+quoteLiteral(b.Comment)); err != nil {
			return 0, &analysis.BackupError{Reason: "could not comment the backup table: " + sanitizeError(err)}
		}
	}
	return tag.RowsAffected(), nil
}

// restoreSQL builds the statement that undoes the change from the backup
// table: DELETE → re-insert the saved rows; UPDATE → set the assigned
// columns back, matching rows by primary key.
func restoreSQL(ctx context.Context, tx pgx.Tx, b *analysis.BackupSpec) (string, string, error) {
	target := pgx.Identifier{b.Plan.Target.Schema, b.Plan.Target.Name}.Sanitize()
	backup := pgx.Identifier{b.Schema, b.Table}.Sanitize()
	cols, err := tableColumns(ctx, tx, target)
	if err != nil {
		return "", "", err
	}
	switch b.Plan.Kind {
	case analysis.KindDelete:
		var names []string
		identity := false
		for _, c := range cols {
			if c.generated {
				continue
			}
			names = append(names, pgx.Identifier{c.name}.Sanitize())
			identity = identity || c.identityAlways
		}
		if len(names) == 0 {
			return "", "The table has no columns that can be inserted.", nil
		}
		list := strings.Join(names, ", ")
		overriding := ""
		if identity {
			overriding = " OVERRIDING SYSTEM VALUE"
		}
		return fmt.Sprintf("INSERT INTO %s (%s)%s SELECT %s FROM %s", target, list, overriding, list, backup), "", nil
	case analysis.KindUpdate:
		var pk []string
		for _, c := range cols {
			if c.pkPos > 0 {
				pk = append(pk, c.name)
			}
		}
		slices.SortFunc(pk, func(x, y string) int { return pkPos(cols, x) - pkPos(cols, y) })
		if len(pk) == 0 {
			return "", "The table has no primary key, so the changed rows cannot be matched for a restore.", nil
		}
		for _, c := range b.Plan.SetColumns {
			if slices.Contains(pk, c) {
				return "", "The statement changed the primary key, so the changed rows cannot be matched for a restore.", nil
			}
		}
		sets := make([]string, 0, len(b.Plan.SetColumns))
		for _, c := range b.Plan.SetColumns {
			id := pgx.Identifier{c}.Sanitize()
			sets = append(sets, fmt.Sprintf("%s = b.%s", id, id))
		}
		conds := make([]string, 0, len(pk))
		for _, c := range pk {
			id := pgx.Identifier{c}.Sanitize()
			conds = append(conds, fmt.Sprintf("t.%s = b.%s", id, id))
		}
		return fmt.Sprintf("UPDATE %s AS t SET %s FROM %s AS b WHERE %s", target, strings.Join(sets, ", "), backup,
			strings.Join(conds, " AND ")), "", nil
	}
	return "", "Restore is not supported for this statement.", nil
}

type tableColumn struct {
	name           string
	generated      bool
	identityAlways bool
	pkPos          int // 1-based position in the primary key; 0 if not part of it
}

func pkPos(cols []tableColumn, name string) int {
	for _, c := range cols {
		if c.name == name {
			return c.pkPos
		}
	}
	return 0
}

func tableColumns(ctx context.Context, tx pgx.Tx, target string) ([]tableColumn, error) {
	rows, err := tx.Query(ctx, `
SELECT a.attname, a.attgenerated <> '', a.attidentity = 'a',
       coalesce(array_position(i.indkey::int2[], a.attnum) - array_lower(i.indkey::int2[], 1) + 1, 0)
FROM pg_attribute a
LEFT JOIN pg_index i ON i.indrelid = a.attrelid AND i.indisprimary
WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY a.attnum`, target)
	if err != nil {
		return nil, &analysis.BackupError{Reason: "could not read the table definition: " + sanitizeError(err)}
	}
	cols, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (tableColumn, error) {
		var c tableColumn
		var pos int32
		err := r.Scan(&c.name, &c.generated, &c.identityAlways, &pos)
		c.pkPos = int(pos)
		return c, err
	})
	if err != nil {
		return nil, &analysis.BackupError{Reason: "could not read the table definition: " + sanitizeError(err)}
	}
	return cols, nil
}

// quoteLiteral quotes s as a standard-conforming string literal.
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// sanitizeError keeps only the message of a database error.
func sanitizeError(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, " (SQLSTATE"); i >= 0 {
		msg = msg[:i]
	}
	return msg
}
