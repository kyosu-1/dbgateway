package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	pg "github.com/pganalyze/pg_query_go/v6"

	"github.com/kyosu-1/dbgateway/internal/analysis"
)

// unsupportedError is why a statement cannot be backed up; it matches
// analysis.ErrBackupUnsupported.
type unsupportedError string

func (e unsupportedError) Error() string        { return string(e) }
func (e unsupportedError) Is(target error) bool { return target == analysis.ErrBackupUnsupported }

func unsupported(format string, args ...any) error {
	return unsupportedError(fmt.Sprintf(format, args...))
}

// PlanBackup returns how to save the rows an UPDATE or DELETE will change.
// Only the plain forms are supported — one base table, a WHERE clause, no
// WITH, FROM (UPDATE) or USING (DELETE) — so that "SELECT target.* FROM
// target WHERE <same condition>" selects the rows the statement changes.
// Execute verifies that the backup holds exactly those rows (by row
// identity) and rolls back otherwise, e.g. when a volatile function or a
// LIMIT without ORDER BY made the two pick different rows.
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
	case *pg.Node_MergeStmt:
		return nil, unsupported("MERGE")
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

	// SELECT <ref>.*, <ref>.tableoid, <ref>.ctid FROM <relation as written>
	// WHERE <condition>: the relation keeps its ONLY flag and alias, so the
	// condition resolves exactly as it does in the statement.
	ref := rel.Relname
	if rel.Alias != nil && rel.Alias.Aliasname != "" {
		ref = rel.Alias.Aliasname
	}
	col := func(name *pg.Node) *pg.Node { return pg.MakeColumnRefNode([]*pg.Node{pg.MakeStrNode(ref), name}, -1) }
	sel := &pg.SelectStmt{
		TargetList: []*pg.Node{
			pg.MakeResTargetNodeWithVal(col(pg.MakeAStarNode()), -1),
			pg.MakeResTargetNodeWithNameAndVal(analysis.BackupTableOIDColumn, col(pg.MakeStrNode("tableoid")), -1),
			pg.MakeResTargetNodeWithNameAndVal(analysis.BackupCTIDColumn, col(pg.MakeStrNode("ctid")), -1),
		},
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
	tag, err := tx.Exec(ctx, "CREATE TABLE "+pgx.Identifier{b.Schema, b.Table}.Sanitize()+" AS "+b.Plan.Select)
	if err != nil {
		return 0, &analysis.BackupError{Reason: "could not create the backup table", Err: err}
	}
	return tag.RowsAffected(), nil
}

// verifyBackup checks, after the write, that the backup holds exactly the
// rows the statement changed: as many rows, and none of the saved row
// versions is still visible (each was updated or deleted by the statement).
func verifyBackup(ctx context.Context, tx pgx.Tx, b *analysis.BackupSpec, saved, affected int64) error {
	if saved != affected {
		return &analysis.BackupError{Reason: fmt.Sprintf("the backup holds %d rows but the statement changed %d", saved, affected)}
	}
	target := pgx.Identifier{b.Plan.Target.Schema, b.Plan.Target.Name}.Sanitize()
	backup := pgx.Identifier{b.Schema, b.Table}.Sanitize()
	oid, ctid := pgx.Identifier{analysis.BackupTableOIDColumn}.Sanitize(), pgx.Identifier{analysis.BackupCTIDColumn}.Sanitize()
	var left int64
	err := tx.QueryRow(ctx, fmt.Sprintf(
		"SELECT count(*) FROM %s AS t WHERE t.ctid = ANY (ARRAY(SELECT b.%s FROM %s AS b)) AND (t.tableoid, t.ctid) IN (SELECT b.%s, b.%s FROM %s AS b)",
		target, ctid, backup, oid, ctid, backup)).Scan(&left)
	if err != nil {
		return &analysis.BackupError{Reason: "could not verify the backup", Err: err}
	}
	if left != 0 {
		return &analysis.BackupError{Reason: "the backup does not hold the rows the statement changed " +
			"(volatile functions such as random() or a LIMIT without ORDER BY can select different rows each time)"}
	}
	return nil
}

// finishBackup builds the restore statement and records it, with the
// source, in the backup table's comment (the gateway lets only that exact
// statement read the backup).
func finishBackup(ctx context.Context, tx pgx.Tx, b *analysis.BackupSpec, saved int64) (*analysis.BackupResult, error) {
	restore, why, err := restoreSQL(ctx, tx, b)
	if err != nil {
		return nil, err
	}
	rec, _ := json.Marshal(analysis.BackupRecord{RequestID: b.RequestID, Source: b.Plan.Target.FQN(), Kind: string(b.Plan.Kind), RestoreSQL: restore})
	if _, err := tx.Exec(ctx, "COMMENT ON TABLE "+pgx.Identifier{b.Schema, b.Table}.Sanitize()+" IS "+quoteLiteral(string(rec))); err != nil {
		return nil, &analysis.BackupError{Reason: "could not record the backup", Err: err}
	}
	return &analysis.BackupResult{Schema: b.Schema, Table: b.Table, Source: b.Plan.Target.FQN(), Rows: saved,
		RestoreSQL: restore, RestoreUnavailable: why}, nil
}

// restoreSQL builds the statement that undoes the change from the backup
// table: DELETE → re-insert the saved rows; UPDATE → set the assigned
// columns back, matching rows by primary key. The UPDATE form uses no FROM
// clause, so a restore can itself be backed up.
func restoreSQL(ctx context.Context, tx pgx.Tx, b *analysis.BackupSpec) (string, string, error) {
	target := pgx.Identifier{b.Plan.Target.Schema, b.Plan.Target.Name}.Sanitize()
	backup := pgx.Identifier{b.Schema, b.Table}.Sanitize()
	cols, err := tableColumns(ctx, tx, target)
	if err != nil {
		return "", "", err
	}
	switch b.Plan.Kind {
	case analysis.KindDelete:
		// Rows deleted through a parent of plain (non-declarative)
		// inheritance came from child tables; inserting into the parent
		// would put them in the wrong table.
		var children int64
		err := tx.QueryRow(ctx, fmt.Sprintf(
			"SELECT count(*) FROM %s AS b WHERE b.%s <> $1::regclass AND (SELECT relkind FROM pg_class WHERE oid = $1::regclass) = 'r'",
			backup, pgx.Identifier{analysis.BackupTableOIDColumn}.Sanitize()), target).Scan(&children)
		if err != nil {
			return "", "", &analysis.BackupError{Reason: "could not read the backup", Err: err}
		}
		if children > 0 {
			return "", "Some rows came from inheritance child tables; restore them from the backup table manually.", nil
		}
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
		var pk []tableColumn
		for _, c := range cols {
			if c.pkPos > 0 {
				pk = append(pk, c)
			}
		}
		slices.SortFunc(pk, func(x, y tableColumn) int { return x.pkPos - y.pkPos })
		if len(pk) == 0 {
			return "", "The table has no primary key, so the changed rows cannot be matched for a restore.", nil
		}
		for _, c := range b.Plan.SetColumns {
			if slices.ContainsFunc(pk, func(k tableColumn) bool { return k.name == c }) {
				return "", "The statement changed the primary key, so the changed rows cannot be matched for a restore.", nil
			}
		}
		var match, tKeys, bKeys []string
		for _, k := range pk {
			id := pgx.Identifier{k.name}.Sanitize()
			match = append(match, fmt.Sprintf("b.%s = t.%s", id, id))
			tKeys = append(tKeys, "t."+id)
			bKeys = append(bKeys, "b."+id)
		}
		cond := strings.Join(match, " AND ")
		sets := make([]string, 0, len(b.Plan.SetColumns))
		for _, c := range b.Plan.SetColumns {
			id := pgx.Identifier{c}.Sanitize()
			sets = append(sets, fmt.Sprintf("%s = (SELECT b.%s FROM %s AS b WHERE %s)", id, id, backup, cond))
		}
		return fmt.Sprintf("UPDATE %s AS t SET %s WHERE (%s) IN (SELECT %s FROM %s AS b)", target, strings.Join(sets, ", "),
			strings.Join(tKeys, ", "), strings.Join(bKeys, ", "), backup), "", nil
	}
	return "", "Restore is not supported for this statement.", nil
}

type tableColumn struct {
	name           string
	generated      bool
	identityAlways bool
	pkPos          int // 1-based position in the primary key; 0 if not part of it
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
		return nil, &analysis.BackupError{Reason: "could not read the table definition", Err: err}
	}
	cols, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (tableColumn, error) {
		var c tableColumn
		var pos int32
		err := r.Scan(&c.name, &c.generated, &c.identityAlways, &pos)
		c.pkPos = int(pos)
		return c, err
	})
	if err != nil {
		return nil, &analysis.BackupError{Reason: "could not read the table definition", Err: err}
	}
	return cols, nil
}

const backupRecordSQL = `
SELECT coalesce(obj_description(c.oid, 'pg_class'), '')
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind = 'r'`

// BackupRecord reads what a backup table records about itself. It returns
// nil when the table does not exist or is not the backup of request table.
// Only the system catalog is read, so the read user needs no access to the
// backup schema.
func (a *Adapter) BackupRecord(ctx context.Context, ac analysis.Conn, schema, table string) (*analysis.BackupRecord, error) {
	c := ac.(*conn)
	var raw string
	err := c.withReadTx(ctx, analysis.ExecOptions{ReadOnly: true}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, backupRecordSQL, schema, table).Scan(&raw)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec analysis.BackupRecord
	if json.Unmarshal([]byte(raw), &rec) != nil || rec.RequestID != table {
		return nil, nil
	}
	return &rec, nil
}

// quoteLiteral quotes s as a string literal. The comment is JSON produced
// by encoding/json, whose backslashes always come in escape pairs, so it is
// safe whatever standard_conforming_strings is.
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
