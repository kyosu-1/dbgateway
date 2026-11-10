package lint

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	pg "github.com/pganalyze/pg_query_go/v6"
	pgparser "github.com/pganalyze/pg_query_go/v6/parser"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// PostgreSQL rule IDs.
const (
	pgCreateIndexConcurrently   = "pg/create-index-concurrently"
	pgDropIndexConcurrently     = "pg/drop-index-concurrently"
	pgConcurrentlyInTransaction = "pg/concurrently-in-transaction"
	pgAddColumnNotNull          = "pg/add-column-not-null-without-default"
	pgAddColumnVolatileDefault  = "pg/add-column-volatile-default"
	pgAlterColumnType           = "pg/alter-column-type"
	pgSetNotNull                = "pg/set-not-null"
	pgAddConstraintNotValid     = "pg/add-constraint-not-valid"
	pgConstraintUsingIndex      = "pg/constraint-using-index"
	pgLockTimeout               = "pg/lock-timeout"
	pgDropTable                 = "pg/drop-table"
	pgDropColumn                = "pg/drop-column"
	pgRenameTable               = "pg/rename-table"
	pgRenameColumn              = "pg/rename-column"
	pgTruncate                  = "pg/truncate"
	pgDMLWithoutWhere           = "pg/dml-without-where"
	pgRequirePrimaryKey         = "pg/require-primary-key"
	pgPreferIdentity            = "pg/prefer-identity"
	pgPreferTimestamptz         = "pg/prefer-timestamptz"
	pgPreferText                = "pg/prefer-text"
)

func init() {
	register(
		Rule{pgCreateIndexConcurrently, Postgres, SeverityError,
			"CREATE INDEX without CONCURRENTLY on an existing table blocks writes until the index is built.",
			"Use CREATE INDEX CONCURRENTLY, outside a transaction block. If it fails, drop the INVALID index it leaves behind and retry."},
		Rule{pgDropIndexConcurrently, Postgres, SeverityWarning,
			"DROP INDEX without CONCURRENTLY takes an ACCESS EXCLUSIVE lock on the table.",
			"Use DROP INDEX CONCURRENTLY, outside a transaction block."},
		Rule{pgConcurrentlyInTransaction, Postgres, SeverityError,
			"CONCURRENTLY cannot run inside a transaction block; the migration fails.",
			"Move the statement out of BEGIN ... COMMIT into a migration that your tool runs without a transaction."},
		Rule{pgAddColumnNotNull, Postgres, SeverityError,
			"ADD COLUMN ... NOT NULL without a DEFAULT fails on a table that has rows.",
			"Add a constant DEFAULT (no table rewrite since PostgreSQL 11), or add the column as nullable, backfill it, then make it NOT NULL."},
		Rule{pgAddColumnVolatileDefault, Postgres, SeverityError,
			"ADD COLUMN with a volatile default, a serial type, an identity or a stored generated column rewrites the whole table under an ACCESS EXCLUSIVE lock.",
			"Add the column without that default (a constant default is fine), backfill it in batches, then set the default for new rows."},
		Rule{pgAlterColumnType, Postgres, SeverityError,
			"ALTER COLUMN ... TYPE usually rewrites the table and its indexes under an ACCESS EXCLUSIVE lock.",
			"Add a new column, backfill it in batches and move the code over. A change that needs no rewrite (such as varchar(n) to text or to a longer varchar) can be suppressed with a dbgw-lint-ignore comment."},
		Rule{pgSetNotNull, Postgres, SeverityError,
			"SET NOT NULL scans the whole table under an ACCESS EXCLUSIVE lock.",
			"Add CHECK (col IS NOT NULL) NOT VALID, run VALIDATE CONSTRAINT separately, then SET NOT NULL (PostgreSQL 12+ skips the scan thanks to the valid constraint) and drop the CHECK."},
		Rule{pgAddConstraintNotValid, Postgres, SeverityError,
			"Adding a FOREIGN KEY or CHECK constraint checks every row while holding a lock that blocks writes.",
			"Add the constraint with NOT VALID, then run ALTER TABLE ... VALIDATE CONSTRAINT in a separate transaction; validating does not block writes."},
		Rule{pgConstraintUsingIndex, Postgres, SeverityError,
			"Adding a PRIMARY KEY or UNIQUE constraint builds its index while holding an ACCESS EXCLUSIVE lock.",
			"Run CREATE UNIQUE INDEX CONCURRENTLY first, then ALTER TABLE ... ADD CONSTRAINT ... PRIMARY KEY USING INDEX (or UNIQUE USING INDEX)."},
		Rule{pgLockTimeout, Postgres, SeverityWarning,
			"DDL that locks an existing table runs without lock_timeout; while it waits for the lock, every later query on the table waits too.",
			"Begin the migration with SET lock_timeout = '5s' (SET LOCAL inside a transaction) and retry when it times out."},
		Rule{pgDropTable, Postgres, SeverityWarning,
			"DROP TABLE deletes the table and its data, and breaks code that still uses it.",
			"Make sure no deployed code uses the table and that the data is backed up or no longer needed."},
		Rule{pgDropColumn, Postgres, SeverityWarning,
			"DROP COLUMN deletes the column's data and breaks code that still reads or writes it.",
			"First deploy code that no longer uses the column, then drop it in a later migration."},
		Rule{pgRenameTable, Postgres, SeverityWarning,
			"Renaming a table or view breaks code that still uses the old name.",
			"Expand and contract: add the new name, move the code over, then remove the old name in a later migration."},
		Rule{pgRenameColumn, Postgres, SeverityWarning,
			"Renaming a column breaks code that still uses the old name.",
			"Add a new column, write to both, backfill, move reads over, then drop the old column in a later migration."},
		Rule{pgTruncate, Postgres, SeverityWarning,
			"TRUNCATE deletes every row and takes an ACCESS EXCLUSIVE lock.",
			"Make sure the data is no longer needed; on a table in use, delete in batches instead."},
		Rule{pgDMLWithoutWhere, Postgres, SeverityError,
			"UPDATE or DELETE without WHERE changes every row of an existing table.",
			"Add a WHERE clause. For an intended backfill, update large tables in batches and suppress the finding with a dbgw-lint-ignore comment."},
		Rule{pgRequirePrimaryKey, Postgres, SeverityWarning,
			"CREATE TABLE without a primary key.",
			"Add a primary key, e.g. id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY. Logical replication, many tools and ORMs need one to identify rows."},
		Rule{pgPreferIdentity, Postgres, SeverityWarning,
			"serial, bigserial and smallserial are discouraged.",
			"Use bigint GENERATED ALWAYS AS IDENTITY (or BY DEFAULT); identity columns are standard SQL and their sequence is managed with the column."},
		Rule{pgPreferTimestamptz, Postgres, SeverityWarning,
			"timestamp without time zone stores no zone, so values are misread when clients use different time zones.",
			"Use timestamptz (timestamp with time zone)."},
		Rule{pgPreferText, Postgres, SeverityInfo,
			"varchar(n) and char(n) make the limit hard to change later, and char(n) pads with spaces.",
			"Use text, with a CHECK (char_length(col) <= n) constraint if a limit is needed."},
	)
}

// volatileFunctions are built-in functions whose use as a column default
// forces a table rewrite when the column is added.
var volatileFunctions = map[string]bool{
	"random": true, "gen_random_uuid": true, "uuidv4": true, "uuidv7": true,
	"uuid_generate_v1": true, "uuid_generate_v1mc": true, "uuid_generate_v4": true,
	"clock_timestamp": true, "timeofday": true, "nextval": true, "random_normal": true,
}

var serialTypes = map[string]bool{
	"serial": true, "serial4": true, "bigserial": true, "serial8": true, "smallserial": true, "serial2": true,
}

func checkPostgres(src string) result {
	tree, err := pg.Parse(src)
	if err != nil {
		off := 0
		var pe *pgparser.Error
		if errors.As(err, &pe) && pe.Cursorpos > 0 {
			off = charOffset(src, pe.Cursorpos-1)
		}
		return result{syntax: &raw{offset: off, stmt: -1, msg: "Could not parse the SQL: " + err.Error()}}
	}
	var res result
	var tokens []int // starts of non-comment tokens
	if scan, err := pg.Scan(src); err == nil {
		for _, t := range scan.Tokens {
			if t.Token == pg.Token_SQL_COMMENT || t.Token == pg.Token_C_COMMENT {
				res.comments = append(res.comments, comment{offset: int(t.Start), text: src[t.Start:t.End]})
				continue
			}
			tokens = append(tokens, int(t.Start))
		}
	}
	c := &pgChecker{src: src, notNullChecks: map[string]bool{}, pendingChecks: map[string]string{}}
	ti := 0
	for i, rs := range tree.Stmts {
		start := int(rs.StmtLocation)
		for ti < len(tokens) && tokens[ti] < start {
			ti++
		}
		if ti < len(tokens) {
			start = tokens[ti]
		}
		end := len(src)
		if rs.StmtLen > 0 {
			end = int(rs.StmtLocation + rs.StmtLen)
		}
		res.stmts = append(res.stmts, span{start, end})
		c.stmt, c.start = i, start
		c.statement(rs.Stmt)
	}
	c.finish()
	res.findings = c.out
	return res
}

// charOffset converts a character index into a byte offset.
func charOffset(s string, chars int) int {
	n := 0
	for i := range s {
		if n == chars {
			return i
		}
		n++
	}
	return len(s)
}

// relName is a possibly schema-qualified relation name.
type relName struct{ schema, name string }

func (r relName) String() string {
	if r.schema == "" {
		return r.name
	}
	return r.schema + "." + r.name
}

// same reports whether two names may refer to the same relation. An
// unqualified name matches any schema.
func (r relName) same(o relName) bool {
	return r.name == o.name && (r.schema == "" || o.schema == "" || r.schema == o.schema)
}

func rangeVarName(rv *pg.RangeVar) relName {
	if rv == nil {
		return relName{}
	}
	return relName{schema: rv.Schemaname, name: rv.Relname}
}

// listName converts a name list (DROP objects) into a relation name.
func listName(n *pg.Node) relName {
	var parts []string
	for _, item := range n.GetList().GetItems() {
		parts = append(parts, item.GetString_().GetSval())
	}
	switch len(parts) {
	case 0:
		return relName{}
	case 1:
		return relName{name: parts[0]}
	}
	return relName{schema: parts[len(parts)-2], name: parts[len(parts)-1]}
}

type pendingPK struct {
	rel    relName
	offset int
	stmt   int
}

type pgChecker struct {
	src   string
	stmt  int // current statement index
	start int // current statement start
	out   []raw

	created        []relName // tables created in this file
	createdIndexes []relName

	inTx            bool
	lockTimeout     bool // session lock_timeout set
	txLockTimeout   bool // SET LOCAL lock_timeout in the current transaction
	lockTimeoutDone bool // pg/lock-timeout reported (once per file)

	notNullChecks map[string]bool   // "table.col" with a valid CHECK (col IS NOT NULL)
	pendingChecks map[string]string // NOT VALID constraint name -> "table.col"
	noPK          []pendingPK
}

func (c *pgChecker) report(rule string, offset int, format string, args ...any) {
	if offset < 0 {
		offset = c.start
	}
	c.out = append(c.out, raw{offset: offset, stmt: c.stmt, rule: rule, msg: fmt.Sprintf(format, args...)})
}

func (c *pgChecker) isNew(r relName) bool {
	for _, t := range c.created {
		if t.same(r) {
			return true
		}
	}
	return false
}

// locks is called for statements that take a strong lock on an existing
// table.
func (c *pgChecker) locks() {
	if c.lockTimeoutDone || c.lockTimeout || (c.inTx && c.txLockTimeout) {
		return
	}
	c.lockTimeoutDone = true
	c.report(pgLockTimeout, c.start, "This statement locks an existing table, but lock_timeout is not set earlier in the file.")
}

func (c *pgChecker) concurrently(what string) {
	if c.inTx {
		c.report(pgConcurrentlyInTransaction, c.start, "%s CONCURRENTLY inside a transaction block (BEGIN earlier in the file) fails.", what)
	}
}

func (c *pgChecker) statement(n *pg.Node) {
	switch s := n.GetNode().(type) {
	case *pg.Node_TransactionStmt:
		c.transaction(s.TransactionStmt)
	case *pg.Node_VariableSetStmt:
		c.set(s.VariableSetStmt)
	case *pg.Node_CreateStmt:
		c.createTable(s.CreateStmt)
	case *pg.Node_CreateTableAsStmt:
		if s.CreateTableAsStmt.GetInto() != nil {
			c.created = append(c.created, rangeVarName(s.CreateTableAsStmt.Into.Rel))
		}
	case *pg.Node_IndexStmt:
		c.createIndex(s.IndexStmt)
	case *pg.Node_DropStmt:
		c.drop(s.DropStmt)
	case *pg.Node_ReindexStmt:
		for _, p := range s.ReindexStmt.Params {
			if p.GetDefElem().GetDefname() == "concurrently" {
				c.concurrently("REINDEX")
			}
		}
	case *pg.Node_AlterTableStmt:
		c.alterTable(s.AlterTableStmt)
	case *pg.Node_RenameStmt:
		c.rename(s.RenameStmt)
	case *pg.Node_TruncateStmt:
		for _, r := range s.TruncateStmt.Relations {
			if rel := rangeVarName(r.GetRangeVar()); !c.isNew(rel) {
				c.locks()
				c.report(pgTruncate, c.start, "TRUNCATE deletes every row of %s.", rel)
				break
			}
		}
	case *pg.Node_UpdateStmt:
		if s.UpdateStmt.WhereClause == nil && !c.isNew(rangeVarName(s.UpdateStmt.Relation)) {
			c.report(pgDMLWithoutWhere, c.start, "UPDATE without WHERE changes every row of %s.", rangeVarName(s.UpdateStmt.Relation))
		}
	case *pg.Node_DeleteStmt:
		if s.DeleteStmt.WhereClause == nil && !c.isNew(rangeVarName(s.DeleteStmt.Relation)) {
			c.report(pgDMLWithoutWhere, c.start, "DELETE without WHERE deletes every row of %s.", rangeVarName(s.DeleteStmt.Relation))
		}
	case *pg.Node_CreateTrigStmt:
		if !c.isNew(rangeVarName(s.CreateTrigStmt.Relation)) {
			c.locks()
		}
	}
}

func (c *pgChecker) transaction(t *pg.TransactionStmt) {
	switch t.Kind {
	case pg.TransactionStmtKind_TRANS_STMT_BEGIN, pg.TransactionStmtKind_TRANS_STMT_START:
		c.inTx = true
	case pg.TransactionStmtKind_TRANS_STMT_COMMIT, pg.TransactionStmtKind_TRANS_STMT_ROLLBACK:
		c.txLockTimeout = false
		c.inTx = t.Chain
	case pg.TransactionStmtKind_TRANS_STMT_PREPARE:
		c.txLockTimeout = false
		c.inTx = false
	}
}

func (c *pgChecker) set(s *pg.VariableSetStmt) {
	if s.Name != "lock_timeout" && s.Kind != pg.VariableSetKind_VAR_RESET_ALL {
		return
	}
	on := false
	if s.Kind == pg.VariableSetKind_VAR_SET_VALUE && len(s.Args) == 1 {
		switch v := s.Args[0].GetAConst(); {
		case v == nil:
			on = true // not a literal; assume it sets a timeout
		case v.GetIval() != nil:
			on = v.GetIval().Ival != 0
		case v.GetSval() != nil:
			on = nonZeroSetting(v.GetSval().Sval)
		default:
			on = true
		}
	}
	if s.IsLocal {
		c.txLockTimeout = on && c.inTx
		return
	}
	c.lockTimeout = on
	if c.inTx {
		c.txLockTimeout = on
	}
}

func (c *pgChecker) createTable(s *pg.CreateStmt) {
	rel := rangeVarName(s.Relation)
	c.created = append(c.created, rel)
	hasPK := false
	skipPK := s.Relation.GetRelpersistence() == "t" || s.Partbound != nil || s.OfTypename != nil
	for _, e := range s.TableElts {
		switch x := e.GetNode().(type) {
		case *pg.Node_ColumnDef:
			c.columnTypes(x.ColumnDef.TypeName)
			for _, con := range x.ColumnDef.Constraints {
				if con.GetConstraint().GetContype() == pg.ConstrType_CONSTR_PRIMARY {
					hasPK = true
				}
			}
		case *pg.Node_Constraint:
			if x.Constraint.Contype == pg.ConstrType_CONSTR_PRIMARY {
				hasPK = true
			}
		case *pg.Node_TableLikeClause:
			skipPK = true // the primary key may be copied
		}
	}
	if !hasPK && !skipPK {
		off := int(s.Relation.GetLocation())
		if off <= 0 {
			off = c.start
		}
		c.noPK = append(c.noPK, pendingPK{rel: rel, offset: off, stmt: c.stmt})
	}
}

// hasPrimaryKey drops a pending missing-primary-key finding when the
// primary key is added later in the file.
func (c *pgChecker) hasPrimaryKey(rel relName) {
	c.noPK = slices.DeleteFunc(c.noPK, func(p pendingPK) bool { return p.rel.same(rel) })
}

func (c *pgChecker) finish() {
	for _, p := range c.noPK {
		c.out = append(c.out, raw{offset: p.offset, stmt: p.stmt, rule: pgRequirePrimaryKey,
			msg: fmt.Sprintf("Table %s has no primary key.", p.rel)})
	}
}

func (c *pgChecker) columnTypes(t *pg.TypeName) {
	if t == nil {
		return
	}
	var names []string
	for _, n := range t.Names {
		names = append(names, n.GetString_().GetSval())
	}
	if len(names) == 0 {
		return
	}
	last := names[len(names)-1]
	builtin := len(names) == 1 || names[0] == "pg_catalog"
	off := int(t.Location)
	switch {
	case len(names) == 1 && serialTypes[last]:
		c.report(pgPreferIdentity, off, "Column uses %s; prefer an identity column.", last)
	case builtin && last == "timestamp":
		c.report(pgPreferTimestamptz, off, "Column uses timestamp without time zone; prefer timestamptz.")
	case builtin && last == "varchar" && len(t.Typmods) > 0:
		c.report(pgPreferText, off, "Column uses varchar(n); prefer text.")
	case names[0] == "pg_catalog" && last == "bpchar":
		c.report(pgPreferText, off, "Column uses char(n); prefer text.")
	}
}

func (c *pgChecker) createIndex(s *pg.IndexStmt) {
	rel := rangeVarName(s.Relation)
	if s.Idxname != "" {
		c.createdIndexes = append(c.createdIndexes, relName{schema: rel.schema, name: s.Idxname})
	}
	if s.Concurrent {
		c.concurrently("CREATE INDEX")
		return
	}
	if c.isNew(rel) {
		return
	}
	c.locks()
	c.report(pgCreateIndexConcurrently, c.start, "CREATE INDEX on %s without CONCURRENTLY blocks writes to the table while the index is built.", rel)
}

func (c *pgChecker) drop(s *pg.DropStmt) {
	switch s.RemoveType {
	case pg.ObjectType_OBJECT_INDEX:
		if s.Concurrent {
			c.concurrently("DROP INDEX")
			return
		}
		for _, o := range s.Objects {
			name := listName(o)
			isNew := false
			for _, ix := range c.createdIndexes {
				isNew = isNew || ix.same(name)
			}
			if !isNew {
				c.locks()
				c.report(pgDropIndexConcurrently, c.start, "DROP INDEX %s without CONCURRENTLY locks its table against reads and writes.", name)
				return
			}
		}
	case pg.ObjectType_OBJECT_TABLE:
		for _, o := range s.Objects {
			if name := listName(o); !c.isNew(name) {
				c.locks()
				c.report(pgDropTable, c.start, "DROP TABLE %s deletes the table and its data.", name)
			}
		}
	}
}

func (c *pgChecker) rename(s *pg.RenameStmt) {
	rel := rangeVarName(s.Relation)
	if s.Relation == nil || c.isNew(rel) {
		return
	}
	switch s.RenameType {
	case pg.ObjectType_OBJECT_TABLE, pg.ObjectType_OBJECT_VIEW, pg.ObjectType_OBJECT_MATVIEW:
		c.locks()
		c.report(pgRenameTable, c.start, "Renaming %s to %s breaks code that uses the old name.", rel, s.Newname)
	case pg.ObjectType_OBJECT_COLUMN:
		c.locks()
		c.report(pgRenameColumn, c.start, "Renaming column %s.%s to %s breaks code that uses the old name.", rel, s.Subname, s.Newname)
	}
}

func (c *pgChecker) alterTable(s *pg.AlterTableStmt) {
	if s.Objtype != pg.ObjectType_OBJECT_TABLE {
		return
	}
	rel := rangeVarName(s.Relation)
	existing := !c.isNew(rel)
	if existing {
		for _, cmd := range s.Cmds {
			if cmd.GetAlterTableCmd().GetSubtype() != pg.AlterTableType_AT_ValidateConstraint {
				c.locks() // VALIDATE CONSTRAINT alone does not block reads or writes
				break
			}
		}
	}
	for _, n := range s.Cmds {
		cmd := n.GetAlterTableCmd()
		if cmd == nil {
			continue
		}
		switch cmd.Subtype {
		case pg.AlterTableType_AT_AddColumn:
			col := cmd.Def.GetColumnDef()
			if col == nil {
				continue
			}
			c.columnTypes(col.TypeName)
			if existing {
				c.addColumn(rel, col)
			}
			for _, con := range col.Constraints {
				if con.GetConstraint().GetContype() == pg.ConstrType_CONSTR_PRIMARY {
					c.hasPrimaryKey(rel)
				}
			}
		case pg.AlterTableType_AT_AlterColumnType:
			col := cmd.Def.GetColumnDef()
			c.columnTypes(col.GetTypeName())
			if existing {
				off := -1
				if col.GetTypeName() != nil {
					off = int(col.TypeName.Location)
				}
				c.report(pgAlterColumnType, off, "Changing the type of %s.%s rewrites the table unless the types are binary coercible.", rel, cmd.Name)
			}
		case pg.AlterTableType_AT_SetNotNull:
			if existing && !c.notNullChecks[rel.name+"."+cmd.Name] {
				c.report(pgSetNotNull, c.start, "SET NOT NULL on %s.%s scans the whole table while blocking reads and writes.", rel, cmd.Name)
			}
		case pg.AlterTableType_AT_AddConstraint:
			if con := cmd.Def.GetConstraint(); con != nil {
				c.addConstraint(rel, existing, con)
			}
		case pg.AlterTableType_AT_ValidateConstraint:
			if col, ok := c.pendingChecks[cmd.Name]; ok {
				c.notNullChecks[col] = true
			}
		case pg.AlterTableType_AT_DropColumn:
			if existing {
				c.report(pgDropColumn, c.start, "Dropping column %s.%s deletes its data.", rel, cmd.Name)
			}
		case pg.AlterTableType_AT_DetachPartition:
			if cmd.Def.GetPartitionCmd().GetConcurrent() {
				c.concurrently("DETACH PARTITION")
			}
		}
	}
}

func (c *pgChecker) addColumn(rel relName, col *pg.ColumnDef) {
	var notNull, hasDefault bool
	var defaults []*pg.Node
	if col.RawDefault != nil {
		defaults = append(defaults, col.RawDefault)
	}
	rewrite := ""
	if names := col.GetTypeName().GetNames(); len(names) == 1 && serialTypes[names[0].GetString_().GetSval()] {
		hasDefault = true
		rewrite = "a serial type"
	}
	for _, n := range col.Constraints {
		con := n.GetConstraint()
		switch con.GetContype() {
		case pg.ConstrType_CONSTR_NOTNULL:
			notNull = true
		case pg.ConstrType_CONSTR_PRIMARY:
			notNull = true
			c.report(pgConstraintUsingIndex, int(con.Location), "Adding column %s.%s with PRIMARY KEY builds the index while blocking reads and writes.", rel, col.Colname)
		case pg.ConstrType_CONSTR_UNIQUE:
			c.report(pgConstraintUsingIndex, int(con.Location), "Adding column %s.%s with UNIQUE builds the index while blocking reads and writes.", rel, col.Colname)
		case pg.ConstrType_CONSTR_DEFAULT:
			hasDefault = true
			defaults = append(defaults, con.RawExpr)
		case pg.ConstrType_CONSTR_IDENTITY:
			hasDefault = true
			rewrite = "an identity column"
		case pg.ConstrType_CONSTR_GENERATED:
			hasDefault = true
			rewrite = "a stored generated column"
		}
	}
	if col.IsNotNull {
		notNull = true
	}
	hasDefault = hasDefault || len(defaults) > 0
	for _, d := range defaults {
		walk(d, func(m proto.Message) bool {
			if f, ok := m.(*pg.FuncCall); ok && len(f.Funcname) > 0 {
				name := f.Funcname[len(f.Funcname)-1].GetString_().GetSval()
				if volatileFunctions[name] {
					rewrite = "the volatile default " + name + "()"
				}
			}
			return true
		})
	}
	if notNull && !hasDefault {
		c.report(pgAddColumnNotNull, int(col.Location), "Adding NOT NULL column %s.%s without a DEFAULT fails if the table has rows.", rel, col.Colname)
	}
	if rewrite != "" {
		c.report(pgAddColumnVolatileDefault, int(col.Location), "Adding column %s.%s with %s rewrites the whole table while blocking reads and writes.", rel, col.Colname, rewrite)
	}
}

func (c *pgChecker) addConstraint(rel relName, existing bool, con *pg.Constraint) {
	switch con.Contype {
	case pg.ConstrType_CONSTR_PRIMARY:
		c.hasPrimaryKey(rel)
		if existing && con.Indexname == "" {
			c.report(pgConstraintUsingIndex, int(con.Location), "Adding a PRIMARY KEY to %s builds the index while blocking reads and writes.", rel)
		}
	case pg.ConstrType_CONSTR_UNIQUE:
		if existing && con.Indexname == "" {
			c.report(pgConstraintUsingIndex, int(con.Location), "Adding a UNIQUE constraint to %s builds the index while blocking reads and writes.", rel)
		}
	case pg.ConstrType_CONSTR_CHECK:
		if col := notNullCheckColumn(con.RawExpr); col != "" {
			key := rel.name + "." + col
			if con.SkipValidation {
				if con.Conname != "" {
					c.pendingChecks[con.Conname] = key
				}
			} else {
				c.notNullChecks[key] = true
			}
		}
		if existing && !con.SkipValidation {
			c.report(pgAddConstraintNotValid, int(con.Location), "Adding a CHECK constraint to %s without NOT VALID checks every row while blocking reads and writes.", rel)
		}
	case pg.ConstrType_CONSTR_FOREIGN:
		if existing && !con.SkipValidation {
			c.report(pgAddConstraintNotValid, int(con.Location), "Adding a FOREIGN KEY to %s without NOT VALID checks every row while blocking writes to both tables.", rel)
		}
	}
}

// notNullCheckColumn returns col for the expression "col IS NOT NULL".
func notNullCheckColumn(n *pg.Node) string {
	nt := n.GetNullTest()
	if nt == nil || nt.Nulltesttype != pg.NullTestType_IS_NOT_NULL {
		return ""
	}
	fields := nt.Arg.GetColumnRef().GetFields()
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1].GetString_().GetSval()
}

// walk visits every message in the tree rooted at n in depth-first order.
// visit returns false to skip the children of a message.
func walk(m proto.Message, visit func(proto.Message) bool) {
	if m == nil {
		return
	}
	rm := m.ProtoReflect()
	if !rm.IsValid() || !visit(m) {
		return
	}
	rm.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList() && fd.Message() != nil:
			l := v.List()
			for i := 0; i < l.Len(); i++ {
				walk(l.Get(i).Message().Interface(), visit)
			}
		case fd.Message() != nil && !fd.IsMap():
			walk(v.Message().Interface(), visit)
		}
		return true
	})
}

// nonZeroSetting reports whether a time setting such as '5s' is not zero.
func nonZeroSetting(s string) bool {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	if i == 0 {
		return true
	}
	v, err := strconv.ParseFloat(s[:i], 64)
	return err != nil || v != 0
}
