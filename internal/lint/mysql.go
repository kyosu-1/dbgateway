package lint

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/ast"
	pmysql "github.com/pingcap/tidb/pkg/parser/mysql"
	// The parser needs a value-expression driver; test_driver is the
	// lightweight one meant for using the parser on its own.
	_ "github.com/pingcap/tidb/pkg/parser/test_driver"
)

// MySQL rule IDs.
const (
	myDropTable         = "mysql/drop-table"
	myDropColumn        = "mysql/drop-column"
	myRenameTable       = "mysql/rename-table"
	myRenameColumn      = "mysql/rename-column"
	myTruncate          = "mysql/truncate"
	myDMLWithoutWhere   = "mysql/dml-without-where"
	myRequirePrimaryKey = "mysql/require-primary-key"
	myAlterAlgorithm    = "mysql/alter-algorithm"
)

func init() {
	register(
		Rule{myDropTable, MySQL, SeverityWarning,
			"DROP TABLE deletes the table and its data, and breaks code that still uses it.",
			"Make sure no deployed code uses the table and that the data is backed up or no longer needed."},
		Rule{myDropColumn, MySQL, SeverityWarning,
			"DROP COLUMN deletes the column's data and breaks code that still reads or writes it.",
			"First deploy code that no longer uses the column, then drop it in a later migration."},
		Rule{myRenameTable, MySQL, SeverityWarning,
			"Renaming a table breaks code that still uses the old name.",
			"Expand and contract: add the new name, move the code over, then remove the old name in a later migration."},
		Rule{myRenameColumn, MySQL, SeverityWarning,
			"Renaming a column (RENAME COLUMN, or CHANGE with a new name) breaks code that still uses the old name.",
			"Add a new column, write to both, backfill, move reads over, then drop the old column in a later migration."},
		Rule{myTruncate, MySQL, SeverityWarning,
			"TRUNCATE TABLE deletes every row.",
			"Make sure the data is no longer needed; on a table in use, delete in batches instead."},
		Rule{myDMLWithoutWhere, MySQL, SeverityError,
			"UPDATE or DELETE without WHERE changes every row of an existing table.",
			"Add a WHERE clause. For an intended backfill, update large tables in batches and suppress the finding with a dbgw-lint-ignore comment."},
		Rule{myRequirePrimaryKey, MySQL, SeverityWarning,
			"CREATE TABLE without a primary key.",
			"Add a primary key. InnoDB otherwise uses a hidden row ID, and replication and online schema change tools need one."},
		Rule{myAlterAlgorithm, MySQL, SeverityWarning,
			"ALTER TABLE on an existing table does not state ALGORITHM=INSTANT or INPLACE, so MySQL may silently copy the table and block writes.",
			"Add ALGORITHM=INSTANT (or ALGORITHM=INPLACE, LOCK=NONE); MySQL then refuses the change instead of locking the table. Use an online schema change tool for changes that need a copy."},
	)
}

// mysqlSQLMode is the MySQL 8 default sql_mode. Migrations are written for
// the server defaults, so "..." is a string and backslash escapes work.
const mysqlSQLMode = "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE," +
	"ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION"

var mysqlParsers = sync.Pool{New: func() any {
	p := parser.New()
	mode, err := pmysql.GetSQLMode(mysqlSQLMode)
	if err != nil {
		panic(err)
	}
	p.SetSQLMode(mode)
	p.EnableWindowFunc(true)
	return p
}}

// parseMySQL parses src. The parser's lightweight value driver panics on
// some inputs; that is reported as a parse error and the parser discarded.
func parseMySQL(src string) (stmts []ast.StmtNode, err error) {
	p := mysqlParsers.Get().(*parser.Parser)
	defer func() {
		if r := recover(); r != nil {
			stmts, err = nil, fmt.Errorf("parser failed: %v", r)
			return
		}
		mysqlParsers.Put(p)
	}()
	stmts, _, err = p.ParseSQL(src)
	return stmts, err
}

var (
	mysqlErrPos    = regexp.MustCompile(`^line (\d+) column (\d+) near "`)
	mysqlErrLength = regexp.MustCompile(`\(total length (\d+)\)\s*$`)
)

// mysqlSyntaxError locates a TiDB parser error. The error quotes the rest of
// the input from the offending token ("near ..."); its line and column
// point after the token.
func mysqlSyntaxError(src string, err error) (int, string) {
	e := err.Error()
	m := mysqlErrPos.FindStringSubmatchIndex(e)
	if m == nil {
		return 0, "Could not parse the SQL: " + e
	}
	off := -1
	if l := mysqlErrLength.FindStringSubmatch(e); l != nil {
		if n, err := strconv.Atoi(l[1]); err == nil && n <= len(src) {
			off = len(src) - n
		}
	}
	if near := e[m[1]:]; off < 0 {
		// The longest prefix of near, ending before a quote, that is a
		// suffix of the input.
		for j := len(near) - 1; j >= 0; j-- {
			if near[j] == '"' && strings.HasSuffix(src, near[:j]) {
				off = len(src) - j
				break
			}
		}
	}
	if off < 0 {
		line, _ := strconv.Atoi(e[m[2]:m[3]])
		col, _ := strconv.Atoi(e[m[4]:m[5]])
		off = newLineIndex(src).offsetOf(line, col)
	}
	near := strings.TrimSpace(src[off:])
	if i := strings.IndexByte(near, '\n'); i >= 0 {
		near = near[:i]
	}
	if r := []rune(near); len(r) > 40 {
		near = string(r[:40]) + "..."
	}
	if near == "" {
		return off, "Could not parse the SQL: unexpected end of input."
	}
	return off, fmt.Sprintf("Could not parse the SQL: syntax error near %q.", near)
}

func checkMySQL(src string) result {
	stmts, err := parseMySQL(src)
	if err != nil {
		off, msg := mysqlSyntaxError(src, err)
		return result{syntax: &raw{offset: off, stmt: -1, msg: msg}}
	}
	var res result
	res.comments = mysqlComments(src)
	c := &myChecker{}
	cursor := 0
	for i, s := range stmts {
		start, end := cursor, len(src)
		if text := s.OriginalText(); text != "" {
			if j := strings.Index(src[cursor:], text); j >= 0 {
				start, end = cursor+j, cursor+j+len(text)
			}
		}
		cursor = end
		start = skipTrivia(src, start, res.comments)
		res.stmts = append(res.stmts, span{start, end})
		c.stmt, c.start = i, start
		c.statement(s)
	}
	c.finish()
	res.findings = c.out
	return res
}

// mysqlComments finds the comments in src, skipping string literals and
// quoted identifiers. Optimizer hints (/*+ */) and executable comments
// (/*! */) are code, not comments.
func mysqlComments(src string) []comment {
	var out []comment
	for i := 0; i < len(src); i++ {
		switch ch := src[i]; {
		case ch == '\'' || ch == '"' || ch == '`':
			for i++; i < len(src); i++ {
				if src[i] == '\\' && ch != '`' {
					i++
				} else if src[i] == ch {
					if i+1 < len(src) && src[i+1] == ch {
						i++
						continue
					}
					break
				}
			}
		case ch == '#' || (ch == '-' && strings.HasPrefix(src[i:], "--") && (i+2 == len(src) || src[i+2] <= ' ')):
			end := strings.IndexByte(src[i:], '\n')
			if end < 0 {
				end = len(src) - i
			}
			out = append(out, comment{offset: i, text: src[i : i+end]})
			i += end
		case ch == '/' && strings.HasPrefix(src[i:], "/*"):
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				end = len(src) - i
			} else {
				end += 4
			}
			if !strings.HasPrefix(src[i:], "/*!") && !strings.HasPrefix(src[i:], "/*+") {
				out = append(out, comment{offset: i, text: src[i : i+end]})
			}
			i += end - 1
		}
	}
	return out
}

// skipTrivia returns the offset of the first character at or after i that
// is neither white space nor part of a comment.
func skipTrivia(src string, i int, comments []comment) int {
	for i < len(src) {
		if src[i] == ' ' || src[i] == '\t' || src[i] == '\n' || src[i] == '\r' || src[i] == ';' {
			i++
			continue
		}
		j := slices.IndexFunc(comments, func(c comment) bool { return c.offset == i })
		if j < 0 {
			break
		}
		i += len(comments[j].text)
	}
	return i
}

type myChecker struct {
	stmt, start int
	out         []raw
	created     []relName
	noPK        []pendingPK
}

func (c *myChecker) report(rule, format string, args ...any) {
	c.out = append(c.out, raw{offset: c.start, stmt: c.stmt, rule: rule, msg: fmt.Sprintf(format, args...)})
}

func tableName(t *ast.TableName) relName {
	if t == nil {
		return relName{}
	}
	return relName{schema: t.Schema.L, name: t.Name.L}
}

func (c *myChecker) isNew(r relName) bool {
	for _, t := range c.created {
		if t.same(r) {
			return true
		}
	}
	return false
}

// singleTable returns the table of a single-table UPDATE or DELETE.
func singleTable(refs *ast.TableRefsClause) (relName, bool) {
	if refs == nil || refs.TableRefs == nil || refs.TableRefs.Right != nil {
		return relName{}, false
	}
	ts, ok := refs.TableRefs.Left.(*ast.TableSource)
	if !ok {
		return relName{}, false
	}
	tn, ok := ts.Source.(*ast.TableName)
	if !ok {
		return relName{}, false
	}
	return tableName(tn), true
}

func (c *myChecker) statement(n ast.StmtNode) {
	switch s := n.(type) {
	case *ast.CreateTableStmt:
		c.createTable(s)
	case *ast.DropTableStmt:
		if s.IsView || s.TemporaryKeyword != ast.TemporaryNone {
			return
		}
		for _, t := range s.Tables {
			if rel := tableName(t); !c.isNew(rel) {
				c.report(myDropTable, "DROP TABLE %s deletes the table and its data.", rel)
			}
		}
	case *ast.RenameTableStmt:
		for _, t := range s.TableToTables {
			if rel := tableName(t.OldTable); !c.isNew(rel) {
				c.report(myRenameTable, "Renaming %s to %s breaks code that uses the old name.", rel, tableName(t.NewTable))
			}
		}
	case *ast.TruncateTableStmt:
		if rel := tableName(s.Table); !c.isNew(rel) {
			c.report(myTruncate, "TRUNCATE TABLE deletes every row of %s.", rel)
		}
	case *ast.UpdateStmt:
		if s.Where == nil {
			if rel, ok := singleTable(s.TableRefs); !ok {
				c.report(myDMLWithoutWhere, "UPDATE without WHERE changes every row of the joined tables.")
			} else if !c.isNew(rel) {
				c.report(myDMLWithoutWhere, "UPDATE without WHERE changes every row of %s.", rel)
			}
		}
	case *ast.DeleteStmt:
		if s.Where == nil {
			if rel, ok := singleTable(s.TableRefs); s.IsMultiTable || !ok {
				c.report(myDMLWithoutWhere, "DELETE without WHERE deletes every row of the joined tables.")
			} else if !c.isNew(rel) {
				c.report(myDMLWithoutWhere, "DELETE without WHERE deletes every row of %s.", rel)
			}
		}
	case *ast.AlterTableStmt:
		c.alterTable(s)
	}
}

func (c *myChecker) createTable(s *ast.CreateTableStmt) {
	rel := tableName(s.Table)
	c.created = append(c.created, rel)
	if s.TemporaryKeyword != ast.TemporaryNone || s.ReferTable != nil || s.Select != nil {
		return
	}
	for _, con := range s.Constraints {
		if con.Tp == ast.ConstraintPrimaryKey {
			return
		}
	}
	for _, col := range s.Cols {
		for _, o := range col.Options {
			if o.Tp == ast.ColumnOptionPrimaryKey {
				return
			}
		}
	}
	c.noPK = append(c.noPK, pendingPK{rel: rel, offset: c.start, stmt: c.stmt})
}

func (c *myChecker) finish() {
	for _, p := range c.noPK {
		c.out = append(c.out, raw{offset: p.offset, stmt: p.stmt, rule: myRequirePrimaryKey,
			msg: fmt.Sprintf("Table %s has no primary key.", p.rel)})
	}
}

func (c *myChecker) alterTable(s *ast.AlterTableStmt) {
	rel := tableName(s.Table)
	existing := !c.isNew(rel)
	algorithm, lock := ast.AlgorithmTypeDefault, ast.LockTypeDefault
	for _, spec := range s.Specs {
		switch spec.Tp {
		case ast.AlterTableAlgorithm:
			algorithm = spec.Algorithm
		case ast.AlterTableLock:
			lock = spec.LockType
		case ast.AlterTableAddConstraint:
			if spec.Constraint != nil && spec.Constraint.Tp == ast.ConstraintPrimaryKey {
				c.noPK = slices.DeleteFunc(c.noPK, func(p pendingPK) bool { return p.rel.same(rel) })
			}
		case ast.AlterTableAddColumns:
			for _, col := range spec.NewColumns {
				for _, o := range col.Options {
					if o.Tp == ast.ColumnOptionPrimaryKey {
						c.noPK = slices.DeleteFunc(c.noPK, func(p pendingPK) bool { return p.rel.same(rel) })
					}
				}
			}
		}
		if !existing {
			continue
		}
		switch spec.Tp {
		case ast.AlterTableDropColumn:
			c.report(myDropColumn, "Dropping column %s.%s deletes its data.", rel, spec.OldColumnName.Name.O)
		case ast.AlterTableRenameColumn:
			c.report(myRenameColumn, "Renaming column %s.%s to %s breaks code that uses the old name.", rel, spec.OldColumnName.Name.O, spec.NewColumnName.Name.O)
		case ast.AlterTableChangeColumn:
			if len(spec.NewColumns) == 1 && spec.OldColumnName != nil && spec.OldColumnName.Name.L != spec.NewColumns[0].Name.Name.L {
				c.report(myRenameColumn, "CHANGE renames column %s.%s to %s, which breaks code that uses the old name.", rel, spec.OldColumnName.Name.O, spec.NewColumns[0].Name.Name.O)
			}
		case ast.AlterTableRenameTable:
			c.report(myRenameTable, "Renaming %s to %s breaks code that uses the old name.", rel, tableName(spec.NewTable))
		}
	}
	if !existing {
		return
	}
	switch {
	case algorithm == ast.AlgorithmTypeCopy:
		c.report(myAlterAlgorithm, "ALTER TABLE %s with ALGORITHM=COPY copies the table and blocks writes until it finishes.", rel)
	case algorithm == ast.AlgorithmTypeDefault:
		c.report(myAlterAlgorithm, "ALTER TABLE %s does not state ALGORITHM; MySQL falls back to copying the table if the change cannot be done in place.", rel)
	case lock == ast.LockTypeShared || lock == ast.LockTypeExclusive:
		c.report(myAlterAlgorithm, "ALTER TABLE %s with LOCK=%s blocks writes until it finishes.", rel, lock)
	}
}
