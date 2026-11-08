package mysql

import (
	"fmt"
	"slices"
	"strings"

	"github.com/pingcap/tidb/pkg/parser/ast"
	"github.com/pingcap/tidb/pkg/parser/test_driver"

	"github.com/kyosu-1/dbgateway/internal/analysis"
)

// maxViewDepth bounds view expansion (views referencing views).
const maxViewDepth = 16

// maxRecursiveIterations bounds the fixed-point iteration for recursive CTEs.
const maxRecursiveIterations = 32

// systemSchemas hold server metadata. Their views are treated as base
// relations (their definitions are not expanded).
var systemSchemas = []string{"information_schema", "mysql", "performance_schema", "sys"}

func isSystemSchema(s string) bool {
	return slices.ContainsFunc(systemSchemas, func(x string) bool { return strings.EqualFold(x, s) })
}

// lineage is the set of base columns a value is derived from.
type lineage struct {
	cols    []analysis.ColumnID
	derived bool // transformed (not a single unmodified column)
	unknown bool // could not be determined
}

func (l *lineage) add(o lineage) {
	for _, c := range o.cols {
		if !slices.Contains(l.cols, c) {
			l.cols = append(l.cols, c)
		}
	}
	l.derived = l.derived || o.derived
	l.unknown = l.unknown || o.unknown
}

func (l lineage) asDerived() lineage {
	l.derived = true
	return l
}

func (l lineage) equal(o lineage) bool {
	if l.derived != o.derived || l.unknown != o.unknown || len(l.cols) != len(o.cols) {
		return false
	}
	for _, c := range l.cols {
		if !slices.Contains(o.cols, c) {
			return false
		}
	}
	return true
}

// col is a named column visible in a scope. MySQL column names are
// case-insensitive.
type col struct {
	name string
	lin  lineage
}

func colsEqual(a, b []col) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i].name, b[i].name) || !a[i].lin.equal(b[i].lin) {
			return false
		}
	}
	return true
}

// item is a FROM-clause entry that can be referenced by name.
type item struct {
	alias  string // reference name (alias, or table name)
	schema string // database of the table when referenced without alias
	cols   []col
	// open items (relations missing from the catalog) accept any column
	// name with unknown lineage.
	open bool
	// table identifies the underlying relation (for write targets); empty
	// for derived tables and CTEs.
	tschema, tname string
}

func (it *item) lookup(name string) (lineage, bool) {
	var out lineage
	found := false
	for _, c := range it.cols {
		if strings.EqualFold(c.name, name) {
			out.add(c.lin)
			found = true
		}
	}
	if !found && it.open {
		return lineage{unknown: true}, true
	}
	return out, found
}

// cte is a WITH query visible to the query body.
type cte struct {
	name string
	cols []col
}

// scope is the name-resolution context of one query level.
type scope struct {
	parent  *scope
	items   []*item // addressable by alias
	visible []col   // columns of the top-level FROM entries (unqualified references, "*")
	open    bool    // a top-level FROM entry is open
	ctes    []*cte
	outputs []col // select-list outputs
	// aliasRefs makes unqualified names also match select-list aliases
	// (GROUP BY, HAVING and ORDER BY in MySQL).
	aliasRefs bool
}

func (s *scope) findCTE(name string) *cte {
	for sc := s; sc != nil; sc = sc.parent {
		for i := len(sc.ctes) - 1; i >= 0; i-- {
			if strings.EqualFold(sc.ctes[i].name, name) {
				return sc.ctes[i]
			}
		}
	}
	return nil
}

// withAliases returns a copy of s in which select-list aliases resolve.
func (s *scope) withAliases() *scope {
	c := *s
	c.aliasRefs = true
	return &c
}

// resolver performs name resolution and lineage tracking for one statement.
type resolver struct {
	cat           *analysis.Catalog
	defaultSchema string
	cols          []analysis.ColumnRef
	tables        []analysis.TableRef
	unknown       []string
	// record is false while expanding view definitions: usages inside a
	// view are not chosen by the caller, so only output lineage matters.
	record    bool
	viewDepth int
}

func newResolver(cat *analysis.Catalog) *resolver {
	if cat == nil {
		cat = analysis.NewCatalog(nil, nil)
	}
	r := &resolver{cat: cat, record: true}
	if len(cat.SearchPath) > 0 {
		r.defaultSchema = cat.SearchPath[0]
	}
	return r
}

func (r *resolver) markUnknown(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !slices.Contains(r.unknown, msg) {
		r.unknown = append(r.unknown, msg)
	}
}

func (r *resolver) use(l lineage, u analysis.Usage) {
	if !r.record {
		return
	}
	for _, c := range l.cols {
		i := slices.IndexFunc(r.cols, func(x analysis.ColumnRef) bool {
			return x.Schema == c.Schema && x.Table == c.Table && x.Column == c.Column
		})
		if i < 0 {
			r.cols = append(r.cols, analysis.ColumnRef{Schema: c.Schema, Table: c.Table, Column: c.Column})
			i = len(r.cols) - 1
		}
		if !slices.Contains(r.cols[i].Usages, u) {
			r.cols[i].Usages = append(r.cols[i].Usages, u)
		}
	}
}

func (r *resolver) recordTableRef(schema, name string, read, write bool) {
	for i := range r.tables {
		if r.tables[i].Schema == schema && r.tables[i].Name == name {
			r.tables[i].Read = r.tables[i].Read || read
			r.tables[i].Write = r.tables[i].Write || write
			return
		}
	}
	r.tables = append(r.tables, analysis.TableRef{Schema: schema, Name: name, Read: read, Write: write})
}

// recordTable records a table reference and returns the resolved relation.
// Relations named only by case-colliding names are absent from the
// catalog (see Catalog) and therefore unknown here.
func (r *resolver) recordTable(tn *ast.TableName, read, write bool) *analysis.Relation {
	schema, name := tn.Schema.O, tn.Name.O
	rel := r.cat.Lookup(schema, name)
	if rel == nil {
		r.markUnknown("relation %s is not in the catalog", qualify(schema, name))
		if schema == "" {
			schema = r.defaultSchema
		}
		if schema == "" {
			schema = "?"
		}
		r.recordTableRef(schema, name, read, write)
		return nil
	}
	r.recordTableRef(rel.Schema, rel.Name, read, write)
	return rel
}

func (r *resolver) finish(st *analysis.Statement) {
	st.Tables = r.tables
	st.Columns = r.cols
	if len(r.unknown) > 0 {
		st.Unknown = true
		st.UnknownReasons = r.unknown
	}
}

func qualify(schema, name string) string {
	if schema == "" {
		return name
	}
	return schema + "." + name
}

func toOutput(cols []col) []analysis.OutputColumn {
	out := make([]analysis.OutputColumn, 0, len(cols))
	for _, c := range cols {
		out = append(out, analysis.OutputColumn{
			Name:    c.name,
			Sources: c.lin.cols,
			Direct:  !c.lin.derived && !c.lin.unknown && len(c.lin.cols) == 1,
			Unknown: c.lin.unknown,
		})
	}
	return out
}

func colsLineage(cols []col) lineage {
	var l lineage
	for _, c := range cols {
		l.add(c.lin)
	}
	return l
}

func renameCols(cols []col, names []ast.CIStr) []col {
	if len(names) == 0 {
		return cols
	}
	out := slices.Clone(cols)
	for i, n := range names {
		if i < len(out) {
			out[i].name = n.O
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Queries

// query analyzes a query expression (SELECT, set operation, VALUES, TABLE)
// and returns its output columns.
func (r *resolver) query(n ast.Node, parent *scope, u analysis.Usage) []col {
	switch x := n.(type) {
	case *ast.SelectStmt:
		return r.selectStmt(x, parent, u)
	case *ast.SetOprStmt:
		base := r.withScope(x.With, parent)
		out := r.setOprList(x.SelectList, base, u)
		sc := &scope{parent: base, outputs: out}
		r.orderBy(x.OrderBy, sc)
		r.limit(x.Limit, sc)
		return out
	case *ast.SetOprSelectList:
		return r.setOprList(x, parent, u)
	case nil:
		return nil
	}
	r.markUnknown("unsupported query %s", stmtName(n))
	return []col{{name: "?column?", lin: lineage{unknown: true}}}
}

func (r *resolver) setOprList(l *ast.SetOprSelectList, parent *scope, u analysis.Usage) []col {
	if l == nil {
		return nil
	}
	base := r.withScope(l.With, parent)
	var out []col
	for i, arm := range l.Selects {
		cols := r.query(arm, base, u)
		if i == 0 {
			out = slices.Clone(cols)
			continue
		}
		if len(cols) != len(out) {
			r.markUnknown("set operation arms have different column counts")
		}
		for j := range out {
			if j < len(cols) {
				out[j].lin.add(cols[j].lin)
			}
		}
	}
	sc := &scope{parent: base, outputs: out}
	r.orderBy(l.OrderBy, sc)
	r.limit(l.Limit, sc)
	return out
}

// withScope processes a WITH clause and returns the scope holding its CTEs.
func (r *resolver) withScope(w *ast.WithClause, parent *scope) *scope {
	if w == nil {
		return parent
	}
	sc := &scope{parent: parent}
	for _, c := range w.CTEs {
		def := &cte{name: c.Name.O}
		var body ast.ResultSetNode
		if c.Query != nil {
			body = c.Query.Query
		}
		if w.IsRecursive {
			// Seed with the first (non-recursive) arm so self-references
			// resolve, then iterate to a fixed point over lineage.
			if so, ok := body.(*ast.SetOprStmt); ok && so.SelectList != nil && len(so.SelectList.Selects) > 0 {
				def.cols = renameCols(r.query(so.SelectList.Selects[0], sc, analysis.UsageOutput), c.ColNameList)
			}
			sc.ctes = append(sc.ctes, def)
			converged := false
			for range maxRecursiveIterations {
				next := renameCols(r.query(body, sc, analysis.UsageOutput), c.ColNameList)
				if colsEqual(next, def.cols) {
					converged = true
					break
				}
				def.cols = next
			}
			if !converged {
				r.markUnknown("recursive CTE %s did not converge", c.Name.O)
				for i := range def.cols {
					def.cols[i].lin.unknown = true
				}
			}
			continue
		}
		def.cols = renameCols(r.query(body, sc, analysis.UsageOutput), c.ColNameList)
		sc.ctes = append(sc.ctes, def)
	}
	return sc
}

func (r *resolver) selectStmt(s *ast.SelectStmt, parent *scope, u analysis.Usage) []col {
	base := r.withScope(s.With, parent)
	sc := &scope{parent: base}
	var out []col

	switch s.Kind {
	case ast.SelectStmtKindValues:
		for _, row := range s.Lists {
			for i, e := range row.Values {
				l := r.expr(e, sc, u)
				if i >= len(out) {
					out = append(out, col{name: fmt.Sprintf("column_%d", i)})
				}
				out[i].lin.add(l)
			}
		}
		sc.outputs = out
		r.orderBy(s.OrderBy, sc)
		r.limit(s.Limit, sc)
		return out
	case ast.SelectStmtKindTable:
		if s.From != nil {
			r.fromItem(s.From.TableRefs, sc, true)
		}
		out = r.starAll(sc)
		for _, c := range out {
			r.use(c.lin, u)
		}
		sc.outputs = out
		r.orderBy(s.OrderBy, sc)
		r.limit(s.Limit, sc)
		return out
	}

	if s.From != nil {
		r.fromItem(s.From.TableRefs, sc, true)
	}
	r.expr(s.Where, sc, analysis.UsageFilter)

	if s.Fields != nil {
		for _, f := range s.Fields.Fields {
			if f.Auxiliary {
				continue
			}
			if f.WildCard != nil {
				expanded := r.star(f.WildCard, sc)
				for _, c := range expanded {
					r.use(c.lin, u)
				}
				out = append(out, expanded...)
				continue
			}
			l := r.expr(f.Expr, sc, u)
			out = append(out, col{name: fieldName(f), lin: l})
		}
	}
	sc.outputs = out

	if s.GroupBy != nil {
		for _, it := range s.GroupBy.Items {
			r.byItem(it, sc, analysis.UsageGroup)
		}
	}
	if s.Having != nil {
		r.expr(s.Having.Expr, sc.withAliases(), analysis.UsageFilter)
	}
	for i := range s.WindowSpecs {
		r.windowSpec(&s.WindowSpecs[i], sc)
	}
	r.orderBy(s.OrderBy, sc)
	r.limit(s.Limit, sc)
	return out
}

// fieldName approximates the output column name MySQL would choose.
func fieldName(f *ast.SelectField) string {
	if f.AsName.O != "" {
		return f.AsName.O
	}
	if cn, ok := unparen(f.Expr).(*ast.ColumnNameExpr); ok && cn.Name != nil {
		return cn.Name.Name.O
	}
	if t := strings.TrimSpace(f.Text()); t != "" {
		return t
	}
	return "?column?"
}

func unparen(e ast.ExprNode) ast.ExprNode {
	for {
		p, ok := e.(*ast.ParenthesesExpr)
		if !ok {
			return e
		}
		e = p.Expr
	}
}

// starAll expands an unqualified "*".
func (r *resolver) starAll(sc *scope) []col {
	if sc.open {
		r.markUnknown("cannot expand * over a relation missing from the catalog")
		return append(slices.Clone(sc.visible), col{name: "?column?", lin: lineage{unknown: true}})
	}
	return slices.Clone(sc.visible)
}

// star expands "*", "t.*" or "db.t.*".
func (r *resolver) star(w *ast.WildCardField, sc *scope) []col {
	if w.Table.O == "" {
		return r.starAll(sc)
	}
	it := r.findItem(w.Schema.O, w.Table.O, sc)
	if it == nil {
		r.markUnknown("cannot resolve %s.*", qualify(w.Schema.O, w.Table.O))
		return []col{{name: "?column?", lin: lineage{unknown: true}}}
	}
	if it.open {
		r.markUnknown("cannot expand %s.* over a relation missing from the catalog", it.alias)
		return append(slices.Clone(it.cols), col{name: "?column?", lin: lineage{unknown: true}})
	}
	return slices.Clone(it.cols)
}

// findItem resolves a qualifier ("t" or "db.t") to a FROM item, searching
// enclosing scopes for correlated references. An exact-case alias match is
// preferred; several case-insensitive matches without an exact one are
// ambiguous (MySQL compares aliases case-sensitively on most platforms).
func (r *resolver) findItem(schema, table string, sc *scope) *item {
	for s := sc; s != nil; s = s.parent {
		var exact, folded []*item
		for _, it := range s.items {
			if schema != "" && (it.schema == "" || !strings.EqualFold(it.schema, schema)) {
				continue
			}
			switch {
			case it.alias == table:
				exact = append(exact, it)
			case strings.EqualFold(it.alias, table):
				folded = append(folded, it)
			}
		}
		switch {
		case len(exact) == 1:
			return exact[0]
		case len(exact) > 1 || len(folded) > 1:
			r.markUnknown("ambiguous table reference %s", qualify(schema, table))
			return nil
		case len(folded) == 1:
			return folded[0]
		}
	}
	return nil
}

// columnRef resolves a column reference to its lineage.
func (r *resolver) columnRef(cn *ast.ColumnName, sc *scope) lineage {
	if cn == nil {
		return lineage{unknown: true}
	}
	name := cn.Name.O
	if cn.Table.O == "" {
		for s := sc; s != nil; s = s.parent {
			var out lineage
			found := false
			for _, c := range s.visible {
				if strings.EqualFold(c.name, name) {
					out.add(c.lin)
					found = true
				}
			}
			if s.aliasRefs {
				// GROUP BY / HAVING / ORDER BY may name select-list aliases.
				// MySQL prefers one or the other depending on the clause;
				// taking both over-reports usage, which is the safe side.
				for _, c := range s.outputs {
					if strings.EqualFold(c.name, name) {
						out.add(c.lin)
						found = true
					}
				}
			}
			if found {
				return out
			}
			if s.open {
				return lineage{unknown: true}
			}
		}
		r.markUnknown("cannot resolve column %q", name)
		return lineage{unknown: true}
	}
	it := r.findItem(cn.Schema.O, cn.Table.O, sc)
	if it == nil {
		r.markUnknown("cannot resolve column %q", qualify(qualify(cn.Schema.O, cn.Table.O), name))
		return lineage{unknown: true}
	}
	if l, ok := it.lookup(name); ok {
		return l
	}
	r.markUnknown("cannot resolve column %q", qualify(qualify(cn.Schema.O, cn.Table.O), name))
	return lineage{unknown: true}
}

// ---------------------------------------------------------------------------
// FROM clause

// fromItem adds a FROM entry to sc. When top is true its columns become
// visible for unqualified references.
func (r *resolver) fromItem(n ast.ResultSetNode, sc *scope, top bool) []col {
	var it *item
	switch x := n.(type) {
	case nil:
		return nil
	case *ast.Join:
		if x.Right == nil {
			return r.fromItem(x.Left, sc, top)
		}
		return r.join(x, sc, top)
	case *ast.TableSource:
		switch src := x.Source.(type) {
		case *ast.TableName:
			it = r.tableName(src, sc)
		case *ast.SelectStmt, *ast.SetOprStmt:
			// Derived tables (LATERAL or not) are resolved with the
			// enclosing scope; MySQL itself rejects illegal references.
			it = &item{cols: r.query(src, sc, analysis.UsageOutput)}
		case *ast.Join:
			return r.fromItem(src, sc, top)
		default:
			r.markUnknown("unsupported FROM item %s", stmtName(x.Source))
			it = &item{open: true}
		}
		if x.AsName.O != "" {
			it.alias = x.AsName.O
			it.schema = ""
		}
		it.cols = renameCols(it.cols, x.ColumnNames)
	case *ast.TableName:
		it = r.tableName(x, sc)
	default:
		r.markUnknown("unsupported FROM item %s", stmtName(n))
		it = &item{open: true}
	}
	sc.items = append(sc.items, it)
	if top {
		sc.visible = append(sc.visible, it.cols...)
		sc.open = sc.open || it.open
	}
	return it.cols
}

func (r *resolver) tableName(tn *ast.TableName, sc *scope) *item {
	// CTE references are unqualified.
	if tn.Schema.O == "" {
		if c := sc.findCTE(tn.Name.O); c != nil {
			return &item{alias: tn.Name.O, cols: slices.Clone(c.cols)}
		}
	}
	rel := r.recordTable(tn, true, false)
	it := &item{alias: tn.Name.O, schema: tn.Schema.O, tschema: tn.Schema.O, tname: tn.Name.O}
	if rel == nil {
		it.open = true
		if it.tschema == "" {
			it.tschema = r.defaultSchema
		}
		return it
	}
	if it.schema == "" {
		it.schema = rel.Schema
	}
	it.tschema, it.tname = rel.Schema, rel.Name
	it.cols = r.relationCols(rel)
	return it
}

// relationCols returns the columns of a relation, expanding views to the
// base columns they read.
func (r *resolver) relationCols(rel *analysis.Relation) []col {
	if rel.Kind == analysis.RelView && !isSystemSchema(rel.Schema) {
		if rel.Definition == "" {
			r.markUnknown("definition of view %s.%s is not visible (grant SHOW VIEW to the read user)", rel.Schema, rel.Name)
			return unknownCols(rel)
		}
		return r.expandView(rel)
	}
	cols := make([]col, 0, len(rel.Columns))
	for _, c := range rel.Columns {
		cols = append(cols, col{name: c.Name, lin: lineage{cols: []analysis.ColumnID{{Schema: rel.Schema, Table: rel.Name, Column: c.Name}}}})
	}
	return cols
}

func unknownCols(rel *analysis.Relation) []col {
	cols := make([]col, 0, len(rel.Columns))
	for _, c := range rel.Columns {
		cols = append(cols, col{name: c.Name, lin: lineage{unknown: true}})
	}
	return cols
}

func (r *resolver) expandView(rel *analysis.Relation) []col {
	if r.viewDepth >= maxViewDepth {
		r.markUnknown("view nesting too deep at %s.%s", rel.Schema, rel.Name)
		return unknownCols(rel)
	}
	stmts, err := viewParsers.parse(rel.Definition)
	if err != nil || len(stmts) != 1 {
		r.markUnknown("cannot analyze definition of view %s.%s", rel.Schema, rel.Name)
		return unknownCols(rel)
	}
	var q ast.Node
	switch s := stmts[0].(type) {
	case *ast.SelectStmt, *ast.SetOprStmt:
		q = s
	default:
		r.markUnknown("cannot analyze definition of view %s.%s", rel.Schema, rel.Name)
		return unknownCols(rel)
	}
	saved := r.record
	r.record = false
	r.viewDepth++
	defCols := r.query(q, nil, analysis.UsageOutput)
	r.viewDepth--
	r.record = saved
	if len(defCols) != len(rel.Columns) {
		r.markUnknown("view %s.%s column count does not match its definition", rel.Schema, rel.Name)
		return unknownCols(rel)
	}
	cols := make([]col, len(rel.Columns))
	for i, c := range rel.Columns {
		cols[i] = col{name: c.Name, lin: defCols[i].lin}
	}
	return cols
}

func (r *resolver) join(j *ast.Join, sc *scope, top bool) []col {
	// Join children are added as addressable items but only the join's
	// combined columns become visible.
	left := r.fromItem(j.Left, sc, false)
	right := r.fromItem(j.Right, sc, false)
	open := slices.ContainsFunc(sc.items, func(it *item) bool { return it.open })

	var using []string
	for _, u := range j.Using {
		using = append(using, u.Name.O)
	}
	hasUsing := len(using) > 0 || j.NaturalJoin

	// For NATURAL and USING joins MySQL lists the coalesced columns first
	// (in the order of the first table), then the remaining columns of the
	// first table, then those of the second. For RIGHT JOIN the right table
	// is the first one.
	first, second := left, right
	if j.Tp == ast.RightJoin {
		first, second = right, left
	}
	inBoth := func(name string) bool {
		return slices.ContainsFunc(first, func(c col) bool { return strings.EqualFold(c.name, name) }) &&
			slices.ContainsFunc(second, func(c col) bool { return strings.EqualFold(c.name, name) })
	}
	isUsing := func(name string) bool {
		return slices.ContainsFunc(using, func(u string) bool { return strings.EqualFold(u, name) })
	}
	if j.NaturalJoin {
		for _, c := range first {
			if inBoth(c.name) && !isUsing(c.name) {
				using = append(using, c.name)
			}
		}
		if open {
			r.markUnknown("cannot resolve NATURAL JOIN over a relation missing from the catalog")
		}
	}

	var cols []col
	if !hasUsing {
		cols = append(slices.Clone(left), right...)
	} else {
		for _, name := range using {
			if !inBoth(name) && !open {
				r.markUnknown("cannot resolve USING column %q", name)
			}
		}
		var coalesced []col
		for _, c := range first {
			if !isUsing(c.name) || slices.ContainsFunc(coalesced, func(x col) bool { return strings.EqualFold(x.name, c.name) }) {
				continue
			}
			var l lineage
			for _, side := range [][]col{first, second} {
				for _, x := range side {
					if strings.EqualFold(x.name, c.name) {
						l.add(x.lin)
					}
				}
			}
			// USING compares the columns: a filter usage.
			r.use(l, analysis.UsageFilter)
			coalesced = append(coalesced, col{name: c.name, lin: l})
		}
		cols = coalesced
		for _, side := range [][]col{first, second} {
			for _, c := range side {
				if !isUsing(c.name) {
					cols = append(cols, c)
				}
			}
		}
	}

	if j.On != nil {
		// ON is evaluated with both sides in scope.
		tmp := &scope{parent: sc.parent, items: sc.items, visible: append(slices.Clone(sc.visible), cols...), open: sc.open || open, ctes: sc.ctes}
		r.expr(j.On.Expr, tmp, analysis.UsageFilter)
	}
	if top {
		sc.visible = append(sc.visible, cols...)
		sc.open = sc.open || open
	}
	return cols
}

// ---------------------------------------------------------------------------
// Clauses

// byItem handles GROUP BY / ORDER BY items, which may name input columns,
// select-list aliases or positions.
func (r *resolver) byItem(it *ast.ByItem, sc *scope, u analysis.Usage) {
	if it == nil {
		return
	}
	if pos, ok := it.Expr.(*ast.PositionExpr); ok {
		if pos.P != nil || pos.N < 1 || pos.N > len(sc.outputs) {
			r.markUnknown("cannot resolve position %d", pos.N)
			return
		}
		r.use(sc.outputs[pos.N-1].lin, u)
		return
	}
	r.expr(it.Expr, sc.withAliases(), u)
}

func (r *resolver) orderBy(o *ast.OrderByClause, sc *scope) {
	if o == nil {
		return
	}
	for _, it := range o.Items {
		r.byItem(it, sc, analysis.UsageOrder)
	}
}

func (r *resolver) limit(l *ast.Limit, sc *scope) {
	if l == nil {
		return
	}
	r.expr(l.Count, sc, analysis.UsageOther)
	r.expr(l.Offset, sc, analysis.UsageOther)
}

func (r *resolver) windowSpec(w *ast.WindowSpec, sc *scope) {
	if w == nil {
		return
	}
	if w.PartitionBy != nil {
		for _, it := range w.PartitionBy.Items {
			r.expr(it.Expr, sc, analysis.UsageGroup)
		}
	}
	if w.OrderBy != nil {
		for _, it := range w.OrderBy.Items {
			r.expr(it.Expr, sc, analysis.UsageOrder)
		}
	}
	if w.Frame != nil {
		r.expr(w.Frame.Extent.Start.Expr, sc, analysis.UsageOther)
		r.expr(w.Frame.Extent.End.Expr, sc, analysis.UsageOther)
	}
}

// ---------------------------------------------------------------------------
// Expressions

// expr returns the lineage of an expression and records every column it
// references with usage u.
func (r *resolver) expr(n ast.ExprNode, sc *scope, u analysis.Usage) lineage {
	switch x := n.(type) {
	case nil:
		return lineage{}
	case *test_driver.ValueExpr, *ast.TimeUnitExpr, *ast.TrimDirectionExpr, *ast.GetFormatSelectorExpr, *ast.MaxValueExpr:
		return lineage{}
	case *ast.DefaultExpr:
		// DEFAULT(col) is the column's default value, not row data.
		return lineage{derived: true}
	case *ast.ColumnNameExpr:
		l := r.columnRef(x.Name, sc)
		r.use(l, u)
		return l
	case *ast.ParenthesesExpr:
		return r.expr(x.Expr, sc, u)
	case *ast.SubqueryExpr:
		return colsLineage(r.query(x.Query, sc, u)).asDerived()
	case *ast.ExistsSubqueryExpr:
		// The subquery's select list does not affect the result.
		if sq, ok := x.Sel.(*ast.SubqueryExpr); ok {
			r.query(sq.Query, sc, analysis.UsageOther)
		} else {
			r.expr(x.Sel, sc, analysis.UsageOther)
		}
		return lineage{derived: true}
	case *ast.CompareSubqueryExpr:
		l := r.expr(x.L, sc, u)
		l.add(r.expr(x.R, sc, u))
		return l.asDerived()
	case *ast.PatternInExpr:
		l := r.expr(x.Expr, sc, u)
		for _, e := range x.List {
			l.add(r.expr(e, sc, u))
		}
		l.add(r.expr(x.Sel, sc, u))
		return l.asDerived()
	case *ast.FuncCallExpr:
		var l lineage
		for _, a := range x.Args {
			l.add(r.expr(a, sc, u))
		}
		return l.asDerived()
	case *ast.FuncCastExpr:
		return r.expr(x.Expr, sc, u).asDerived()
	case *ast.SetCollationExpr:
		return r.expr(x.Expr, sc, u).asDerived()
	case *ast.AggregateFuncExpr:
		var l lineage
		for _, a := range x.Args {
			l.add(r.expr(a, sc, u))
		}
		// Aggregate ORDER BY influences the value but is not part of it.
		if x.Order != nil {
			for _, it := range x.Order.Items {
				r.expr(it.Expr, sc, analysis.UsageOrder)
			}
		}
		return l.asDerived()
	case *ast.WindowFuncExpr:
		var l lineage
		for _, a := range x.Args {
			l.add(r.expr(a, sc, u))
		}
		r.windowSpec(&x.Spec, sc)
		return l.asDerived()
	case *ast.CaseExpr:
		// The tested expression and WHEN conditions choose the result.
		l := r.expr(x.Value, sc, u)
		for _, w := range x.WhenClauses {
			l.add(r.expr(w.Expr, sc, u))
			l.add(r.expr(w.Result, sc, u))
		}
		l.add(r.expr(x.ElseClause, sc, u))
		return l.asDerived()
	case *ast.BinaryOperationExpr:
		l := r.expr(x.L, sc, u)
		l.add(r.expr(x.R, sc, u))
		return l.asDerived()
	case *ast.UnaryOperationExpr:
		return r.expr(x.V, sc, u).asDerived()
	case *ast.BetweenExpr:
		l := r.expr(x.Expr, sc, u)
		l.add(r.expr(x.Left, sc, u))
		l.add(r.expr(x.Right, sc, u))
		return l.asDerived()
	case *ast.IsNullExpr:
		return r.expr(x.Expr, sc, u).asDerived()
	case *ast.IsTruthExpr:
		return r.expr(x.Expr, sc, u).asDerived()
	case *ast.PatternLikeOrIlikeExpr:
		l := r.expr(x.Expr, sc, u)
		l.add(r.expr(x.Pattern, sc, u))
		return l.asDerived()
	case *ast.PatternRegexpExpr:
		l := r.expr(x.Expr, sc, u)
		l.add(r.expr(x.Pattern, sc, u))
		return l.asDerived()
	case *ast.RowExpr:
		var l lineage
		for _, v := range x.Values {
			l.add(r.expr(v, sc, u))
		}
		return l.asDerived()
	case *ast.MatchAgainst:
		var l lineage
		for _, cn := range x.ColumnNames {
			cl := r.columnRef(cn, sc)
			r.use(cl, u)
			l.add(cl)
		}
		l.add(r.expr(x.Against, sc, u))
		return l.asDerived()
	case *ast.ValuesExpr:
		// VALUES(col) in INSERT ... ON DUPLICATE KEY UPDATE.
		if x.Column == nil {
			return lineage{derived: true}
		}
		return r.expr(x.Column, sc, u).asDerived()
	}
	r.markUnknown("unsupported expression %s", stmtName(n))
	return lineage{unknown: true}
}

// ---------------------------------------------------------------------------
// Data-modifying statements (executed only after approval; analyzed for
// policy evaluation, tests and the audit log).

// singleTarget returns the table of a FROM clause that names exactly one
// table (single-table UPDATE / DELETE, INSERT target).
func singleTarget(refs *ast.TableRefsClause) *ast.TableName {
	if refs == nil || refs.TableRefs == nil || refs.TableRefs.Right != nil {
		return nil
	}
	var n ast.ResultSetNode = refs.TableRefs.Left
	if ts, ok := n.(*ast.TableSource); ok {
		n = ts.Source
	}
	tn, _ := n.(*ast.TableName)
	return tn
}

// markWritten records the relation behind it as written.
func (r *resolver) markWritten(it *item) {
	if it == nil || it.tname == "" {
		r.markUnknown("cannot determine the written table")
		return
	}
	r.recordTableRef(it.tschema, it.tname, false, true)
}

// itemOf returns the FROM item that provides the column named by cn.
func (r *resolver) itemOf(cn *ast.ColumnName, sc *scope) *item {
	if cn.Table.O != "" {
		return r.findItem(cn.Schema.O, cn.Table.O, sc)
	}
	var hits, open []*item
	for _, it := range sc.items {
		if it.open {
			open = append(open, it)
			continue
		}
		if _, ok := it.lookup(cn.Name.O); ok {
			hits = append(hits, it)
		}
	}
	switch {
	case len(hits) == 1:
		return hits[0]
	case len(hits) == 0 && len(open) == 1:
		return open[0]
	}
	return nil // missing or ambiguous
}

func (r *resolver) writeTarget(it *item, cn *ast.ColumnName) {
	if it == nil {
		r.markUnknown("cannot resolve target column %q", cn.Name.O)
		return
	}
	if l, ok := it.lookup(cn.Name.O); ok {
		r.use(l, analysis.UsageWrite)
	} else {
		r.markUnknown("cannot resolve target column %q", cn.Name.O)
	}
}

func (r *resolver) insertStmt(s *ast.InsertStmt) []analysis.OutputColumn {
	sc := &scope{}
	tn := singleTarget(s.Table)
	if tn == nil {
		r.markUnknown("unsupported INSERT target")
		return nil
	}
	rel := r.recordTable(tn, false, true)
	it := &item{alias: tn.Name.O, schema: tn.Schema.O, tschema: tn.Schema.O, tname: tn.Name.O}
	if rel == nil {
		it.open = true
	} else {
		it.schema = rel.Schema
		it.cols = r.relationCols(rel)
	}
	sc.items = append(sc.items, it)
	sc.visible = append(sc.visible, it.cols...)
	sc.open = it.open

	if len(s.Columns) > 0 {
		for _, c := range s.Columns {
			r.writeTarget(it, c)
		}
	} else {
		for _, c := range it.cols {
			r.use(c.lin, analysis.UsageWrite)
		}
		if it.open {
			r.markUnknown("cannot resolve the columns of %s", tn.Name.O)
		}
	}
	for _, row := range s.Lists {
		for _, e := range row {
			r.expr(e, sc, analysis.UsageOther)
		}
	}
	if s.Select != nil {
		r.query(s.Select, nil, analysis.UsageOther)
	}
	if s.RowAlias.O != "" {
		alias := &item{alias: s.RowAlias.O, cols: renameCols(it.cols, s.ColumnAliases)}
		sc.items = append(sc.items, alias)
	}
	for _, a := range s.OnDuplicate {
		r.writeTarget(it, a.Column)
		r.expr(a.Expr, sc, analysis.UsageOther)
	}
	return r.returning(s.Returning, sc)
}

func (r *resolver) updateStmt(s *ast.UpdateStmt) []analysis.OutputColumn {
	base := r.withScope(s.With, nil)
	sc := &scope{parent: base}
	single := singleTarget(s.TableRefs)
	if s.TableRefs != nil {
		r.fromItem(s.TableRefs.TableRefs, sc, true)
	}
	for _, a := range s.List {
		it := r.itemOf(a.Column, sc)
		r.writeTarget(it, a.Column)
		r.markWritten(it)
		r.expr(a.Expr, sc, analysis.UsageOther)
	}
	r.expr(s.Where, sc, analysis.UsageFilter)
	r.orderBy(s.Order, sc)
	r.limit(s.Limit, sc)
	if single != nil {
		r.targetOnly(sc)
	}
	return r.returning(s.Returning, sc)
}

func (r *resolver) deleteStmt(s *ast.DeleteStmt) []analysis.OutputColumn {
	base := r.withScope(s.With, nil)
	sc := &scope{parent: base}
	single := singleTarget(s.TableRefs)
	if s.TableRefs != nil {
		r.fromItem(s.TableRefs.TableRefs, sc, true)
	}
	if s.IsMultiTable && s.Tables != nil {
		for _, tn := range s.Tables.Tables {
			r.markWritten(r.findItem(tn.Schema.O, tn.Name.O, sc))
		}
	} else if len(sc.items) == 1 {
		r.markWritten(sc.items[0])
	} else {
		r.markUnknown("cannot determine the written table")
	}
	r.expr(s.Where, sc, analysis.UsageFilter)
	r.orderBy(s.Order, sc)
	r.limit(s.Limit, sc)
	if single != nil {
		r.targetOnly(sc)
	}
	return r.returning(s.Returning, sc)
}

// targetOnly marks the single target of an UPDATE / DELETE as written but
// not read, matching how the PostgreSQL adapter reports write targets.
func (r *resolver) targetOnly(sc *scope) {
	if len(sc.items) != 1 || sc.items[0].tname == "" {
		return
	}
	it := sc.items[0]
	for i := range r.tables {
		if r.tables[i].Schema == it.tschema && r.tables[i].Name == it.tname && r.tables[i].Write {
			r.tables[i].Read = false
		}
	}
}

func (r *resolver) returning(fields []*ast.SelectField, sc *scope) []analysis.OutputColumn {
	if len(fields) == 0 {
		return nil
	}
	var out []col
	for _, f := range fields {
		if f.WildCard != nil {
			expanded := r.star(f.WildCard, sc)
			for _, c := range expanded {
				r.use(c.lin, analysis.UsageOutput)
			}
			out = append(out, expanded...)
			continue
		}
		out = append(out, col{name: fieldName(f), lin: r.expr(f.Expr, sc, analysis.UsageOutput)})
	}
	return toOutput(out)
}
