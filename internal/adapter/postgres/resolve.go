package postgres

import (
	"fmt"
	"slices"
	"strings"

	pg "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/kyosu-1/dbgateway/internal/analysis"
)

// maxViewDepth bounds view expansion (views referencing views).
const maxViewDepth = 16

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

// col is a named column visible in a scope.
type col struct {
	name string
	lin  lineage
}

// item is a FROM-clause entry that can be referenced by name.
type item struct {
	alias  string // reference name (alias, or relation name)
	schema string // relation schema when referenced without alias
	cols   []col
	// open items (functions without a column definition list) accept any
	// column name, deriving it from openLin.
	open    bool
	openLin lineage
}

func (it *item) lookup(name string) (lineage, bool) {
	var out lineage
	found := false
	for _, c := range it.cols {
		if c.name == name {
			out.add(c.lin)
			found = true
		}
	}
	if !found && it.open {
		return it.openLin.asDerived(), true
	}
	return out, found
}

func (it *item) wholeRow() lineage {
	var out lineage
	for _, c := range it.cols {
		out.add(c.lin)
	}
	if it.open {
		out.add(it.openLin)
	}
	return out.asDerived()
}

// cte is a WITH query visible to the query body.
type cte struct {
	name string
	cols []col
}

// scope is the name-resolution context of one query level.
type scope struct {
	parent *scope
	items  []*item // addressable by alias
	// visible are the columns of the top-level FROM entries, used for
	// unqualified references and "*".
	visible []col
	open    []*item // open function items, for unqualified references
	ctes    []*cte
	outputs []col // select-list outputs (ORDER BY / GROUP BY aliases)
}

func (s *scope) findCTE(name string) *cte {
	for sc := s; sc != nil; sc = sc.parent {
		for i := len(sc.ctes) - 1; i >= 0; i-- {
			if sc.ctes[i].name == name {
				return sc.ctes[i]
			}
		}
	}
	return nil
}

// resolver performs name resolution and lineage tracking for one statement.
type resolver struct {
	cat     *analysis.Catalog
	cols    []analysis.ColumnRef
	tables  []analysis.TableRef
	unknown []string
	isWrite bool
	// record is false while expanding view definitions: usages inside a
	// view are not chosen by the caller, so only output lineage matters.
	record    bool
	viewDepth int
}

func newResolver(cat *analysis.Catalog) *resolver {
	if cat == nil {
		cat = analysis.NewCatalog(nil, nil)
	}
	return &resolver{cat: cat, record: true}
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

// recordTable records a RangeVar and returns the resolved relation.
func (r *resolver) recordTable(rv *pg.RangeVar, read, write bool) *analysis.Relation {
	rel := r.cat.Lookup(rv.Schemaname, rv.Relname)
	if rel == nil {
		r.markUnknown("relation %s is not in the catalog", qualify(rv.Schemaname, rv.Relname))
		schema := rv.Schemaname
		if schema == "" {
			schema = "?"
		}
		r.recordTableRef(schema, rv.Relname, read, write)
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

// ---------------------------------------------------------------------------
// Queries

func (r *resolver) selectStmt(s *pg.SelectStmt, parent *scope, targetUsage analysis.Usage) []analysis.OutputColumn {
	return toOutput(r.query(s, parent, targetUsage))
}

// withScope processes a WITH clause and returns the scope holding its CTEs.
func (r *resolver) withScope(w *pg.WithClause, parent *scope) *scope {
	if w == nil {
		return parent
	}
	sc := &scope{parent: parent}
	for _, n := range w.Ctes {
		c := n.GetCommonTableExpr()
		if c == nil {
			continue
		}
		def := &cte{name: c.Ctename}
		if w.Recursive {
			// Seed with the non-recursive term so self-references resolve,
			// then iterate to a fixed point over lineage.
			if sel := c.Ctequery.GetSelectStmt(); sel != nil && sel.Op != pg.SetOperation_SETOP_NONE && sel.Larg != nil {
				def.cols = renameCols(r.query(sel.Larg, sc, analysis.UsageOutput), c.Aliascolnames)
			}
			sc.ctes = append(sc.ctes, def)
			for range 3 {
				def.cols = renameCols(r.cteBody(c.Ctequery, sc), c.Aliascolnames)
			}
			continue
		}
		def.cols = renameCols(r.cteBody(c.Ctequery, sc), c.Aliascolnames)
		sc.ctes = append(sc.ctes, def)
	}
	return sc
}

func (r *resolver) cteBody(n *pg.Node, sc *scope) []col {
	switch x := n.Node.(type) {
	case *pg.Node_SelectStmt:
		return r.query(x.SelectStmt, sc, analysis.UsageOutput)
	case *pg.Node_InsertStmt:
		r.isWrite = true
		return fromOutput(r.insertStmt(x.InsertStmt, sc))
	case *pg.Node_UpdateStmt:
		r.isWrite = true
		return fromOutput(r.updateStmt(x.UpdateStmt, sc))
	case *pg.Node_DeleteStmt:
		r.isWrite = true
		return fromOutput(r.deleteStmt(x.DeleteStmt, sc))
	case *pg.Node_MergeStmt:
		r.isWrite = true
		return fromOutput(r.mergeStmt(x.MergeStmt, sc))
	}
	r.markUnknown("unsupported CTE body %s", nodeName(n))
	return nil
}

func fromOutput(out []analysis.OutputColumn) []col {
	cols := make([]col, 0, len(out))
	for _, o := range out {
		cols = append(cols, col{name: o.Name, lin: lineage{cols: o.Sources, derived: !o.Direct, unknown: o.Unknown}})
	}
	return cols
}

func renameCols(cols []col, names []*pg.Node) []col {
	if len(names) == 0 {
		return cols
	}
	out := slices.Clone(cols)
	for i, n := range names {
		if i < len(out) {
			out[i].name = n.GetString_().GetSval()
		}
	}
	return out
}

// query analyzes a SELECT (including set operations and VALUES) and returns
// its output columns.
func (r *resolver) query(s *pg.SelectStmt, parent *scope, targetUsage analysis.Usage) []col {
	if s == nil {
		return nil
	}
	base := r.withScope(s.WithClause, parent)

	var out []col
	switch {
	case s.Op != pg.SetOperation_SETOP_NONE:
		left := r.query(s.Larg, base, targetUsage)
		right := r.query(s.Rarg, base, targetUsage)
		if len(left) != len(right) {
			r.markUnknown("set operation arms have different column counts")
		}
		out = slices.Clone(left)
		for i := range out {
			if i < len(right) {
				out[i].lin.add(right[i].lin)
			}
		}
		sc := &scope{parent: base, outputs: out}
		r.sortClause(s.SortClause, sc)
		r.expr(s.LimitCount, sc, analysis.UsageOther)
		r.expr(s.LimitOffset, sc, analysis.UsageOther)
		return out
	case len(s.ValuesLists) > 0:
		sc := &scope{parent: base}
		for _, row := range s.ValuesLists {
			items := row.GetList().GetItems()
			for i, e := range items {
				l := r.expr(e, sc, targetUsage)
				if i >= len(out) {
					out = append(out, col{name: fmt.Sprintf("column%d", i+1)})
				}
				out[i].lin.add(l)
			}
		}
		return out
	}

	sc := &scope{parent: base}
	for _, f := range s.FromClause {
		r.fromItem(f, sc, true)
	}
	r.expr(s.WhereClause, sc, analysis.UsageFilter)

	for _, t := range s.TargetList {
		rt := t.GetResTarget()
		if rt == nil {
			continue
		}
		if cr := rt.Val.GetColumnRef(); cr != nil && isStar(cr) {
			expanded := r.star(cr, sc)
			for _, c := range expanded {
				r.use(c.lin, targetUsage)
			}
			out = append(out, expanded...)
			continue
		}
		l := r.expr(rt.Val, sc, targetUsage)
		out = append(out, col{name: targetName(rt), lin: l})
	}
	sc.outputs = out

	// DISTINCT ON (...) behaves like grouping. Plain DISTINCT is a list
	// with a single empty node.
	for _, d := range s.DistinctClause {
		if d != nil && d.Node != nil {
			r.groupExpr(d, sc)
		}
	}
	for _, g := range s.GroupClause {
		r.groupExpr(g, sc)
	}
	r.expr(s.HavingClause, sc, analysis.UsageFilter)
	for _, w := range s.WindowClause {
		r.windowDef(w.GetWindowDef(), sc)
	}
	r.sortClause(s.SortClause, sc)
	r.expr(s.LimitCount, sc, analysis.UsageOther)
	r.expr(s.LimitOffset, sc, analysis.UsageOther)
	return out
}

func isStar(cr *pg.ColumnRef) bool {
	if len(cr.Fields) == 0 {
		return false
	}
	return cr.Fields[len(cr.Fields)-1].GetAStar() != nil
}

// targetName approximates the output column name PostgreSQL would choose.
func targetName(rt *pg.ResTarget) string {
	if rt.Name != "" {
		return rt.Name
	}
	return exprName(rt.Val)
}

func exprName(n *pg.Node) string {
	switch {
	case n == nil:
		return "?column?"
	case n.GetColumnRef() != nil:
		f := n.GetColumnRef().Fields
		if len(f) > 0 {
			if s := f[len(f)-1].GetString_(); s != nil {
				return s.Sval
			}
		}
	case n.GetFuncCall() != nil:
		f := n.GetFuncCall().Funcname
		if len(f) > 0 {
			return f[len(f)-1].GetString_().GetSval()
		}
	case n.GetTypeCast() != nil:
		if name := exprName(n.GetTypeCast().Arg); name != "?column?" {
			return name
		}
	case n.GetCaseExpr() != nil:
		return "case"
	case n.GetCoalesceExpr() != nil:
		return "coalesce"
	}
	return "?column?"
}

// star expands "*" or "t.*".
func (r *resolver) star(cr *pg.ColumnRef, sc *scope) []col {
	if len(cr.Fields) == 1 {
		for _, it := range sc.open {
			if len(it.cols) == 0 {
				r.markUnknown("cannot expand * over a function without a column definition list")
			}
		}
		return slices.Clone(sc.visible)
	}
	names := fieldNames(cr.Fields[:len(cr.Fields)-1])
	it := r.findItem(names, sc)
	if it == nil {
		r.markUnknown("cannot resolve %s.*", strings.Join(names, "."))
		return []col{{name: "?column?", lin: lineage{unknown: true}}}
	}
	if it.open && len(it.cols) == 0 {
		r.markUnknown("cannot expand %s.* over a function without a column definition list", it.alias)
	}
	return slices.Clone(it.cols)
}

func fieldNames(fields []*pg.Node) []string {
	var out []string
	for _, f := range fields {
		if s := f.GetString_(); s != nil {
			out = append(out, s.Sval)
		}
	}
	return out
}

// findItem resolves a qualifier ("t", "s.t" or "db.s.t") to a FROM item,
// searching enclosing scopes for correlated references.
func (r *resolver) findItem(q []string, sc *scope) *item {
	if len(q) == 3 {
		q = q[1:] // ignore the database name
	}
	for s := sc; s != nil; s = s.parent {
		for _, it := range s.items {
			switch len(q) {
			case 1:
				if it.alias == q[0] {
					return it
				}
			case 2:
				if it.schema == q[0] && it.alias == q[1] {
					return it
				}
			}
		}
	}
	return nil
}

// columnRef resolves a column reference to its lineage.
func (r *resolver) columnRef(cr *pg.ColumnRef, sc *scope) lineage {
	names := fieldNames(cr.Fields)
	if len(names) != len(cr.Fields) || len(names) == 0 {
		r.markUnknown("unsupported column reference")
		return lineage{unknown: true}
	}
	if len(names) == 1 {
		name := names[0]
		for s := sc; s != nil; s = s.parent {
			var out lineage
			found := false
			for _, c := range s.visible {
				if c.name == name {
					out.add(c.lin)
					found = true
				}
			}
			if found {
				return out
			}
			// A bare table name is a whole-row reference.
			for _, it := range s.items {
				if it.alias == name {
					return it.wholeRow()
				}
			}
			for _, it := range s.open {
				if l, ok := it.lookup(name); ok {
					return l
				}
			}
		}
		r.markUnknown("cannot resolve column %q", name)
		return lineage{unknown: true}
	}
	it := r.findItem(names[:len(names)-1], sc)
	if it == nil {
		r.markUnknown("cannot resolve column %q", strings.Join(names, "."))
		return lineage{unknown: true}
	}
	if l, ok := it.lookup(names[len(names)-1]); ok {
		return l
	}
	r.markUnknown("cannot resolve column %q", strings.Join(names, "."))
	return lineage{unknown: true}
}

// ---------------------------------------------------------------------------
// FROM clause

// fromItem adds a FROM entry to sc. When top is true its columns become
// visible for unqualified references.
func (r *resolver) fromItem(n *pg.Node, sc *scope, top bool) []col {
	if n == nil {
		return nil
	}
	var it *item
	switch x := n.Node.(type) {
	case *pg.Node_RangeVar:
		it = r.rangeVar(x.RangeVar, sc)
	case *pg.Node_RangeSubselect:
		rs := x.RangeSubselect
		sel := rs.Subquery.GetSelectStmt()
		if sel == nil {
			r.markUnknown("unsupported subquery in FROM")
			it = &item{open: true, openLin: lineage{unknown: true}}
			break
		}
		// Lateral (and, harmlessly, non-lateral) subqueries may see earlier
		// FROM entries.
		cols := r.query(sel, sc, analysis.UsageOutput)
		it = &item{cols: cols}
		applyAlias(it, rs.Alias)
	case *pg.Node_RangeFunction:
		it = r.rangeFunction(x.RangeFunction, sc)
	case *pg.Node_JoinExpr:
		return r.join(x.JoinExpr, sc, top)
	case *pg.Node_RangeTableSample:
		for _, a := range x.RangeTableSample.Args {
			r.expr(a, sc, analysis.UsageOther)
		}
		r.expr(x.RangeTableSample.Repeatable, sc, analysis.UsageOther)
		return r.fromItem(x.RangeTableSample.Relation, sc, top)
	default:
		r.markUnknown("unsupported FROM item %s", nodeName(n))
		it = &item{open: true, openLin: lineage{unknown: true}}
	}
	sc.items = append(sc.items, it)
	if top {
		sc.visible = append(sc.visible, it.cols...)
		if it.open {
			sc.open = append(sc.open, it)
		}
	}
	return it.cols
}

func applyAlias(it *item, a *pg.Alias) {
	if a == nil {
		return
	}
	it.alias = a.Aliasname
	it.schema = ""
	it.cols = renameCols(it.cols, a.Colnames)
}

func (r *resolver) rangeVar(rv *pg.RangeVar, sc *scope) *item {
	// CTE references are unqualified.
	if rv.Schemaname == "" {
		if c := sc.findCTE(rv.Relname); c != nil {
			it := &item{alias: rv.Relname, cols: slices.Clone(c.cols)}
			applyAlias(it, rv.Alias)
			return it
		}
	}
	rel := r.recordTable(rv, true, false)
	it := &item{alias: rv.Relname, schema: rv.Schemaname}
	if rel == nil {
		it.open = true
		it.openLin = lineage{unknown: true}
	} else {
		if it.schema == "" {
			it.schema = rel.Schema
		}
		it.cols = r.relationCols(rel)
	}
	applyAlias(it, rv.Alias)
	return it
}

// relationCols returns the columns of a relation, expanding views to the
// base columns they read.
func (r *resolver) relationCols(rel *analysis.Relation) []col {
	if (rel.Kind == analysis.RelView || rel.Kind == analysis.RelMatView) && rel.Definition != "" {
		return r.expandView(rel)
	}
	cols := make([]col, 0, len(rel.Columns))
	for _, c := range rel.Columns {
		cols = append(cols, col{name: c.Name, lin: lineage{cols: []analysis.ColumnID{{Schema: rel.Schema, Table: rel.Name, Column: c.Name}}}})
	}
	return cols
}

func (r *resolver) expandView(rel *analysis.Relation) []col {
	unknownCols := func() []col {
		cols := make([]col, 0, len(rel.Columns))
		for _, c := range rel.Columns {
			cols = append(cols, col{name: c.Name, lin: lineage{unknown: true}})
		}
		return cols
	}
	if r.viewDepth >= maxViewDepth {
		r.markUnknown("view nesting too deep at %s.%s", rel.Schema, rel.Name)
		return unknownCols()
	}
	tree, err := pg.Parse(rel.Definition)
	if err != nil || len(tree.Stmts) != 1 || tree.Stmts[0].Stmt.GetSelectStmt() == nil {
		r.markUnknown("cannot analyze definition of view %s.%s", rel.Schema, rel.Name)
		return unknownCols()
	}
	saved := r.record
	r.record = false
	r.viewDepth++
	defCols := r.query(tree.Stmts[0].Stmt.GetSelectStmt(), nil, analysis.UsageOutput)
	r.viewDepth--
	r.record = saved
	if len(defCols) != len(rel.Columns) {
		r.markUnknown("view %s.%s column count does not match its definition", rel.Schema, rel.Name)
		return unknownCols()
	}
	cols := make([]col, len(rel.Columns))
	for i, c := range rel.Columns {
		cols[i] = col{name: c.Name, lin: defCols[i].lin}
	}
	return cols
}

// Known set-returning functions that return several columns.
var multiColumnFuncs = map[string][]string{
	"json_each": {"key", "value"}, "jsonb_each": {"key", "value"},
	"json_each_text": {"key", "value"}, "jsonb_each_text": {"key", "value"},
}

func (r *resolver) rangeFunction(rf *pg.RangeFunction, sc *scope) *item {
	var lin lineage
	var names []string
	for _, f := range rf.Functions {
		parts := f.GetList().GetItems()
		if len(parts) == 0 {
			continue
		}
		fc := parts[0]
		l := r.expr(fc, sc, analysis.UsageOther)
		lin.add(l)
		if call := fc.GetFuncCall(); call != nil {
			fname := strings.ToLower(call.Funcname[len(call.Funcname)-1].GetString_().GetSval())
			if cols, ok := multiColumnFuncs[fname]; ok {
				names = append(names, cols...)
			} else {
				names = append(names, fname)
			}
		}
		// Column definition list inside ROWS FROM(... AS (a int, b text)).
		if len(parts) > 1 {
			for _, cd := range parts[1].GetList().GetItems() {
				if d := cd.GetColumnDef(); d != nil {
					names = append(names, d.Colname)
				}
			}
		}
	}
	lin = lin.asDerived()
	it := &item{}
	if len(rf.Coldeflist) > 0 {
		names = names[:0]
		for _, cd := range rf.Coldeflist {
			if d := cd.GetColumnDef(); d != nil {
				names = append(names, d.Colname)
			}
		}
	} else if len(rf.Functions) == 1 && len(names) == 1 && rf.Alias != nil {
		// A single scalar-returning function: its column takes the alias.
		names[0] = rf.Alias.Aliasname
	}
	for _, n := range names {
		it.cols = append(it.cols, col{name: n, lin: lin})
	}
	if rf.Ordinality {
		it.cols = append(it.cols, col{name: "ordinality"})
	}
	if rf.Alias != nil {
		it.alias = rf.Alias.Aliasname
		it.cols = renameCols(it.cols, rf.Alias.Colnames)
	} else if len(names) > 0 {
		it.alias = names[0]
	}
	// Functions of unknown shape also accept any column name, deriving it
	// from the arguments.
	if len(rf.Coldeflist) == 0 && (rf.Alias == nil || len(rf.Alias.Colnames) == 0) {
		it.open = true
	}
	it.openLin = lin
	return it
}

func (r *resolver) join(j *pg.JoinExpr, sc *scope, top bool) []col {
	// Join children are added as addressable items but only the join's
	// combined columns become visible.
	left := r.fromItem(j.Larg, sc, false)
	right := r.fromItem(j.Rarg, sc, false)
	// Open function items inside joins still resolve unqualified names.
	if top {
		for _, it := range sc.items {
			if it.open && !slices.Contains(sc.open, it) {
				sc.open = append(sc.open, it)
			}
		}
	}

	var using []string
	for _, u := range j.UsingClause {
		using = append(using, u.GetString_().GetSval())
	}
	if j.IsNatural {
		for _, lc := range left {
			if slices.ContainsFunc(right, func(rc col) bool { return rc.name == lc.name }) && !slices.Contains(using, lc.name) {
				using = append(using, lc.name)
			}
		}
	}

	var cols []col
	if len(using) == 0 {
		cols = append(slices.Clone(left), right...)
	} else {
		for _, name := range using {
			var l lineage
			for _, c := range left {
				if c.name == name {
					l.add(c.lin)
				}
			}
			for _, c := range right {
				if c.name == name {
					l.add(c.lin)
				}
			}
			// USING compares the columns: a filter usage.
			r.use(l, analysis.UsageFilter)
			cols = append(cols, col{name: name, lin: l})
		}
		for _, c := range left {
			if !slices.Contains(using, c.name) {
				cols = append(cols, c)
			}
		}
		for _, c := range right {
			if !slices.Contains(using, c.name) {
				cols = append(cols, c)
			}
		}
	}

	// ON is evaluated with both sides in scope.
	tmp := &scope{parent: sc.parent, items: sc.items, visible: append(slices.Clone(sc.visible), cols...), open: sc.open, ctes: sc.ctes}
	r.expr(j.Quals, tmp, analysis.UsageFilter)

	if j.Alias != nil {
		it := &item{alias: j.Alias.Aliasname, cols: renameCols(cols, j.Alias.Colnames)}
		sc.items = append(sc.items, it)
		cols = it.cols
	}
	if j.JoinUsingAlias != nil {
		var ucols []col
		for _, c := range cols {
			if slices.Contains(using, c.name) {
				ucols = append(ucols, c)
			}
		}
		sc.items = append(sc.items, &item{alias: j.JoinUsingAlias.Aliasname, cols: ucols})
	}
	if top {
		sc.visible = append(sc.visible, cols...)
	}
	return cols
}

// ---------------------------------------------------------------------------
// Clauses

// groupExpr handles GROUP BY / DISTINCT ON items, which may name input
// columns, output aliases or output positions.
func (r *resolver) groupExpr(n *pg.Node, sc *scope) {
	if l, ok := r.outputRef(n, sc, false); ok {
		r.use(l, analysis.UsageGroup)
		return
	}
	r.expr(n, sc, analysis.UsageGroup)
}

func (r *resolver) sortClause(items []*pg.Node, sc *scope) {
	for _, n := range items {
		sb := n.GetSortBy()
		if sb == nil {
			continue
		}
		if l, ok := r.outputRef(sb.Node, sc, true); ok {
			r.use(l, analysis.UsageOrder)
			continue
		}
		r.expr(sb.Node, sc, analysis.UsageOrder)
	}
}

// outputRef resolves ORDER BY / GROUP BY references to select-list outputs:
// a position ("ORDER BY 2") or a bare output alias. For ORDER BY, output
// names take precedence over input columns; for GROUP BY, input columns
// win.
func (r *resolver) outputRef(n *pg.Node, sc *scope, outputFirst bool) (lineage, bool) {
	if n == nil {
		return lineage{}, false
	}
	if c := n.GetAConst(); c != nil && c.GetIval() != nil {
		pos := int(c.GetIval().Ival)
		if pos >= 1 && pos <= len(sc.outputs) {
			return sc.outputs[pos-1].lin, true
		}
		return lineage{}, false
	}
	cr := n.GetColumnRef()
	if cr == nil || len(cr.Fields) != 1 || cr.Fields[0].GetString_() == nil {
		return lineage{}, false
	}
	name := cr.Fields[0].GetString_().Sval
	if !outputFirst && slices.ContainsFunc(sc.visible, func(c col) bool { return c.name == name }) {
		return lineage{}, false
	}
	var out lineage
	found := false
	for _, o := range sc.outputs {
		if o.name == name {
			out.add(o.lin)
			found = true
		}
	}
	return out, found
}

func (r *resolver) windowDef(w *pg.WindowDef, sc *scope) {
	if w == nil {
		return
	}
	for _, p := range w.PartitionClause {
		r.expr(p, sc, analysis.UsageGroup)
	}
	for _, o := range w.OrderClause {
		if sb := o.GetSortBy(); sb != nil {
			r.expr(sb.Node, sc, analysis.UsageOrder)
		}
	}
	r.expr(w.StartOffset, sc, analysis.UsageOther)
	r.expr(w.EndOffset, sc, analysis.UsageOther)
}

// ---------------------------------------------------------------------------
// Expressions

// expr returns the lineage of an expression and records every column it
// references with usage u.
func (r *resolver) expr(n *pg.Node, sc *scope, u analysis.Usage) lineage {
	if n == nil || n.Node == nil {
		return lineage{}
	}
	return r.exprMsg(nodeMessage(n), sc, u)
}

func (r *resolver) exprMsg(m proto.Message, sc *scope, u analysis.Usage) lineage {
	switch x := m.(type) {
	case nil:
		return lineage{}
	case *pg.Node:
		return r.expr(x, sc, u)
	case *pg.A_Const, *pg.ParamRef, *pg.SQLValueFunction, *pg.A_Star:
		return lineage{}
	case *pg.ColumnRef:
		l := r.columnRef(x, sc)
		r.use(l, u)
		return l
	case *pg.SubLink:
		return r.subLink(x, sc, u)
	case *pg.FuncCall:
		var l lineage
		for _, a := range x.Args {
			l.add(r.expr(a, sc, u))
		}
		// FILTER and aggregate ORDER BY influence the value but are not
		// part of it.
		r.expr(x.AggFilter, sc, analysis.UsageFilter)
		for _, o := range x.AggOrder {
			if sb := o.GetSortBy(); sb != nil {
				r.expr(sb.Node, sc, analysis.UsageOrder)
			}
		}
		r.windowDef(x.Over, sc)
		return l.asDerived()
	case *pg.SelectStmt:
		return colsLineage(r.query(x, sc, u)).asDerived()
	case *pg.CaseExpr:
		var l lineage
		// The tested expression and WHEN conditions choose the result.
		l.add(r.expr(x.Arg, sc, u))
		for _, w := range x.Args {
			if cw := w.GetCaseWhen(); cw != nil {
				l.add(r.expr(cw.Expr, sc, u))
				l.add(r.expr(cw.Result, sc, u))
			}
		}
		l.add(r.expr(x.Defresult, sc, u))
		return l.asDerived()
	}
	// Generic: union of all children.
	var l lineage
	m.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList() && fd.Message() != nil:
			list := v.List()
			for i := 0; i < list.Len(); i++ {
				l.add(r.exprMsg(list.Get(i).Message().Interface(), sc, u))
			}
		case fd.Message() != nil && !fd.IsMap():
			l.add(r.exprMsg(v.Message().Interface(), sc, u))
		}
		return true
	})
	return l.asDerived()
}

func colsLineage(cols []col) lineage {
	var l lineage
	for _, c := range cols {
		l.add(c.lin)
	}
	return l
}

func (r *resolver) subLink(s *pg.SubLink, sc *scope, u analysis.Usage) lineage {
	sel := s.Subselect.GetSelectStmt()
	if sel == nil {
		r.markUnknown("unsupported sublink")
		return lineage{unknown: true}
	}
	var l lineage
	switch s.SubLinkType {
	case pg.SubLinkType_EXISTS_SUBLINK:
		// The subquery's select list does not affect the result.
		r.query(sel, sc, analysis.UsageOther)
		return lineage{}
	case pg.SubLinkType_EXPR_SUBLINK, pg.SubLinkType_ARRAY_SUBLINK, pg.SubLinkType_MULTIEXPR_SUBLINK:
		l.add(colsLineage(r.query(sel, sc, u)))
	default: // ANY, ALL, ROWCOMPARE (IN, = ANY, ...): a comparison
		l.add(r.expr(s.Testexpr, sc, u))
		l.add(colsLineage(r.query(sel, sc, u)))
	}
	return l.asDerived()
}

// ---------------------------------------------------------------------------
// Data-modifying statements (always denied in phase 1, analyzed for policy
// evaluation, tests and the audit log).

func (r *resolver) targetItem(rv *pg.RangeVar, sc *scope) *item {
	rel := r.recordTable(rv, false, true)
	it := &item{alias: rv.Relname, schema: rv.Schemaname}
	if rel == nil {
		it.open = true
		it.openLin = lineage{unknown: true}
	} else {
		if it.schema == "" {
			it.schema = rel.Schema
		}
		it.cols = r.relationCols(rel)
	}
	applyAlias(it, rv.Alias)
	sc.items = append(sc.items, it)
	sc.visible = append(sc.visible, it.cols...)
	if it.open {
		sc.open = append(sc.open, it)
	}
	return it
}

func (r *resolver) writeTargets(it *item, names []string) {
	for _, n := range names {
		if l, ok := it.lookup(n); ok {
			r.use(l, analysis.UsageWrite)
		} else {
			r.markUnknown("cannot resolve target column %q", n)
		}
	}
}

func (r *resolver) returning(list []*pg.Node, sc *scope) []analysis.OutputColumn {
	var out []col
	for _, t := range list {
		rt := t.GetResTarget()
		if rt == nil {
			continue
		}
		if cr := rt.Val.GetColumnRef(); cr != nil && isStar(cr) {
			expanded := r.star(cr, sc)
			for _, c := range expanded {
				r.use(c.lin, analysis.UsageOutput)
			}
			out = append(out, expanded...)
			continue
		}
		out = append(out, col{name: targetName(rt), lin: r.expr(rt.Val, sc, analysis.UsageOutput)})
	}
	return toOutput(out)
}

func (r *resolver) insertStmt(s *pg.InsertStmt, parent *scope) []analysis.OutputColumn {
	base := r.withScope(s.WithClause, parent)
	sc := &scope{parent: base}
	it := r.targetItem(s.Relation, sc)
	var names []string
	for _, c := range s.Cols {
		if rt := c.GetResTarget(); rt != nil {
			names = append(names, rt.Name)
		}
	}
	if len(names) == 0 {
		for _, c := range it.cols {
			names = append(names, c.name)
		}
	}
	r.writeTargets(it, names)
	if sel := s.SelectStmt.GetSelectStmt(); sel != nil {
		r.query(sel, base, analysis.UsageOther)
	}
	if oc := s.OnConflictClause; oc != nil {
		for _, t := range oc.TargetList {
			if rt := t.GetResTarget(); rt != nil {
				r.writeTargets(it, []string{rt.Name})
				r.expr(rt.Val, sc, analysis.UsageOther)
			}
		}
		r.expr(oc.WhereClause, sc, analysis.UsageFilter)
	}
	return r.returning(s.ReturningList, sc)
}

func (r *resolver) updateStmt(s *pg.UpdateStmt, parent *scope) []analysis.OutputColumn {
	base := r.withScope(s.WithClause, parent)
	sc := &scope{parent: base}
	it := r.targetItem(s.Relation, sc)
	for _, f := range s.FromClause {
		r.fromItem(f, sc, true)
	}
	for _, t := range s.TargetList {
		if rt := t.GetResTarget(); rt != nil {
			r.writeTargets(it, []string{rt.Name})
			r.expr(rt.Val, sc, analysis.UsageOther)
		}
	}
	r.expr(s.WhereClause, sc, analysis.UsageFilter)
	return r.returning(s.ReturningList, sc)
}

func (r *resolver) deleteStmt(s *pg.DeleteStmt, parent *scope) []analysis.OutputColumn {
	base := r.withScope(s.WithClause, parent)
	sc := &scope{parent: base}
	r.targetItem(s.Relation, sc)
	for _, f := range s.UsingClause {
		r.fromItem(f, sc, true)
	}
	r.expr(s.WhereClause, sc, analysis.UsageFilter)
	return r.returning(s.ReturningList, sc)
}

func (r *resolver) mergeStmt(s *pg.MergeStmt, parent *scope) []analysis.OutputColumn {
	base := r.withScope(s.WithClause, parent)
	sc := &scope{parent: base}
	it := r.targetItem(s.Relation, sc)
	r.fromItem(s.SourceRelation, sc, true)
	r.expr(s.JoinCondition, sc, analysis.UsageFilter)
	for _, w := range s.MergeWhenClauses {
		mw := w.GetMergeWhenClause()
		if mw == nil {
			continue
		}
		r.expr(mw.Condition, sc, analysis.UsageFilter)
		for _, t := range mw.TargetList {
			if rt := t.GetResTarget(); rt != nil {
				r.writeTargets(it, []string{rt.Name})
				r.expr(rt.Val, sc, analysis.UsageOther)
			}
		}
		for _, v := range mw.Values {
			r.expr(v, sc, analysis.UsageOther)
		}
	}
	return r.returning(s.ReturningList, sc)
}
