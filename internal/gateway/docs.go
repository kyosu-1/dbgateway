package gateway

import (
	"context"
	"slices"
	"strings"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/config"
)

// Example is a configured example query (databases[].docs.examples).
type Example struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	SQL         string `json:"sql"`
	// Tables are the relations the query references (schema.name), as
	// resolved by the database's SQL analyzer.
	Tables []string `json:"tables,omitempty"`
}

// exampleTables is the analysis result of one example query.
type exampleTables struct {
	tables []string // lower-case schema.name, for matching
	shown  []string // schema.name as resolved, for display
}

// tableDocs indexes the configured table docs by lower-case schema.name,
// with column descriptions by lower-case column name.
type tableDocs map[string]tableDoc

type tableDoc struct {
	description string
	columns     map[string]string
}

func indexDocs(d *config.DatabaseDocs) tableDocs {
	idx := tableDocs{}
	for k, t := range d.Tables {
		td := tableDoc{description: strings.TrimSpace(t.Description), columns: map[string]string{}}
		for c, desc := range t.Columns {
			td.columns[strings.ToLower(c)] = strings.TrimSpace(desc)
		}
		idx[strings.ToLower(k)] = td
	}
	return idx
}

// apply fills the curated descriptions of objects and their columns.
// Database comments are kept as they are: comment is what the database
// says, description is what the configuration says.
func (idx tableDocs) apply(objs []analysis.Object) {
	if len(idx) == 0 {
		return
	}
	for i := range objs {
		o := &objs[i]
		td, ok := idx[strings.ToLower(o.Schema+"."+o.Name)]
		if !ok {
			continue
		}
		o.Description = td.description
		for j := range o.Columns {
			o.Columns[j].Description = td.columns[strings.ToLower(o.Columns[j].Name)]
		}
	}
}

// examplesFor returns the configured examples that reference one of objs.
//
// Which tables an example references is decided by the database's own SQL
// analyzer against the current catalog, the same way execute_sql resolves
// names (search_path, aliases, CTEs, views). An example that cannot be
// analyzed (a typo, a table that no longer exists, a statement the gateway
// refuses) references nothing and is therefore never shown; a warning is
// logged once so that the configuration can be fixed.
func (g *Gateway) examplesFor(ctx context.Context, d *database, objs []analysis.Object) []Example {
	exs := d.cfg.Docs.Examples
	if len(exs) == 0 || len(objs) == 0 {
		return nil
	}
	refs := g.exampleRefs(ctx, d)
	if refs == nil {
		return nil
	}
	returned := map[string]bool{}
	for _, o := range objs {
		returned[strings.ToLower(o.Schema+"."+o.Name)] = true
	}
	var out []Example
	for i, ex := range exs {
		if !slices.ContainsFunc(refs[i].tables, func(t string) bool { return returned[t] }) {
			continue
		}
		out = append(out, Example{Title: strings.TrimSpace(ex.Title), Description: strings.TrimSpace(ex.Description),
			SQL: strings.TrimSpace(ex.SQL), Tables: refs[i].shown})
	}
	return out
}

// exampleRefs analyzes the examples against the cached catalog, once per
// catalog load. It returns nil when the catalog is unavailable.
func (g *Gateway) exampleRefs(ctx context.Context, d *database) []exampleTables {
	cat, err := d.catalog(ctx, catalogTTL)
	if err != nil {
		return nil
	}
	d.mu.Lock()
	if d.exCat == cat {
		refs := d.examples
		d.mu.Unlock()
		return refs
	}
	d.mu.Unlock()

	exs := d.cfg.Docs.Examples
	refs := make([]exampleTables, len(exs))
	for i, ex := range exs {
		qa, err := d.adapter.Analyze(ctx, ex.SQL, cat)
		if err != nil {
			g.warnExample(d, ex.Title, err)
			continue
		}
		for _, t := range qa.Statement.Tables {
			refs[i].tables = append(refs[i].tables, strings.ToLower(t.FQN()))
			refs[i].shown = append(refs[i].shown, t.FQN())
		}
	}
	d.mu.Lock()
	d.examples, d.exCat = refs, cat
	d.mu.Unlock()
	return refs
}

func (g *Gateway) warnExample(d *database, title string, err error) {
	d.mu.Lock()
	if d.exWarned == nil {
		d.exWarned = map[string]bool{}
	}
	seen := d.exWarned[title]
	d.exWarned[title] = true
	d.mu.Unlock()
	if !seen {
		g.logger.Warn("docs example could not be analyzed and is not shown; check databases[].docs.examples",
			"database", d.cfg.Name, "title", title, "err", err)
	}
}
