package analysis

import (
	"slices"
	"strings"
)

// SystemSchemas are hidden from exploration unless asked for explicitly.
var SystemSchemas = []string{"pg_catalog", "information_schema"}

// FilterObjects selects catalog relations by keyword (matching schema,
// relation or column names, case-insensitively) and schema. System schemas
// are excluded unless requested explicitly.
func FilterObjects(cat *Catalog, f ObjectFilter) []Object {
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
	var out []Object
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
		var cols []ObjectColumn
		colMatch := false
		for _, c := range rel.Columns {
			if kw != "" && strings.Contains(strings.ToLower(c.Name), kw) {
				colMatch = true
			}
			oc := ObjectColumn{Name: c.Name, Type: c.Type}
			if f.Detail == "full" {
				oc.Nullable = c.Nullable
				oc.Comment = c.Comment
			}
			cols = append(cols, oc)
		}
		if !relMatch && !colMatch {
			continue
		}
		o := Object{Type: string(rel.Kind), Schema: rel.Schema, Name: rel.Name}
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
