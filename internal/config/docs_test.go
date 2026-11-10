package config

import (
	"strings"
	"testing"
)

const docsBase = `auth: { dev_login: true }
databases:
  - name: db
    primary: { host: localhost, read_user: r, sslmode: disable }
`

func TestDatabaseDocs(t *testing.T) {
	c, err := Parse([]byte(docsBase + `    docs:
      description: Core OLTP database.
      tables:
        public.Orders:
          description: One row per checkout.
          columns:
            Total_Amount: Total in JPY, tax included.
        public.users:
          columns: { email: Login e-mail. }
      examples:
        - title: Daily revenue
          description: Paid orders only.
          sql: SELECT 1 FROM orders
`))
	if err != nil {
		t.Fatal(err)
	}
	d := c.Databases[0].Docs
	if d.Description != "Core OLTP database." || len(d.Examples) != 1 || d.Examples[0].Description != "Paid orders only." {
		t.Fatalf("docs = %+v", d)
	}
	if tb := d.Tables["public.Orders"]; tb.Description != "One row per checkout." || tb.Columns["Total_Amount"] != "Total in JPY, tax included." {
		t.Fatalf("table docs = %+v", tb)
	}

	c, err = Parse([]byte(docsBase))
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Databases[0].Docs; d.Description != "" || d.Tables != nil || d.Examples != nil {
		t.Fatal("docs are optional")
	}
}

func TestDatabaseDocsValidation(t *testing.T) {
	for _, tt := range []struct{ docs, want string }{
		{"tables: { orders: { description: x } }", "docs.tables.orders: the key must be schema.table"},
		{"tables: { public.app.orders: { description: x } }", "docs.tables.public.app.orders: the key must be schema.table"},
		{"tables: { .orders: { description: x } }", "the key must be schema.table"},
		{"tables: { public.orders: { description: x }, Public.Orders: { description: y } }", "duplicate of"},
		{"tables: { public.orders: {} }", "docs.tables.public.orders: description or columns is required"},
		{"tables: { public.orders: { columns: { total: '' } } }", "docs.tables.public.orders.columns.total: description is required"},
		{"tables: { public.orders: { columns: { orders.total: x } } }", "must be a column name"},
		{"tables: { public.orders: { columns: { total: x, TOTAL: y } } }", "columns.total: duplicate of"},
		{"tables: { public.orders: { comment: x } }", "field comment not found"},
		{"examples: [{ sql: SELECT 1 }]", "docs.examples[0].title: required"},
		{"examples: [{ title: a }]", "docs.examples[0].sql: required"},
		{"examples: [{ title: Revenue, sql: SELECT 1 }, { title: ' revenue ', sql: SELECT 2 }]", `docs.examples[1].title: duplicate "revenue"`},
		{"examples: [{ title: a, sql: SELECT 1, tables: [x] }]", "field tables not found"},
		{"notes: x", "field notes not found"},
	} {
		_, err := Parse([]byte(docsBase + "    docs: { " + tt.docs + " }\n"))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.docs, err, tt.want)
		}
	}
}
