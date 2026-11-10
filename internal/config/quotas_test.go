package config

import (
	"strings"
	"testing"
	"time"
)

func TestQuotasConfig(t *testing.T) {
	c, err := Parse([]byte(`
auth: { dev_login: true }
quotas:
  - name: agents
    when: principal.kind == "agent"
    queries_per_minute: 30
    rows_per_hour: 20000
    rows_per_day: 100000
    hint: Ask #data-platform for a higher quota.
  - name: everyone
    queries_per_hour: 1000
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Quotas) != 2 {
		t.Fatalf("quotas = %+v", c.Quotas)
	}
	ls := c.Quotas[0].Limits()
	if len(ls) != 3 || ls[0].Key != "queries_per_minute" || ls[0].Rows || ls[1].Key != "rows_per_hour" || !ls[1].Rows ||
		ls[2].Window != 24*time.Hour || ls[2].Max != 100000 {
		t.Fatalf("limits = %+v", ls)
	}
	if c.Quotas[0].Window() != 24*time.Hour || c.Quotas[1].Window() != time.Hour {
		t.Fatalf("windows = %v, %v", c.Quotas[0].Window(), c.Quotas[1].Window())
	}

	for _, tt := range []struct{ yaml, want string }{
		{"quotas: [{ queries_per_hour: 1 }]", "quotas[0].name: required"},
		{"quotas: [{ name: a, queries_per_hour: 1 }, { name: a, rows_per_hour: 1 }]", `quotas[1].name: duplicate "a"`},
		{"quotas: [{ name: a }]", "set at least one of"},
		{"quotas: [{ name: a, rows_per_hour: -1 }]", "limits must be positive"},
		{"quotas: [{ name: a, rows_per_week: 1 }]", "field rows_per_week not found"},
	} {
		_, err := Parse([]byte("auth: { dev_login: true }\n" + tt.yaml + "\n"))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.yaml, err, tt.want)
		}
	}
}
