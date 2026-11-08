package postgres

import "testing"

func TestParseExplain(t *testing.T) {
	update := []byte(`[{"Plan": {"Node Type": "ModifyTable", "Plan Rows": 0, "Total Cost": 11.01,
		"Plans": [{"Node Type": "Index Scan", "Plan Rows": 99, "Total Cost": 11.01}]}}]`)
	cte := []byte(`[{"Plan": {"Node Type": "Aggregate", "Plan Rows": 1, "Total Cost": 20,
		"Plans": [
			{"Node Type": "ModifyTable", "Plan Rows": 9, "Plans": [{"Node Type": "Index Scan", "Plan Rows": 9}]},
			{"Node Type": "CTE Scan", "Plan Rows": 9}]}}]`)
	sel := []byte(`[{"Plan": {"Node Type": "Seq Scan", "Plan Rows": 500, "Total Cost": 12}}]`)
	for _, tt := range []struct {
		name  string
		raw   []byte
		write bool
		rows  float64
	}{
		{"update without RETURNING", update, true, 99},
		{"writable CTE", cte, true, 9},
		{"read", sel, false, 500},
		{"read of a plan with ModifyTable is not adjusted", update, false, 0},
	} {
		est, err := parseExplain(tt.raw, tt.write)
		if err != nil || est.Rows != tt.rows {
			t.Errorf("%s: got %+v, %v; want rows %v", tt.name, est, err, tt.rows)
		}
	}
	if _, err := parseExplain([]byte(`[]`), false); err == nil {
		t.Error("empty output must fail")
	}
}
