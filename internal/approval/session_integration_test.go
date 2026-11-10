//go:build integration

package approval_test

import (
	"context"
	"testing"

	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/gateway"
)

// With session_identity, row-level security policies see who the request
// is for, for reads and for approved writes.
func TestSessionIdentityWithRowLevelSecurity(t *testing.T) {
	su := prepare(t)
	for _, q := range []string{
		`DROP TABLE IF EXISTS dbgw_it_rls`,
		`CREATE TABLE dbgw_it_rls (id bigint PRIMARY KEY, owner text NOT NULL, note text NOT NULL DEFAULT '')`,
		`INSERT INTO dbgw_it_rls VALUES (1, 'taro@example.com'), (2, 'hanako@example.com')`,
		`ALTER TABLE dbgw_it_rls ENABLE ROW LEVEL SECURITY`,
		`CREATE POLICY own ON dbgw_it_rls USING (owner = current_setting('dbgateway.user', true))`,
		`GRANT SELECT ON dbgw_it_rls TO dbgw_reader`,
		`GRANT SELECT, UPDATE ON dbgw_it_rls TO dbgw_writer`,
	} {
		if _, err := su.Exec(context.Background(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	t.Cleanup(func() { _, _ = su.Exec(context.Background(), `DROP TABLE IF EXISTS dbgw_it_rls`) })

	ids := func(h *harness) []any {
		t.Helper()
		resp := h.exec(t, taro, "SELECT id FROM dbgw_it_rls ORDER BY id")
		if resp.Status != gateway.StatusOK {
			t.Fatalf("select: %+v", resp)
		}
		var out []any
		for _, r := range resp.Rows {
			out = append(out, r[0])
		}
		return out
	}

	// Without it, the policy matches nobody.
	if got := ids(setup(t)); len(got) != 0 {
		t.Fatalf("without session identity: %v", got)
	}

	h := setupWith(t, "    session_identity: true\n")
	if got := ids(h); len(got) != 1 || got[0] != int64(1) {
		t.Fatalf("taro sees %v, want [1]", got)
	}
	// An approved write runs as its requester too: taro cannot change
	// hanako's row, only their own.
	r := h.submitAndApprove(t, taro, "UPDATE dbgw_it_rls SET note = 'x' WHERE id IN (1, 2)")
	if r.Status != approval.StatusSucceeded || r.Result.RowsAffected != 1 {
		t.Fatalf("write: %+v %+v", r, r.Result)
	}
	var note string
	if err := su.QueryRow(context.Background(), "SELECT note FROM dbgw_it_rls WHERE id = 2").Scan(&note); err != nil || note != "" {
		t.Fatalf("hanako's row: %q %v", note, err)
	}
	// Callers cannot change the settings themselves.
	if resp := h.exec(t, taro, "SELECT set_config('dbgateway.user', 'hanako@example.com', true)"); resp.Status != gateway.StatusDenied {
		t.Fatalf("set_config: %+v", resp)
	}
}
