package config

import (
	"strings"
	"testing"
)

func TestStoreAndAuditOutputConfig(t *testing.T) {
	const base = "auth: { dev_login: true }\n"
	t.Setenv("DBGW_TEST_STORE_DSN", "postgres://u:p@db/dbgw")
	t.Setenv("DBGW_TEST_AUDIT_DSN", "postgres://u:p@audit/dbgw")
	t.Setenv("DBGW_TEST_UNSET_DSN", "")

	for _, tt := range []struct {
		name, yaml       string
		err, warning     string
		storeDSN, audDSN string
	}{
		{name: "defaults", yaml: ""},
		{name: "postgres store", yaml: "store: { driver: postgres, dsn_env: DBGW_TEST_STORE_DSN }",
			storeDSN: "postgres://u:p@db/dbgw", audDSN: "postgres://u:p@db/dbgw"},
		{name: "postgres audit with the store DSN", yaml: "store: { driver: postgres, dsn_env: DBGW_TEST_STORE_DSN }\naudit: { output: postgres }",
			storeDSN: "postgres://u:p@db/dbgw", audDSN: "postgres://u:p@db/dbgw"},
		{name: "postgres audit with its own DSN", yaml: "store: { driver: postgres, dsn_env: DBGW_TEST_STORE_DSN }\naudit: { output: postgres, dsn_env: DBGW_TEST_AUDIT_DSN }",
			storeDSN: "postgres://u:p@db/dbgw", audDSN: "postgres://u:p@audit/dbgw"},
		{name: "postgres without dsn_env", yaml: "store: { driver: postgres }", err: "store.dsn_env: required"},
		{name: "DSN in place of the variable", yaml: "store: { driver: postgres, dsn_env: 'postgres://u:p@db/x' }", err: "not the DSN itself"},
		{name: "unset variable", yaml: "store: { driver: postgres, dsn_env: DBGW_TEST_UNSET_DSN }", warning: "is not set"},
		{name: "unknown driver", yaml: "store: { driver: mysql }", err: "store.driver"},
		{name: "postgres audit needs postgres store", yaml: "audit: { output: postgres }", err: "requires store.driver: postgres"},
		{name: "unknown output", yaml: "audit: { output: syslog }", err: "audit.output"},
		{name: "path ignored", yaml: "store: { driver: postgres, dsn_env: DBGW_TEST_STORE_DSN, path: x.db }", warning: "store.path: ignored"},
		{name: "audit dsn ignored", yaml: "audit: { dsn_env: DBGW_TEST_AUDIT_DSN }", warning: "audit.dsn_env: ignored"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Parse([]byte(base + tt.yaml + "\n"))
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("err = %v, want %q", err, tt.err)
				}
				if strings.Contains(err.Error(), "u:p@") {
					t.Fatalf("error leaks the DSN: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			warnings := strings.Join(c.Warnings, "\n")
			if tt.warning != "" && !strings.Contains(warnings, tt.warning) {
				t.Fatalf("warnings = %q, want %q", c.Warnings, tt.warning)
			}
			if tt.storeDSN != "" {
				if got, err := c.StoreDSN(); err != nil || got != tt.storeDSN {
					t.Fatalf("StoreDSN = %q, %v", got, err)
				}
				if got, err := c.AuditDSN(); err != nil || got != tt.audDSN {
					t.Fatalf("AuditDSN = %q, %v", got, err)
				}
			}
		})
	}

	c, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if c.Store.Driver != StoreSQLite || c.Store.Path != "var/dbgateway.db" || c.Audit.Output != AuditOutputFile {
		t.Fatalf("defaults: %+v %+v", c.Store, c.Audit)
	}
	if _, err := c.StoreDSN(); err == nil {
		t.Fatal("StoreDSN without dsn_env")
	}
	c, _ = Parse([]byte(base + "store: { driver: postgres, dsn_env: DBGW_TEST_UNSET_DSN }\n"))
	if _, err := c.StoreDSN(); err == nil || !strings.Contains(err.Error(), "DBGW_TEST_UNSET_DSN is not set") {
		t.Fatalf("StoreDSN with unset variable: %v", err)
	}
	if c.Store.Path != "" {
		t.Fatalf("sqlite path defaulted for postgres: %q", c.Store.Path)
	}
}
