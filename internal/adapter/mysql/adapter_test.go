package mysql

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
)

func parseConfig(t *testing.T, db string) (*config.Config, error) {
	t.Helper()
	return config.Parse([]byte("auth: { dev_login: true }\ndatabases:\n" + db))
}

func TestConfigDefaults(t *testing.T) {
	cfg, err := parseConfig(t, `
  - name: m
    type: mysql
    primary: { host: db.internal, dbname: app, read_user: r }
    replica: { host: replica.internal, read_user: r }
`)
	if err != nil {
		t.Fatal(err)
	}
	db := cfg.Databases[0]
	if db.Primary.Port != 3306 || db.Replica.Port != 3306 || db.Replica.DBName != "app" {
		t.Errorf("endpoints = %+v / %+v", db.Primary, *db.Replica)
	}
	if len(db.SearchPath) != 1 || db.SearchPath[0] != "app" {
		t.Errorf("search_path = %v", db.SearchPath)
	}
	if db.Primary.SSLMode != "verify-full" {
		t.Errorf("sslmode = %s", db.Primary.SSLMode)
	}
}

func TestConfigErrors(t *testing.T) {
	for name, db := range map[string]string{
		"missing dbname":   "  - { name: m, type: mysql, primary: { host: h, read_user: r } }",
		"verify-ca":        "  - { name: m, type: mysql, primary: { host: h, dbname: app, read_user: r, sslmode: verify-ca } }",
		"prefer":           "  - { name: m, type: mysql, primary: { host: h, dbname: app, read_user: r, sslmode: prefer } }",
		"search_path":      "  - { name: m, type: mysql, search_path: [other], primary: { host: h, dbname: app, read_user: r } }",
		"two search paths": "  - { name: m, type: mysql, search_path: [app, other], primary: { host: h, dbname: app, read_user: r } }",
		"unknown type":     "  - { name: m, type: oracle, primary: { host: h, dbname: app, read_user: r } }",
	} {
		if _, err := parseConfig(t, db); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := parseConfig(t, "  - { name: m, type: mysql, search_path: [app], primary: { host: h, dbname: app, read_user: r, sslmode: require } }"); err != nil {
		t.Errorf("explicit search_path equal to dbname: %v", err)
	}
}

func TestTLSConfig(t *testing.T) {
	if tc, err := tlsConfig(config.Endpoint{SSLMode: "disable"}); err != nil || tc != nil {
		t.Errorf("disable: %v %v", tc, err)
	}
	if tc, err := tlsConfig(config.Endpoint{SSLMode: "require"}); err != nil || tc == nil || !tc.InsecureSkipVerify {
		t.Errorf("require: %v %v", tc, err)
	}
	tc, err := tlsConfig(config.Endpoint{SSLMode: "verify-full", Host: "db.example.com"})
	if err != nil || tc == nil || tc.InsecureSkipVerify || tc.ServerName != "db.example.com" || tc.RootCAs != nil {
		t.Errorf("verify-full: %+v %v", tc, err)
	}
	bad := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsConfig(config.Endpoint{SSLMode: "verify-full", Host: "h", SSLRootCert: bad}); err == nil {
		t.Error("invalid sslrootcert must fail")
	}
	if _, err := tlsConfig(config.Endpoint{SSLMode: "verify-ca"}); err == nil {
		t.Error("verify-ca must be refused")
	}
}

func TestParseExplain(t *testing.T) {
	v1 := `{"query_block": {"select_id": 1, "cost_info": {"query_cost": "1012.25"},
	  "nested_loop": [
	    {"table": {"table_name": "u", "rows_examined_per_scan": 500, "rows_produced_per_join": 500}},
	    {"table": {"table_name": "o", "rows_examined_per_scan": 10, "rows_produced_per_join": 5000,
	      "attached_subqueries": [{"query_block": {"table": {"rows_produced_per_join": 99999}}}]}}
	  ]}}`
	est, err := parseExplain([]byte(v1))
	if err != nil || est.Rows != 5000 || est.Cost != 1012.25 {
		t.Errorf("v1 = %+v %v", est, err)
	}
	est, err = parseExplain([]byte(`{"query_block": {"select_id": 1, "message": "No tables used"}}`))
	if err != nil || est.Rows != 1 {
		t.Errorf("no tables = %+v %v", est, err)
	}
	est, err = parseExplain([]byte(`{"query": "...", "estimated_rows": 42, "estimated_total_cost": 7.5}`))
	if err != nil || est.Rows != 42 || est.Cost != 7.5 {
		t.Errorf("v2 = %+v %v", est, err)
	}
	if _, err := parseExplain([]byte(`not json`)); err == nil {
		t.Error("invalid output must fail")
	}
}

func TestJSONValue(t *testing.T) {
	ts := time.Date(2024, 1, 2, 3, 4, 5, 6000, time.UTC)
	tests := []struct {
		in   any
		typ  string
		want any
	}{
		{nil, "VARCHAR", nil},
		{int64(-3), "BIGINT", int64(-3)},
		{uint64(18446744073709551615), "UNSIGNED BIGINT", "18446744073709551615"},
		{uint64(7), "UNSIGNED INT", int64(7)},
		{float32(1.5), "FLOAT", float64(1.5)},
		{[]byte("12.50"), "DECIMAL", "12.50"},
		{[]byte("abc"), "VARCHAR", "abc"},
		{[]byte{0xff, 0x00}, "VARBINARY", `\xff00`},
		{[]byte{0x01}, "BLOB", `\x01`},
		{[]byte("text"), "TEXT", "text"},
		{[]byte{0x01, 0x00}, "BIT", int64(256)},
		{[]byte(`{"a":1}`), "JSON", map[string]any{"a": float64(1)}},
		{[]byte(`10:11:12`), "TIME", "10:11:12"},
		{[]byte(`2024`), "YEAR", int64(2024)},
		{ts, "DATETIME", "2024-01-02T03:04:05.000006Z"},
		{ts, "TIMESTAMP", "2024-01-02T03:04:05.000006Z"},
		{ts, "DATE", "2024-01-02"},
		{time.Time{}, "DATETIME", "0000-00-00 00:00:00"},
		{[]byte{0xff}, "", `\xff`},
	}
	for _, tt := range tests {
		got := jsonValue(tt.in, tt.typ)
		if fmt.Sprintf("%#v", got) != fmt.Sprintf("%#v", tt.want) {
			t.Errorf("jsonValue(%#v, %s) = %#v, want %#v", tt.in, tt.typ, got, tt.want)
		}
	}
}

func TestNewPoolRequiresPassword(t *testing.T) {
	_, err := newPool(config.Endpoint{Host: "h", Port: 3306, DBName: "app", SSLMode: "disable"}, "r", "DBGW_TEST_UNSET_PASSWORD_ENV")
	if err == nil || !strings.Contains(err.Error(), "DBGW_TEST_UNSET_PASSWORD_ENV") {
		t.Errorf("err = %v", err)
	}
}
