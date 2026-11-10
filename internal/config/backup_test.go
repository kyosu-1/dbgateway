package config

import (
	"strings"
	"testing"
)

func TestBackupConfig(t *testing.T) {
	db := func(extra string) string {
		return "auth: { dev_login: true }\ndatabases:\n  - name: main\n    primary: { host: db, read_user: r, password_env: P, write_user: w, write_password_env: W }\n" + extra
	}
	c, err := Parse([]byte(db("    backup: { schema: dbgw_backup, required: true }\n")))
	if err != nil {
		t.Fatal(err)
	}
	if b := c.Databases[0].Backup; b == nil || b.Schema != "dbgw_backup" || !b.Required {
		t.Fatalf("backup = %+v", b)
	}
	for yaml, want := range map[string]string{
		db("    backup: {}\n"):                                         "backup.schema: required",
		db("    backup: { schema: \"Bad-Name\" }\n"):                   "backup.schema: required",
		db("    backup: { schema: public }\n"):                         "search_path",
		db("    search_path: [app, bk]\n    backup: { schema: bk }\n"): "search_path",
		db("    backup: { schema: bk, keep: 3 }\n"):                    "keep",
		"auth: { dev_login: true }\ndatabases:\n  - name: main\n    primary: { host: db, read_user: r, password_env: P }\n    backup: { schema: bk }\n":                                                                     "requires primary.write_user",
		"auth: { dev_login: true }\ndatabases:\n  - name: main\n    type: mysql\n    primary: { host: db, dbname: app, read_user: r, password_env: P, write_user: w, write_password_env: W }\n    backup: { schema: bk }\n": "only supported for postgres",
	} {
		if _, err := Parse([]byte(yaml)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", yaml, err, want)
		}
	}
}

func TestSessionIdentityConfig(t *testing.T) {
	if _, err := Parse([]byte("auth: { dev_login: true }\ndatabases:\n  - name: main\n    primary: { host: db, read_user: r, password_env: P }\n    session_identity: true\n")); err != nil {
		t.Fatal(err)
	}
	_, err := Parse([]byte("auth: { dev_login: true }\ndatabases:\n  - name: main\n    type: mysql\n    primary: { host: db, dbname: app, read_user: r, password_env: P }\n    session_identity: true\n"))
	if err == nil || !strings.Contains(err.Error(), "session_identity: only supported for postgres") {
		t.Fatalf("mysql: %v", err)
	}
}
