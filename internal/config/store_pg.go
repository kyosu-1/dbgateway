package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Management-DB drivers (store.driver).
const (
	StoreSQLite   = "sqlite"
	StorePostgres = "postgres"
)

// Audit outputs (audit.output).
const (
	AuditOutputFile     = "file"
	AuditOutputStdout   = "stdout"
	AuditOutputPostgres = "postgres"
)

// envNamePattern matches environment variable names. DSNs carry passwords,
// so the configuration names the variable instead of holding the DSN.
var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validateStoreAndAuditOutput checks store.driver, store.dsn_env,
// audit.output and audit.dsn_env.
//
//	store:
//	  driver: postgres        # sqlite (default) | postgres
//	  dsn_env: DBGW_STORE_DSN # postgres: variable holding the DSN
//	audit:
//	  output: postgres        # file (default) | stdout | postgres
//	  dsn_env: DBGW_AUDIT_DSN # optional; default store.dsn_env
func (c *Config) validateStoreAndAuditOutput(add func(string, ...any)) {
	switch c.Store.Driver {
	case StoreSQLite:
		if c.Store.DSNEnv != "" {
			c.warn("store.dsn_env: ignored with store.driver %q", StoreSQLite)
		}
	case StorePostgres:
		if c.Store.Path != "" {
			c.warn("store.path: ignored with store.driver %q", StorePostgres)
		}
		c.validateDSNEnv("store.dsn_env", c.Store.DSNEnv, add)
	default:
		add("store.driver: must be %q or %q", StoreSQLite, StorePostgres)
	}

	switch c.Audit.Output {
	case AuditOutputFile, AuditOutputStdout:
		if c.Audit.DSNEnv != "" {
			c.warn("audit.dsn_env: ignored unless audit.output is %q", AuditOutputPostgres)
		}
	case AuditOutputPostgres:
		if c.Store.Driver != StorePostgres {
			add("audit.output: %q requires store.driver: %s", AuditOutputPostgres, StorePostgres)
		}
		if c.Audit.DSNEnv != "" {
			c.validateDSNEnv("audit.dsn_env", c.Audit.DSNEnv, add)
		}
	default:
		add("audit.output: must be %q, %q or %q", AuditOutputFile, AuditOutputStdout, AuditOutputPostgres)
	}
}

func (c *Config) validateDSNEnv(field, name string, add func(string, ...any)) {
	switch {
	case name == "":
		add("%s: required (the name of the environment variable holding the PostgreSQL DSN)", field)
	case !envNamePattern.MatchString(name):
		add("%s: must be the name of an environment variable holding the DSN, not the DSN itself", field)
	case strings.TrimSpace(os.Getenv(name)) == "":
		c.warn("%s: %s is not set; dbgateway will refuse to start", field, name)
	}
}

// StoreDSN returns the PostgreSQL DSN of the management database from
// store.dsn_env. The error never includes the DSN.
func (c *Config) StoreDSN() (string, error) {
	dsn, err := dsnFromEnv("store.dsn_env", c.Store.DSNEnv)
	if err != nil {
		return "", err
	}
	return withSSLRootCert(dsn, c.Store.SSLRootCert), nil
}

// AuditDSN returns the PostgreSQL DSN of the audit database
// (audit.output: postgres): audit.dsn_env when set, else store.dsn_env.
func (c *Config) AuditDSN() (string, error) {
	if c.Audit.DSNEnv != "" {
		return dsnFromEnv("audit.dsn_env", c.Audit.DSNEnv)
	}
	return c.StoreDSN()
}

func dsnFromEnv(field, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%s: not configured", field)
	}
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return "", fmt.Errorf("%s: environment variable %s is not set", field, name)
	}
	return v, nil
}
