// Package config loads and validates the dbgateway YAML configuration.
//
// The configuration is a single file intended to live in Git so that policy
// changes go through code review. Secrets are never written in the file;
// only the names of environment variables that hold them.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kyosu-1/dbgateway/internal/identity"
)

// Mode controls enforcement.
type Mode string

const (
	// ModeEnforce enforces every decision.
	ModeEnforce Mode = "enforce"
	// ModeShadow only records policy denials of reads instead of enforcing
	// them. Parse-stage rejections and write denials are always enforced.
	ModeShadow Mode = "shadow"
)

// Data classes for columns.
const (
	ClassPublic = "public"
	ClassMasked = "masked"
	ClassNoAI   = "no_ai"
)

// Policy actions.
const (
	ActionAllow   = "allow"
	ActionApprove = "approve"
	ActionDeny    = "deny"
)

// Masking methods.
const (
	MethodRedact  = "redact"
	MethodPartial = "partial"
	MethodHMAC    = "hmac"
)

// Config is the root of dbgateway.yaml.
type Config struct {
	Server        Server                  `yaml:"server"`
	Auth          Auth                    `yaml:"auth"`
	Store         Store                   `yaml:"store"`
	Audit         Audit                   `yaml:"audit"`
	SQL           SQL                     `yaml:"sql"`
	Masking       Masking                 `yaml:"masking"`
	Databases     []Database              `yaml:"databases"`
	Groups        []Group                 `yaml:"groups"`
	RoleBindings  []RoleBinding           `yaml:"role_bindings"`
	DefaultClass  *DefaultClass           `yaml:"default_class"`
	DataClasses   []DataClass             `yaml:"data_classes"`
	SemanticTypes map[string]SemanticType `yaml:"semantic_types"`
	Policies      []Rule                  `yaml:"policies"`
	PGProxy       PGProxy                 `yaml:"pgproxy"`
	SCIM          SCIM                    `yaml:"scim"`
	PIIDetection  PIIDetection            `yaml:"pii_detection"`

	// Phase 2: approvals (see approvals.go).
	Approvals     Approvals      `yaml:"approvals"`
	Risk          Risk           `yaml:"risk"`
	ApprovalRules []ApprovalRule `yaml:"approval_rules"`
	Unmask        []Unmask       `yaml:"unmask"`
	BreakGlass    *BreakGlass    `yaml:"break_glass"`
	// Notifications is accepted so that a full configuration validates,
	// but is not used yet.
	Notifications yaml.Node `yaml:"notifications"`

	// Version identifies the loaded file contents (short SHA-256). It is
	// recorded in every audit log entry.
	Version string `yaml:"-"`
	// Warnings collected while validating (non-fatal).
	Warnings []string `yaml:"-"`
}

type Server struct {
	Listen    string `yaml:"listen"`
	PublicURL string `yaml:"public_url"`
	Mode      Mode   `yaml:"mode"`
}

type Auth struct {
	OIDC        *OIDC       `yaml:"oidc"`
	Passkeys    bool        `yaml:"passkeys"` // phase 2
	AgentTokens AgentTokens `yaml:"agent_tokens"`
	// CLITokenTTL is the lifetime of human tokens issued to `dbgw login`.
	CLITokenTTL Duration `yaml:"cli_token_ttl"`
	// SessionTTL is the lifetime of the browser login session.
	SessionTTL Duration `yaml:"session_ttl"`
	// DevLogin enables a password-less login form that accepts any email.
	// Only for local development; refused unless listening on loopback.
	DevLogin bool `yaml:"dev_login"`
	// AllowInsecureClientMetadata allows http:// Client ID Metadata Document
	// URLs on loopback hosts (development only).
	AllowInsecureClientMetadata bool `yaml:"allow_insecure_client_metadata"`
}

type OIDC struct {
	Issuer          string   `yaml:"issuer"`
	ClientIDEnv     string   `yaml:"client_id_env"`
	ClientSecretEnv string   `yaml:"client_secret_env"`
	GroupsClaim     string   `yaml:"groups_claim"`
	Scopes          []string `yaml:"scopes"`
}

type AgentTokens struct {
	MaxTTL  Duration `yaml:"max_ttl"`
	Refresh bool     `yaml:"refresh"`
}

type Store struct {
	Driver string `yaml:"driver"` // sqlite
	Path   string `yaml:"path"`
}

type Audit struct {
	Output    string   `yaml:"output"` // file | stdout
	Dir       string   `yaml:"dir"`
	Retention Duration `yaml:"retention"`
	// LogRawSQL records SQL with literal values. Off by default: literals are
	// replaced with placeholders.
	LogRawSQL bool `yaml:"log_raw_sql"`
	// NoFsync disables fsync after each entry (faster, less durable).
	NoFsync bool `yaml:"no_fsync"`
	// OTLP additionally forwards entries as OpenTelemetry logs (optional,
	// best effort).
	OTLP *AuditOTLP `yaml:"otlp"`
}

type SQL struct {
	// AllowedFunctions extends the built-in function allowlist. Entries are
	// function names, optionally schema-qualified ("public.my_func").
	AllowedFunctions []string `yaml:"allowed_functions"`
}

type Masking struct {
	// HMACKeyEnv names the environment variable holding the HMAC key used by
	// the "hmac" masking method.
	HMACKeyEnv string `yaml:"hmac_key_env"`
}

type Database struct {
	Name         string            `yaml:"name"`
	Type         string            `yaml:"type"`
	Labels       map[string]string `yaml:"labels"`
	Primary      Endpoint          `yaml:"primary"`
	Replica      *Endpoint         `yaml:"replica"`
	Limits       Limits            `yaml:"limits"`
	SearchPath   []string          `yaml:"search_path"`
	DefaultClass *DefaultClass     `yaml:"default_class"`
}

type Endpoint struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	DBName   string `yaml:"dbname"`
	Auth     string `yaml:"auth"`   // password | aws_iam | gcp_iam
	Region   string `yaml:"region"` // aws_iam only (default: AWS SDK config)
	ReadUser string `yaml:"read_user"`
	// PasswordEnv names the env var with the read user's password.
	PasswordEnv string `yaml:"password_env"`
	WriteUser   string `yaml:"write_user"`
	// WritePasswordEnv names the env var with the write user's password.
	WritePasswordEnv string `yaml:"write_password_env"`
	SSLMode          string `yaml:"sslmode"`
	SSLRootCert      string `yaml:"sslrootcert"`
}

type Limits struct {
	MaxRows          int      `yaml:"max_rows"`
	MaxBytes         ByteSize `yaml:"max_bytes"`
	StatementTimeout Duration `yaml:"statement_timeout"`
	LockTimeout      Duration `yaml:"lock_timeout"`
}

type Group struct {
	Name      string   `yaml:"name"`
	OIDCGroup string   `yaml:"oidc_group"`
	Members   []string `yaml:"members"` // for environments without an IdP
}

type RoleBinding struct {
	Group     string           `yaml:"group"`
	User      string           `yaml:"user"` // e-mail; alternative to group (e.g. JIT grants)
	Databases DatabaseSelector `yaml:"databases"`
	Roles     []identity.Role  `yaml:"roles"`
	ExpiresAt *time.Time       `yaml:"expires_at"`
}

type DefaultClass struct {
	Human string `yaml:"human"`
	Agent string `yaml:"agent"`
}

type DataClass struct {
	Columns       []string `yaml:"columns"`
	ColumnPattern string   `yaml:"column_pattern"`
	Class         string   `yaml:"class"`
	SemanticType  string   `yaml:"semantic_type"`

	Pattern *regexp.Regexp `yaml:"-"`
}

type SemanticType struct {
	Method string `yaml:"method"`
}

// Rule is one policy rule. Rules are evaluated top to bottom and the first
// match wins. No match means deny.
type Rule struct {
	Name    string  `yaml:"name"`
	When    string  `yaml:"when"`
	Action  string  `yaml:"action"`
	Require Require `yaml:"require"`
	// Message and Hint are returned to the caller on deny, to explain why and
	// how to get the query through.
	Message string `yaml:"message"`
	Hint    string `yaml:"hint"`
}

type Require struct {
	StepUp  bool `yaml:"step_up"`
	Reason  bool `yaml:"reason"`
	MaxRows int  `yaml:"max_rows"`
	Replica bool `yaml:"replica"`
}

// Load reads, parses, defaults and validates a configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Parse parses, defaults and validates configuration bytes.
func Parse(raw []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	sum := sha256.Sum256(raw)
	c.Version = hex.EncodeToString(sum[:])[:12]
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// DefaultPolicies is used when the configuration has no policies: reads are
// allowed, everything else is denied (no rule matches).
var DefaultPolicies = []Rule{{
	Name:   "default-reads",
	When:   `stmt.kind == "select" && !stmt.is_write`,
	Action: ActionAllow,
}}

func (c *Config) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = "127.0.0.1:8443"
	}
	if c.Server.PublicURL == "" {
		c.Server.PublicURL = "http://" + c.Server.Listen
	}
	c.Server.PublicURL = strings.TrimRight(c.Server.PublicURL, "/")
	if c.Server.Mode == "" {
		c.Server.Mode = ModeEnforce
	}
	if c.Auth.AgentTokens.MaxTTL == 0 {
		c.Auth.AgentTokens.MaxTTL = Duration(time.Hour)
	}
	if c.Auth.CLITokenTTL == 0 {
		c.Auth.CLITokenTTL = Duration(12 * time.Hour)
	}
	if c.Auth.SessionTTL == 0 {
		c.Auth.SessionTTL = Duration(time.Hour)
	}
	if c.Auth.OIDC != nil {
		if c.Auth.OIDC.GroupsClaim == "" {
			c.Auth.OIDC.GroupsClaim = "groups"
		}
		if len(c.Auth.OIDC.Scopes) == 0 {
			c.Auth.OIDC.Scopes = []string{"openid", "email", "profile"}
		}
	}
	if c.Store.Driver == "" {
		c.Store.Driver = "sqlite"
	}
	if c.Store.Path == "" {
		c.Store.Path = "var/dbgateway.db"
	}
	if c.Audit.Output == "" {
		c.Audit.Output = "file"
	}
	if c.Audit.Dir == "" {
		c.Audit.Dir = "var/audit"
	}
	if c.Audit.Retention == 0 {
		c.Audit.Retention = Duration(365 * 24 * time.Hour)
	}
	for i := range c.Databases {
		db := &c.Databases[i]
		if db.Type == "" {
			db.Type = "postgres"
		}
		for _, ep := range []*Endpoint{&db.Primary, db.Replica} {
			if ep == nil {
				continue
			}
			if ep.Port == 0 {
				ep.Port = 5432
				if db.Type == "mysql" {
					ep.Port = 3306
				}
			}
			if ep.Auth == "" {
				ep.Auth = "password"
			}
			if ep.SSLMode == "" {
				ep.SSLMode = "verify-full"
			}
			if ep.DBName == "" {
				// MySQL has no default database: the primary's dbname is
				// required (validated below) and the replica inherits it.
				if db.Type == "mysql" {
					ep.DBName = db.Primary.DBName
				} else {
					ep.DBName = "postgres"
				}
			}
		}
		if db.Limits.MaxRows == 0 {
			db.Limits.MaxRows = 1000
		}
		if db.Limits.MaxBytes == 0 {
			db.Limits.MaxBytes = 1 << 20
		}
		if db.Limits.StatementTimeout == 0 {
			db.Limits.StatementTimeout = Duration(10 * time.Second)
		}
		if db.Limits.LockTimeout == 0 {
			db.Limits.LockTimeout = Duration(2 * time.Second)
		}
		if len(db.SearchPath) == 0 {
			db.SearchPath = []string{"public"}
			if db.Type == "mysql" {
				// Unqualified names resolve against the default database.
				db.SearchPath = []string{db.Primary.DBName}
			}
		}
	}
	c.applyApprovalDefaults()
	if len(c.Policies) == 0 {
		c.Policies = c.defaultPolicies()
	}
}

func (c *Config) warn(format string, args ...any) {
	c.Warnings = append(c.Warnings, fmt.Sprintf(format, args...))
}

func (c *Config) validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.Server.Mode != ModeEnforce && c.Server.Mode != ModeShadow {
		add("server.mode: must be %q or %q", ModeEnforce, ModeShadow)
	}
	if u, err := url.Parse(c.Server.PublicURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		add("server.public_url: must be an absolute http(s) URL")
	} else if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		add("server.public_url: plain http is only allowed for loopback hosts; terminate TLS in front of dbgateway")
	}
	if c.Auth.DevLogin && !isLoopbackListen(c.Server.Listen) {
		add("auth.dev_login: only allowed when server.listen is a loopback address")
	}
	if c.Auth.OIDC == nil && !c.Auth.DevLogin {
		add("auth: configure auth.oidc (or auth.dev_login for local development)")
	}
	if o := c.Auth.OIDC; o != nil {
		if o.Issuer == "" || o.ClientIDEnv == "" {
			add("auth.oidc: issuer and client_id_env are required")
		}
	}
	if c.Auth.Passkeys {
		c.warn("auth.passkeys: passkeys are planned for phase 2 and are ignored")
	}
	if c.Auth.AgentTokens.MaxTTL.D() > 24*time.Hour {
		add("auth.agent_tokens.max_ttl: must be at most 24h")
	}
	if c.Store.Driver != "sqlite" {
		add("store.driver: only \"sqlite\" is supported")
	}
	if c.Audit.Output != "file" && c.Audit.Output != "stdout" {
		add("audit.output: must be \"file\" or \"stdout\"")
	}
	if c.Audit.OTLP != nil {
		c.Audit.OTLP.validate(add, c.warn)
	}
	if c.Masking.HMACKeyEnv != "" && os.Getenv(c.Masking.HMACKeyEnv) == "" {
		c.warn("masking.hmac_key_env: %s is not set; the hmac method will fall back to redact", c.Masking.HMACKeyEnv)
	}

	dbNames := map[string]bool{}
	for i, db := range c.Databases {
		p := fmt.Sprintf("databases[%d]", i)
		if db.Name == "" {
			add("%s.name: required", p)
		} else if dbNames[db.Name] {
			add("%s.name: duplicate %q", p, db.Name)
		}
		dbNames[db.Name] = true
		switch db.Type {
		case "postgres":
		case "mysql":
			if db.Primary.DBName == "" {
				add("%s.primary.dbname: required for mysql", p)
			}
			if len(db.SearchPath) != 1 || db.SearchPath[0] != db.Primary.DBName {
				add("%s.search_path: for mysql, omit it or set it to [%s] (the default database)", p, db.Primary.DBName)
			}
		default:
			add("%s.type: unsupported %q (supported: postgres, mysql)", p, db.Type)
		}
		for _, ep := range []struct {
			name string
			e    *Endpoint
		}{{"primary", &db.Primary}, {"replica", db.Replica}} {
			if ep.e == nil {
				continue
			}
			pp := p + "." + ep.name
			if ep.e.Host == "" {
				add("%s.host: required", pp)
			}
			if ep.e.ReadUser == "" {
				add("%s.read_user: required", pp)
			}
			validateEndpointAuth(pp, ep.e, add, c.warn)
			if db.Type == "mysql" && ep.e.Auth != "password" {
				add("%s.auth: only password is supported for mysql", pp)
			}
			switch {
			case db.Type == "mysql":
				// Mapped to go-sql-driver TLS settings: disable (no TLS),
				// require (TLS without verification), verify-full.
				switch ep.e.SSLMode {
				case "disable", "require", "verify-full":
				default:
					add("%s.sslmode: %q is not supported for mysql (use disable, require or verify-full)", pp, ep.e.SSLMode)
				}
			default:
				switch ep.e.SSLMode {
				case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
				default:
					add("%s.sslmode: invalid %q", pp, ep.e.SSLMode)
				}
			}
			if ep.e.SSLMode != "verify-full" && !isLoopbackHost(ep.e.Host) && db.Labels["env"] == "prod" {
				c.warn("%s.sslmode: %q on a prod database; verify-full is strongly recommended", pp, ep.e.SSLMode)
			}
		}
		if db.Limits.MaxRows < 0 || db.Limits.MaxBytes < 0 {
			add("%s.limits: must be positive", p)
		}
		if db.DefaultClass != nil {
			validateDefaultClass(db.DefaultClass, p+".default_class", add)
		}
	}

	groupNames := map[string]bool{}
	for i, g := range c.Groups {
		if g.Name == "" {
			add("groups[%d].name: required", i)
		}
		if groupNames[g.Name] {
			add("groups[%d].name: duplicate %q", i, g.Name)
		}
		groupNames[g.Name] = true
	}
	for i, rb := range c.RoleBindings {
		p := fmt.Sprintf("role_bindings[%d]", i)
		switch {
		case (rb.Group == "") == (rb.User == ""):
			add("%s: exactly one of group or user is required", p)
		case rb.Group != "" && !groupNames[rb.Group]:
			add("%s.group: unknown group %q", p, rb.Group)
		}
		for _, n := range rb.Databases.Names {
			if !dbNames[n] {
				add("%s.databases: unknown database %q", p, n)
			}
		}
		if !rb.Databases.All && len(rb.Databases.Names) == 0 && len(rb.Databases.Labels) == 0 {
			add("%s.databases: required", p)
		}
		if len(rb.Roles) == 0 {
			add("%s.roles: required", p)
		}
		for _, r := range rb.Roles {
			if !r.Valid() {
				add("%s.roles: unknown role %q", p, r)
			}
			if (r == identity.RoleApprover || r == identity.RoleWriter) && !c.Approvals.Enabled {
				c.warn("%s.roles: %q has no effect until approvals.enabled is true", p, r)
			}
		}
	}

	if c.DefaultClass != nil {
		validateDefaultClass(c.DefaultClass, "default_class", add)
	}
	for name, st := range c.SemanticTypes {
		switch st.Method {
		case MethodRedact, MethodPartial, MethodHMAC:
		default:
			add("semantic_types.%s.method: must be redact, partial or hmac", name)
		}
	}
	for i := range c.DataClasses {
		dc := &c.DataClasses[i]
		p := fmt.Sprintf("data_classes[%d]", i)
		if !validClass(dc.Class) {
			add("%s.class: must be public, masked or no_ai", p)
		}
		if (len(dc.Columns) == 0) == (dc.ColumnPattern == "") {
			add("%s: exactly one of columns or column_pattern is required", p)
		}
		for _, col := range dc.Columns {
			if strings.Count(col, ".") != 2 {
				add("%s.columns: %q must be schema.table.column", p, col)
			}
		}
		if dc.ColumnPattern != "" {
			re, err := regexp.Compile("^(?:" + dc.ColumnPattern + ")$")
			if err != nil {
				add("%s.column_pattern: %v", p, err)
			}
			dc.Pattern = re
		}
		if dc.SemanticType != "" {
			if _, ok := c.SemanticTypes[dc.SemanticType]; !ok {
				add("%s.semantic_type: unknown semantic type %q", p, dc.SemanticType)
			}
		}
	}

	ruleNames := map[string]bool{}
	for i, r := range c.Policies {
		p := fmt.Sprintf("policies[%d]", i)
		if r.Name == "" {
			add("%s.name: required", p)
		} else if ruleNames[r.Name] {
			add("%s.name: duplicate %q", p, r.Name)
		}
		ruleNames[r.Name] = true
		if strings.TrimSpace(r.When) == "" {
			add("%s.when: required", p)
		}
		switch r.Action {
		case ActionAllow, ActionApprove, ActionDeny:
		default:
			add("%s.action: must be allow, approve or deny", p)
		}
		if r.Require.MaxRows < 0 {
			add("%s.require.max_rows: must be positive", p)
		}
		// CEL compilation and the "allow must never match a write" check
		// are done by the policy package (see policy.Compile).
	}

	c.validatePGProxy(add)
	c.validateApprovals(groupNames, dbNames, add)
	if c.Notifications.Kind != 0 {
		c.warn("notifications: planned for phase 2; ignored")
	}
	c.SCIM.validate(c, add)
	c.PIIDetection.validate(add)
	return errors.Join(errs...)
}

func validateDefaultClass(d *DefaultClass, p string, add func(string, ...any)) {
	if d.Human != "" && !validClass(d.Human) {
		add("%s.human: must be public, masked or no_ai", p)
	}
	if d.Agent != "" && !validClass(d.Agent) {
		add("%s.agent: must be public, masked or no_ai", p)
	}
}

func validClass(s string) bool {
	return s == ClassPublic || s == ClassMasked || s == ClassNoAI
}

// Database returns the database with the given name, or nil.
func (c *Config) Database(name string) *Database {
	for i := range c.Databases {
		if c.Databases[i].Name == name {
			return &c.Databases[i]
		}
	}
	return nil
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return isLoopbackHost(host)
}
