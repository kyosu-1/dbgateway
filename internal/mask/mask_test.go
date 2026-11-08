package mask

import (
	"strings"
	"testing"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

const yamlCfg = `
auth: { dev_login: true }
masking: { hmac_key_env: DBGW_TEST_HMAC }
databases:
  - name: prod-main
    labels: { env: prod }
    primary: { host: localhost, read_user: r, sslmode: disable }
  - name: dev
    primary: { host: localhost, read_user: r, sslmode: disable }
data_classes:
  - columns: ["public.users.email"]
    class: masked
    semantic_type: contact
  - columns: ["public.users.id"]
    class: public
  - column_pattern: ".*(password|token|secret).*"
    class: masked
    semantic_type: secret
  - columns: ["public.tickets.body"]
    class: no_ai
  - columns: ["public.users.ssn"]
    class: masked
    semantic_type: hashed
semantic_types:
  contact: { method: partial }
  secret: { method: redact }
  hashed: { method: hmac }
`

func setup(t *testing.T) (*config.Config, *Classifier) {
	t.Helper()
	t.Setenv("DBGW_TEST_HMAC", "k")
	cfg, err := config.Parse([]byte(yamlCfg))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, NewClassifier(cfg)
}

func id(fqn string) analysis.ColumnID {
	p := strings.Split(fqn, ".")
	return analysis.ColumnID{Schema: p[0], Table: p[1], Column: p[2]}
}

func TestClassify(t *testing.T) {
	cfg, c := setup(t)
	prod, dev := cfg.Database("prod-main"), cfg.Database("dev")
	tests := []struct {
		db    *config.Database
		col   string
		kind  identity.Kind
		class string
	}{
		{prod, "public.users.email", identity.KindHuman, "masked"},
		{prod, "public.users.id", identity.KindAgent, "public"},
		{prod, "public.users.api_token", identity.KindHuman, "masked"},
		{prod, "public.tickets.body", identity.KindAgent, "no_ai"},
		{prod, "public.users.name", identity.KindAgent, "masked"}, // unclassified on prod, agent
		{prod, "public.users.name", identity.KindHuman, "public"},
		{dev, "public.users.name", identity.KindAgent, "public"},
	}
	for _, tt := range tests {
		if got := c.Classify(tt.db, id(tt.col), tt.kind).Class; got != tt.class {
			t.Errorf("%s/%s/%s = %s, want %s", tt.db.Name, tt.col, tt.kind, got, tt.class)
		}
	}
}

func TestPlanAndApply(t *testing.T) {
	cfg, c := setup(t)
	db := cfg.Database("prod-main")
	out := []analysis.OutputColumn{
		{Name: "id", Sources: []analysis.ColumnID{id("public.users.id")}, Direct: true},
		{Name: "email", Sources: []analysis.ColumnID{id("public.users.email")}, Direct: true},
		{Name: "lower", Sources: []analysis.ColumnID{id("public.users.email")}},
		{Name: "body", Sources: []analysis.ColumnID{id("public.tickets.body")}, Direct: true},
		{Name: "mix", Sources: []analysis.ColumnID{id("public.users.id"), id("public.users.email")}},
		{Name: "ssn", Sources: []analysis.ColumnID{id("public.users.ssn")}, Direct: true},
		{Name: "count", Sources: nil},
	}
	plans, err := c.Plan(db, out, identity.KindAgent)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		t Treatment
		m string
	}{{Show, ""}, {Mask, "partial"}, {Mask, "redact"}, {Withhold, ""}, {Mask, "redact"}, {Mask, "hmac"}, {Show, ""}}
	for i, w := range want {
		if plans[i].Treatment != w.t || plans[i].Method != w.m {
			t.Errorf("col %s: got %v/%s want %v/%s", out[i].Name, plans[i].Treatment, plans[i].Method, w.t, w.m)
		}
	}
	m := NewMasker(cfg)
	if got := m.Apply("taro@example.com", "partial"); got != "t***@example.com" {
		t.Errorf("partial email = %v", got)
	}
	if got := m.Apply("090-1234-5678", "partial"); got != "0***8" {
		t.Errorf("partial phone = %v", got)
	}
	if got := m.Apply(int64(42), "partial"); got != Redacted {
		t.Errorf("partial int = %v", got)
	}
	h1, h2 := m.Apply("x", "hmac"), m.Apply("x", "hmac")
	if h1 != h2 || !strings.HasPrefix(h1.(string), "hmac:") {
		t.Errorf("hmac = %v %v", h1, h2)
	}
	if m.Apply(nil, "redact") != nil {
		t.Error("null must stay null")
	}

	if _, err := c.Plan(db, []analysis.OutputColumn{{Name: "?", Unknown: true}}, identity.KindAgent); err == nil {
		t.Error("unknown lineage must fail")
	}

	// Humans see no_ai columns.
	plans, _ = c.Plan(db, out[3:4], identity.KindHuman)
	if plans[0].Treatment != Show {
		t.Errorf("human no_ai = %v", plans[0].Treatment)
	}
}
