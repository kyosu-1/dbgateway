// Package policytest runs policy test files: "this SQL, by this principal,
// on this database, must get this decision". It needs no database: the
// catalog is declared in the test file, so it runs in CI.
package policytest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kyosu-1/dbgateway/internal/adapter/mysql"
	"github.com/kyosu-1/dbgateway/internal/adapter/postgres"
	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/mask"
)

// File is a policy test file.
type File struct {
	// Config is the configuration to test, relative to the test file.
	// Overridden by the --config flag.
	Config     string               `yaml:"config"`
	Catalog    Catalog              `yaml:"catalog"`
	Principals map[string]Principal `yaml:"principals"`
	Cases      []Case               `yaml:"cases"`
}

// Catalog declares the relations used for name resolution.
type Catalog struct {
	SearchPath []string   `yaml:"search_path"`
	Relations  []Relation `yaml:"relations"`
}

// Relation is a table or view.
type Relation struct {
	Name       string   `yaml:"name"` // schema.name
	Kind       string   `yaml:"kind"` // table (default) | view | materialized_view
	Columns    []string `yaml:"columns"`
	Definition string   `yaml:"definition"`
}

// Principal is a caller. Groups are dbgateway group names.
type Principal struct {
	Kind      string   `yaml:"kind"` // human | agent
	Human     string   `yaml:"human"`
	Agent     string   `yaml:"agent"`
	Groups    []string `yaml:"groups"`
	Scopes    []string `yaml:"scopes"`
	Databases []string `yaml:"databases"`
}

// Case is one expectation.
type Case struct {
	Name      string     `yaml:"name"`
	Principal yaml.Node  `yaml:"principal"` // name from principals, or inline
	Database  string     `yaml:"database"`
	SQL       string     `yaml:"sql"`
	Estimate  *Estimate  `yaml:"estimate"`
	Expect    Expectancy `yaml:"expect"`
}

// Estimate stubs the planner estimate.
type Estimate struct {
	Rows float64 `yaml:"rows"`
	Cost float64 `yaml:"cost"`
}

// Expectancy is the expected outcome. Empty fields are not checked.
type Expectancy struct {
	Decision     string   `yaml:"decision"` // allow | approve | deny
	Rule         string   `yaml:"rule"`
	Stage        string   `yaml:"stage"`
	Risk         string   `yaml:"risk"`          // low | medium | high
	ApprovalRule string   `yaml:"approval_rule"` // matched approval rule (approve)
	Masked       []string `yaml:"masked"`        // output columns that must be masked
	Withheld     []string `yaml:"withheld"`      // output columns that must be withheld
	Visible      []string `yaml:"visible"`       // output columns that must be shown as is
}

// Result is the outcome of one case.
type Result struct {
	Name     string
	Passed   bool
	Failures []string
	Got      string
}

// Load reads a test file.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.Config != "" && !filepath.IsAbs(f.Config) {
		f.Config = filepath.Join(filepath.Dir(path), f.Config)
	}
	return &f, nil
}

func (f *File) catalog() (*analysis.Catalog, error) {
	sp := f.Catalog.SearchPath
	if len(sp) == 0 {
		sp = []string{"public"}
	}
	cat := analysis.NewCatalog(sp, []string{"pg_catalog"})
	for _, r := range f.Catalog.Relations {
		schema, name, ok := strings.Cut(r.Name, ".")
		if !ok {
			return nil, fmt.Errorf("catalog: relation %q must be schema.name", r.Name)
		}
		kind := analysis.RelKind(r.Kind)
		if kind == "" {
			kind = analysis.RelTable
		}
		rel := &analysis.Relation{Schema: schema, Name: name, Kind: kind, Definition: r.Definition}
		for _, c := range r.Columns {
			rel.Columns = append(rel.Columns, analysis.Column{Name: c, Type: "unknown"})
		}
		cat.Add(rel)
	}
	return cat, nil
}

func (f *File) principal(n yaml.Node) (*identity.Principal, error) {
	var p Principal
	switch n.Kind {
	case yaml.ScalarNode:
		var ok bool
		if p, ok = f.Principals[n.Value]; !ok {
			return nil, fmt.Errorf("unknown principal %q", n.Value)
		}
	case yaml.MappingNode:
		if err := n.Decode(&p); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("principal is required")
	}
	out := &identity.Principal{Kind: identity.Kind(p.Kind), Human: p.Human, Agent: p.Agent, Groups: p.Groups, Scopes: p.Scopes, Databases: p.Databases}
	switch out.Kind {
	case identity.KindHuman:
	case identity.KindAgent:
		if out.Scopes == nil {
			out.Scopes = []string{identity.ScopeRead}
		}
	default:
		return nil, fmt.Errorf("principal kind must be human or agent")
	}
	return out, nil
}

// Run evaluates every case against cfg.
func Run(ctx context.Context, f *File, cfg *config.Config) ([]Result, error) {
	ev, err := gateway.NewEvaluator(cfg)
	if err != nil {
		return nil, err
	}
	cat, err := f.catalog()
	if err != nil {
		return nil, err
	}
	analyzers := map[string]gateway.Analyzer{
		"postgres": postgres.NewAnalyzer(postgres.NewFunctionAllowlist(cfg.SQL.AllowedFunctions)),
		"mysql":    mysql.NewAnalyzer(mysql.NewFunctionAllowlist(cfg.SQL.AllowedFunctions)),
	}
	var results []Result
	for i, c := range f.Cases {
		name := c.Name
		if name == "" {
			name = fmt.Sprintf("case %d", i+1)
		}
		r := Result{Name: name}
		fail := func(format string, args ...any) { r.Failures = append(r.Failures, fmt.Sprintf(format, args...)) }

		p, err := f.principal(c.Principal)
		db := cfg.Database(c.Database)
		switch {
		case err != nil:
			fail("%v", err)
		case db == nil:
			fail("unknown database %q", c.Database)
		}
		if len(r.Failures) > 0 {
			results = append(results, r)
			continue
		}
		var est gateway.EstimateFunc
		if c.Estimate != nil {
			e := &analysis.Estimate{Rows: c.Estimate.Rows, Cost: c.Estimate.Cost}
			est = func(context.Context, bool) (*analysis.Estimate, error) { return e, nil }
		} else {
			est = func(context.Context, bool) (*analysis.Estimate, error) { return &analysis.Estimate{}, nil }
		}
		analyzer, ok := analyzers[db.Type]
		if !ok {
			fail("no analyzer for database type %q", db.Type)
			results = append(results, r)
			continue
		}
		out := ev.Evaluate(ctx, p, db, analyzer, c.SQL, cat, est)
		d := out.Decision
		approvalRule := ""
		if d.ApprovalRule != nil {
			approvalRule = d.ApprovalRule.Name
		}
		r.Got = fmt.Sprintf("%s (stage=%s rule=%s risk=%s)", d.Action, d.Stage, d.Rule, d.Risk)
		if approvalRule != "" {
			r.Got += " approval_rule=" + approvalRule
		}
		if d.ShadowDeniedBy != "" {
			r.Got += " shadow_denied_by=" + d.ShadowDeniedBy
		}
		exp := c.Expect
		if exp.Decision != "" && exp.Decision != d.Action {
			fail("decision: got %s, want %s (%s)", d.Action, exp.Decision, d.Message)
		}
		if exp.Rule != "" && exp.Rule != d.Rule {
			fail("rule: got %s, want %s", d.Rule, exp.Rule)
		}
		if exp.Stage != "" && exp.Stage != string(d.Stage) {
			fail("stage: got %s, want %s", d.Stage, exp.Stage)
		}
		if exp.Risk != "" && exp.Risk != d.Risk {
			fail("risk: got %s, want %s", d.Risk, exp.Risk)
		}
		if exp.ApprovalRule != "" && exp.ApprovalRule != approvalRule {
			fail("approval_rule: got %q, want %s", approvalRule, exp.ApprovalRule)
		}
		if len(exp.Masked)+len(exp.Withheld)+len(exp.Visible) > 0 {
			checkMasking(ev, db, p, out, exp, fail)
		}
		r.Passed = len(r.Failures) == 0
		results = append(results, r)
	}
	return results, nil
}

func checkMasking(ev *gateway.Evaluator, db *config.Database, p *identity.Principal, out *gateway.Evaluation, exp Expectancy, fail func(string, ...any)) {
	if out.Analysis == nil {
		fail("masking: statement was not analyzed")
		return
	}
	plans, err := ev.Classifier.Plan(db, out.Analysis.Output, p.Kind)
	if err != nil {
		fail("masking: %v", err)
		return
	}
	treatment := map[string]mask.Treatment{}
	for i, o := range out.Analysis.Output {
		treatment[o.Name] = plans[i].Treatment
	}
	check := func(names []string, want mask.Treatment, label string) {
		for _, n := range names {
			t, ok := treatment[n]
			switch {
			case !ok:
				fail("masking: no output column %q (have %v)", n, keys(treatment))
			case t != want:
				fail("masking: column %q is not %s", n, label)
			}
		}
	}
	check(exp.Masked, mask.Mask, "masked")
	check(exp.Withheld, mask.Withhold, "withheld")
	check(exp.Visible, mask.Show, "visible")
}

func keys(m map[string]mask.Treatment) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
