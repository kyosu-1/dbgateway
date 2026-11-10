package policy

import (
	"errors"
	"fmt"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"

	"github.com/kyosu-1/dbgateway/internal/config"
)

type compiledQuota struct {
	quota *config.Quota
	prg   cel.Program // nil: matches every read
}

// compileQuotas type-checks the quota conditions.
func (e *Engine) compileQuotas(cfg *config.Config) error {
	env, err := newQuotaEnv()
	if err != nil {
		return err
	}
	var errs []error
	for i := range cfg.Quotas {
		q := &cfg.Quotas[i]
		cq := compiledQuota{quota: q}
		if q.When != "" {
			_, prg, err := compileBool(env, q.When)
			if err != nil {
				errs = append(errs, fmt.Errorf("quotas[%d] (%s).when: %w", i, q.Name, err))
				continue
			}
			cq.prg = prg
		}
		e.quotas = append(e.quotas, cq)
	}
	return errors.Join(errs...)
}

// Quotas returns the quotas whose condition matches in, in configuration
// order. A condition that fails to evaluate (e.g. a missing label)
// matches: quotas fail closed, like deny rules.
func (e *Engine) Quotas(in Input) []*config.Quota {
	if len(e.quotas) == 0 {
		return nil
	}
	act := in.activation()
	var out []*config.Quota
	for _, cq := range e.quotas {
		if cq.prg != nil {
			res, _, err := cq.prg.Eval(act)
			if err == nil && res != types.True {
				continue
			}
		}
		out = append(out, cq.quota)
	}
	return out
}
