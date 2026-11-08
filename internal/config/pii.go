package config

import "slices"

// PII detectors.
const (
	PIIEmail      = "email"
	PIIPhoneJP    = "phone_jp"
	PIICreditCard = "credit_card"
	PIIMyNumber   = "my_number"
)

// PIIDetectors lists every known detector, in evaluation order.
var PIIDetectors = []string{PIIEmail, PIIPhoneJP, PIICreditCard, PIIMyNumber}

// PII detection actions.
const (
	// PIIActionMask replaces the detected spans with a placeholder.
	PIIActionMask = "mask"
	// PIIActionDeny refuses to return the whole result.
	PIIActionDeny = "deny"
)

// PIIDetection configures value-based PII detection on the public columns
// returned to agents. It is a safety net for columns that were not
// classified, not a replacement for data_classes.
//
//	pii_detection:
//	  enabled: true
//	  detectors: [email, phone_jp, credit_card, my_number]
//	  action: mask            # mask | deny
type PIIDetection struct {
	Enabled bool `yaml:"enabled"`
	// Detectors to run. Empty means all of them.
	Detectors []string `yaml:"detectors"`
	// Action is mask (default) or deny.
	Action string `yaml:"action"`
}

// validate checks the section and fills in the defaults (all detectors,
// action mask).
func (p *PIIDetection) validate(add func(string, ...any)) {
	if p.Action == "" {
		p.Action = PIIActionMask
	}
	if p.Action != PIIActionMask && p.Action != PIIActionDeny {
		add("pii_detection.action: must be %q or %q", PIIActionMask, PIIActionDeny)
	}
	if len(p.Detectors) == 0 {
		p.Detectors = slices.Clone(PIIDetectors)
		return
	}
	seen := map[string]bool{}
	for i, d := range p.Detectors {
		switch {
		case !slices.Contains(PIIDetectors, d):
			add("pii_detection.detectors[%d]: unknown detector %q (known: email, phone_jp, credit_card, my_number)", i, d)
		case seen[d]:
			add("pii_detection.detectors[%d]: duplicate %q", i, d)
		}
		seen[d] = true
	}
}
