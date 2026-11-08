// Package mask classifies columns (public / masked / no_ai) and masks
// result values before they leave dbgateway.
package mask

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

// Classification is the data class of a column plus its semantic type.
type Classification struct {
	Class        string // public | masked | no_ai
	SemanticType string // optional
	Explicit     bool   // set by a data_classes rule (not a default)
}

// Treatment is what happens to a value for a given principal.
type Treatment int

const (
	Show     Treatment = iota // return as is
	Mask                      // return a masked value
	Withhold                  // do not return the value at all
)

// Classifier assigns classifications to columns.
type Classifier struct {
	cfg   *config.Config
	exact map[string]config.DataClass // lower-case schema.table.column
}

// NewClassifier builds a classifier from the configuration.
func NewClassifier(cfg *config.Config) *Classifier {
	c := &Classifier{cfg: cfg, exact: map[string]config.DataClass{}}
	for _, dc := range cfg.DataClasses {
		for _, col := range dc.Columns {
			k := strings.ToLower(col)
			if _, dup := c.exact[k]; !dup { // first rule wins
				c.exact[k] = dc
			}
		}
	}
	return c
}

// Classify returns the classification of a base column as seen by kind.
// Explicit column entries win over patterns; patterns are tried in order;
// unclassified columns get the default class for the principal kind.
func (c *Classifier) Classify(db *config.Database, col analysis.ColumnID, kind identity.Kind) Classification {
	fqn := col.FQN()
	if dc, ok := c.exact[strings.ToLower(fqn)]; ok {
		return Classification{Class: dc.Class, SemanticType: dc.SemanticType, Explicit: true}
	}
	for _, dc := range c.cfg.DataClasses {
		if dc.Pattern != nil && dc.Pattern.MatchString(fqn) {
			return Classification{Class: dc.Class, SemanticType: dc.SemanticType, Explicit: true}
		}
	}
	return Classification{Class: c.defaultClass(db, kind)}
}

// defaultClass resolves the class of unclassified columns: the database's
// default_class, then the global one, then the built-in default (public
// for humans; masked for agents on env=prod databases, public otherwise).
func (c *Classifier) defaultClass(db *config.Database, kind identity.Kind) string {
	pick := func(d *config.DefaultClass) string {
		if d == nil {
			return ""
		}
		if kind == identity.KindAgent {
			return d.Agent
		}
		return d.Human
	}
	if db != nil {
		if v := pick(db.DefaultClass); v != "" {
			return v
		}
	}
	if v := pick(c.cfg.DefaultClass); v != "" {
		return v
	}
	if kind == identity.KindAgent && db != nil && db.Labels["env"] == "prod" {
		return config.ClassMasked
	}
	return config.ClassPublic
}

// TreatmentFor returns how a class is handled for the principal kind.
func TreatmentFor(class string, kind identity.Kind) Treatment {
	switch class {
	case config.ClassMasked:
		return Mask
	case config.ClassNoAI:
		if kind == identity.KindAgent {
			return Withhold
		}
	}
	return Show
}

// Sensitive reports whether values of the class are hidden from kind.
func Sensitive(class string, kind identity.Kind) bool {
	return TreatmentFor(class, kind) != Show
}

// OutputPlan says how to treat one result column.
type OutputPlan struct {
	Treatment    Treatment
	Class        string
	SemanticType string
	Method       string // masking method when Treatment == Mask
}

// Plan computes the treatment for each output column from its lineage: the
// strictest source wins. Columns with unknown lineage cannot be planned and
// make Plan return an error (fail closed).
func (c *Classifier) Plan(db *config.Database, out []analysis.OutputColumn, kind identity.Kind) ([]OutputPlan, error) {
	plans := make([]OutputPlan, len(out))
	for i, o := range out {
		if o.Unknown {
			return nil, fmt.Errorf("cannot determine the source of result column %d (%q)", i+1, o.Name)
		}
		p := OutputPlan{Treatment: Show, Class: config.ClassPublic}
		for _, src := range o.Sources {
			cl := c.Classify(db, src, kind)
			t := TreatmentFor(cl.Class, kind)
			if t > p.Treatment || (t == p.Treatment && p.Class == config.ClassPublic && cl.Class != config.ClassPublic) {
				p.Treatment, p.Class, p.SemanticType = t, cl.Class, cl.SemanticType
			}
		}
		if p.Treatment == Mask {
			p.Method = config.MethodRedact
			if st, ok := c.cfg.SemanticTypes[p.SemanticType]; ok {
				p.Method = st.Method
			}
			// Format-preserving partial masking only makes sense for an
			// unmodified column; derived values are fully redacted.
			if p.Method == config.MethodPartial && (!o.Direct || len(o.Sources) != 1) {
				p.Method = config.MethodRedact
			}
		}
		plans[i] = p
	}
	return plans, nil
}

// Masker applies masking methods to values.
type Masker struct {
	key []byte
}

// NewMasker returns a masker. The HMAC key is read from the environment
// variable named in the configuration; without a key, hmac falls back to
// redact.
func NewMasker(cfg *config.Config) *Masker {
	m := &Masker{}
	if cfg.Masking.HMACKeyEnv != "" {
		m.key = []byte(os.Getenv(cfg.Masking.HMACKeyEnv))
	}
	return m
}

// Redacted is the placeholder for fully redacted values.
const Redacted = "****"

// Apply masks one value. NULL stays NULL.
func (m *Masker) Apply(v any, method string) any {
	if v == nil {
		return nil
	}
	switch method {
	case config.MethodPartial:
		if s, ok := v.(string); ok {
			return partial(s)
		}
		return Redacted
	case config.MethodHMAC:
		if len(m.key) == 0 {
			return Redacted
		}
		mac := hmac.New(sha256.New, m.key)
		fmt.Fprint(mac, v)
		return "hmac:" + hex.EncodeToString(mac.Sum(nil))[:16]
	default:
		return Redacted
	}
}

// partial keeps the first character (and an e-mail domain) visible:
// "taro@example.com" → "t***@example.com", "090-1234-5678" → "0***8".
func partial(s string) string {
	if local, domain, ok := strings.Cut(s, "@"); ok && local != "" && domain != "" {
		r, _ := utf8.DecodeRuneInString(local)
		return string(r) + "***@" + domain
	}
	n := utf8.RuneCountInString(s)
	if n <= 4 {
		return Redacted
	}
	first, _ := utf8.DecodeRuneInString(s)
	last, _ := utf8.DecodeLastRuneInString(s)
	return string(first) + "***" + string(last)
}
