package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that accepts Go duration strings plus a "d"
// (day) suffix, e.g. "90d" or "1h30m".
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

var dayRe = regexp.MustCompile(`^(\d+)d(.*)$`)

// ParseDuration parses a duration string, additionally accepting a leading
// day component such as "7d" or "1d12h".
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	var total time.Duration
	if m := dayRe.FindStringSubmatch(s); m != nil {
		days, _ := strconv.Atoi(m[1])
		total = time.Duration(days) * 24 * time.Hour
		s = m[2]
		if s == "" {
			return total, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return total + d, nil
}

// ByteSize is a size in bytes that accepts units such as "512KiB", "1MiB",
// "1MB" or a plain integer.
type ByteSize int64

func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := ParseByteSize(s)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*b = ByteSize(v)
	return nil
}

var sizeRe = regexp.MustCompile(`^(\d+)\s*([KMG]i?B|B)?$`)

// ParseByteSize parses a human-readable byte size.
func ParseByteSize(s string) (int64, error) {
	m := sizeRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("invalid byte size %q", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid byte size %q", s)
	}
	mult := map[string]int64{
		"": 1, "B": 1,
		"KB": 1000, "MB": 1000 * 1000, "GB": 1000 * 1000 * 1000,
		"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30,
	}[m[2]]
	return n * mult, nil
}

// DatabaseSelector selects databases either by name, by labels, or all ("*").
//
// YAML forms:
//
//	databases: "*"
//	databases: ["prod-main", "staging"]
//	databases: { labels: { env: prod } }
type DatabaseSelector struct {
	All    bool
	Names  []string
	Labels map[string]string
}

func (s *DatabaseSelector) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var v string
		if err := n.Decode(&v); err != nil {
			return err
		}
		if v == "*" {
			s.All = true
			return nil
		}
		s.Names = []string{v}
		return nil
	case yaml.SequenceNode:
		return n.Decode(&s.Names)
	case yaml.MappingNode:
		var m struct {
			Labels map[string]string `yaml:"labels"`
		}
		dec := n
		if err := dec.Decode(&m); err != nil {
			return err
		}
		if len(m.Labels) == 0 {
			return fmt.Errorf("line %d: database selector map must have non-empty labels", n.Line)
		}
		s.Labels = m.Labels
		return nil
	}
	return fmt.Errorf("line %d: invalid database selector", n.Line)
}

// Matches reports whether the database is selected.
func (s DatabaseSelector) Matches(db *Database) bool {
	if s.All {
		return true
	}
	for _, n := range s.Names {
		if n == db.Name {
			return true
		}
	}
	if len(s.Labels) > 0 {
		for k, v := range s.Labels {
			if db.Labels[k] != v {
				return false
			}
		}
		return true
	}
	return false
}
