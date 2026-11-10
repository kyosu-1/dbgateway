package lint

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is a lint configuration file. Unknown keys are errors.
//
//	dialect: postgres
//	rules:
//	  pg/prefer-text: off
//	  pg/drop-column: error
//	ignore:
//	  - files: ["migrations/0001_*.sql"]
//	    rules: [pg/require-primary-key]
type Config struct {
	// Dialect is the default dialect; the --dialect flag overrides it.
	Dialect string `yaml:"dialect"`
	// Rules changes the severity of rules: error, warning, info or off.
	Rules map[string]string `yaml:"rules"`
	// Ignore turns rules off for some files.
	Ignore []Ignore `yaml:"ignore"`
}

// Ignore turns rules off for files matching a pattern.
type Ignore struct {
	// Files are glob patterns: * and ? match within a path segment, **
	// matches any number of segments. A pattern without a slash matches the
	// file name in any directory.
	Files []string `yaml:"files"`
	// Rules to turn off. Empty: the files are not checked at all.
	Rules []string `yaml:"rules"`
}

// LoadConfig reads a configuration file.
func LoadConfig(file string) (*Config, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	cfg, err := ParseConfig(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return cfg, nil
}

// ParseConfig parses and validates a configuration.
func ParseConfig(b []byte) (*Config, error) {
	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	var errs []error
	if c.Dialect != "" {
		if _, err := ParseDialect(c.Dialect); err != nil {
			errs = append(errs, err)
		}
	}
	ids := make([]string, 0, len(c.Rules))
	for id := range c.Rules {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if _, ok := registry[id]; !ok {
			errs = append(errs, fmt.Errorf("rules: unknown rule %q", id))
			continue
		}
		if v := c.Rules[id]; v != "off" {
			if _, err := ParseSeverity(v); err != nil {
				errs = append(errs, fmt.Errorf("rules: %s: %w", id, err))
			}
		}
	}
	for i, ig := range c.Ignore {
		if len(ig.Files) == 0 {
			errs = append(errs, fmt.Errorf("ignore[%d]: files is required", i))
		}
		for _, f := range ig.Files {
			if strings.TrimSpace(f) == "" {
				errs = append(errs, fmt.Errorf("ignore[%d]: empty file pattern", i))
			}
		}
		for _, id := range ig.Rules {
			if _, ok := registry[id]; !ok {
				errs = append(errs, fmt.Errorf("ignore[%d]: unknown rule %q", i, id))
			}
		}
	}
	return errors.Join(errs...)
}

// glob is a compiled file pattern.
type glob struct {
	re       *regexp.Regexp
	baseOnly bool // the pattern has no slash: match the file name only
}

func compileGlob(pattern string) glob {
	pattern = cleanPath(pattern)
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; {
		case c == '*' && strings.HasPrefix(pattern[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case c == '*' && strings.HasPrefix(pattern[i:], "**"):
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
	}
	b.WriteString("$")
	return glob{re: regexp.MustCompile(b.String()), baseOnly: !strings.Contains(pattern, "/")}
}

func (g glob) match(name string) bool {
	if g.baseOnly {
		name = path.Base(name)
	}
	return g.re.MatchString(name)
}
