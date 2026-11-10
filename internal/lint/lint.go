// Package lint reviews SQL migration files offline. It parses them with the
// same parsers the gateway uses (pg_query for PostgreSQL, the TiDB parser for
// MySQL) and reports statements that are likely to cause an outage or lose
// data when applied to a production database: locks held for a long time,
// table rewrites, destructive changes and changes that break running code.
//
// It never connects to a database. Whether a table already exists is judged
// from the file alone: a table created earlier in the same file is new, any
// other table is assumed to exist and hold data.
package lint

import (
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

// Dialect is the SQL dialect of the files.
type Dialect string

// Dialects.
const (
	Postgres Dialect = "postgres"
	MySQL    Dialect = "mysql"
)

// ParseDialect parses a dialect name.
func ParseDialect(s string) (Dialect, error) {
	switch strings.ToLower(s) {
	case "postgres", "postgresql":
		return Postgres, nil
	case "mysql":
		return MySQL, nil
	}
	return "", fmt.Errorf("unknown dialect %q (use postgres or mysql)", s)
}

// Severity is how serious a finding is. Only errors make the command fail.
type Severity int

// Severities, from least to most serious.
const (
	SeverityInfo Severity = iota + 1
	SeverityWarning
	SeverityError
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityError:
		return "error"
	}
	return "unknown"
}

// MarshalText implements encoding.TextMarshaler.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity parses error, warning or info.
func ParseSeverity(s string) (Severity, error) {
	switch s {
	case "error":
		return SeverityError, nil
	case "warning":
		return SeverityWarning, nil
	case "info":
		return SeverityInfo, nil
	}
	return 0, fmt.Errorf("unknown severity %q (use error, warning, info or off)", s)
}

// Rule describes one check.
type Rule struct {
	ID       string
	Dialect  Dialect
	Severity Severity // default severity
	Summary  string   // what is reported
	Hint     string   // how to fix it
}

// SyntaxErrorRule is reported when a file cannot be parsed. It is always an
// error and cannot be disabled or suppressed: nothing else in the file was
// checked.
const SyntaxErrorRule = "syntax-error"

var registry = map[string]Rule{}

func register(rs ...Rule) {
	for _, r := range rs {
		if _, dup := registry[r.ID]; dup {
			panic("lint: duplicate rule " + r.ID)
		}
		registry[r.ID] = r
	}
}

// Rules returns the rules of a dialect (all dialects when d is empty),
// sorted by ID.
func Rules(d Dialect) []Rule {
	var out []Rule
	for _, r := range registry {
		if d == "" || r.Dialect == d {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b Rule) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Finding is one problem in a file.
type Finding struct {
	File     string   `json:"file"`
	Line     int      `json:"line"`   // 1-based
	Column   int      `json:"column"` // 1-based, in characters
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Hint     string   `json:"hint,omitempty"`
}

// Linter checks files of one dialect with a configuration.
type Linter struct {
	dialect  Dialect
	severity map[string]Severity // enabled rules
	ignore   []ignoreEntry
}

// New returns a linter. cfg may be nil for the defaults.
func New(d Dialect, cfg *Config) (*Linter, error) {
	l := &Linter{dialect: d, severity: map[string]Severity{}}
	for _, r := range Rules(d) {
		l.severity[r.ID] = r.Severity
	}
	if cfg == nil {
		return l, nil
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	for id, v := range cfg.Rules {
		if registry[id].Dialect != d {
			continue
		}
		if v == "off" {
			delete(l.severity, id)
			continue
		}
		l.severity[id], _ = ParseSeverity(v)
	}
	for _, ig := range cfg.Ignore {
		e := ignoreEntry{rules: map[string]bool{}}
		for _, f := range ig.Files {
			e.files = append(e.files, compileGlob(f))
		}
		for _, id := range ig.Rules {
			e.rules[id] = true
		}
		l.ignore = append(l.ignore, e)
	}
	return l, nil
}

// raw is a finding before positions, configuration and suppressions are
// applied.
type raw struct {
	offset int // byte offset in the file
	stmt   int // statement index, -1 if none
	rule   string
	msg    string
}

// span is a statement: start is its first token (after leading comments).
type span struct{ start, end int }

// comment is a comment in the file.
type comment struct {
	offset int
	text   string
}

// result is what a dialect's checker produces for one file.
type result struct {
	findings []raw
	stmts    []span
	comments []comment
	syntax   *raw // set when the file could not be parsed
}

// Lint checks one file. name is used for reporting and for the
// configuration's ignore patterns.
func (l *Linter) Lint(name string, src []byte) []Finding {
	ignored := map[string]bool{}
	for _, e := range l.ignore {
		if !e.matches(name) {
			continue
		}
		if len(e.rules) == 0 {
			return nil // the whole file is ignored
		}
		for id := range e.rules {
			ignored[id] = true
		}
	}

	text := string(src)
	var res result
	switch l.dialect {
	case MySQL:
		res = checkMySQL(text)
	default:
		res = checkPostgres(text)
	}
	lines := newLineIndex(text)
	if res.syntax != nil {
		line, col := lines.position(res.syntax.offset)
		return []Finding{{
			File: name, Line: line, Column: col, Rule: SyntaxErrorRule, Severity: SeverityError,
			Message: res.syntax.msg,
			Hint:    "Fix the syntax error; the file was not checked otherwise.",
		}}
	}

	dirs := directives(res.comments, res.stmts, lines)
	var out []Finding
	for _, f := range res.findings {
		sev, enabled := l.severity[f.rule]
		if !enabled || ignored[f.rule] {
			continue
		}
		line, col := lines.position(f.offset)
		if suppressed(dirs, f, line) {
			continue
		}
		out = append(out, Finding{
			File: name, Line: line, Column: col, Rule: f.rule, Severity: sev,
			Message: f.msg, Hint: registry[f.rule].Hint,
		})
	}
	slices.SortStableFunc(out, func(a, b Finding) int {
		if a.Line != b.Line {
			return a.Line - b.Line
		}
		if a.Column != b.Column {
			return a.Column - b.Column
		}
		return strings.Compare(a.Rule, b.Rule)
	})
	return out
}

// directive is an inline suppression comment:
//
//	-- dbgw-lint-ignore pg/rule-id[, pg/other-rule] [-- reason]
//
// On a line of its own it applies to the statement that follows it and to
// the line below it. After code on the same line it applies to that line
// and to the statement that ends before it on that line. Without rule IDs
// it suppresses every rule.
type directive struct {
	line     int
	trailing bool
	stmt     int // index of the statement it applies to, -1 if none
	rules    map[string]bool
}

const directiveKeyword = "dbgw-lint-ignore"

func directives(comments []comment, stmts []span, lines lineIndex) []directive {
	var out []directive
	for _, c := range comments {
		body := strings.TrimSpace(c.text)
		for _, p := range []string{"--", "#", "/*"} {
			if strings.HasPrefix(body, p) {
				body = strings.TrimSpace(strings.TrimPrefix(body, p))
				break
			}
		}
		body = strings.TrimSpace(strings.TrimSuffix(body, "*/"))
		rest, ok := strings.CutPrefix(body, directiveKeyword)
		if !ok || (rest != "" && rest[0] != ' ' && rest[0] != '\t' && rest[0] != ',') {
			continue
		}
		d := directive{stmt: -1, rules: map[string]bool{}}
		d.line, _ = lines.position(c.offset)
		for _, f := range strings.FieldsFunc(rest, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' }) {
			if strings.HasPrefix(f, "--") {
				break // the rest is the reason
			}
			if strings.Contains(f, "/") {
				d.rules[f] = true
			}
		}
		lineStart := lines.starts[d.line-1]
		d.trailing = strings.TrimSpace(lines.src[lineStart:c.offset]) != ""
		if d.trailing {
			for i := len(stmts) - 1; i >= 0; i-- {
				if stmts[i].start < c.offset {
					if stmts[i].end <= c.offset && stmts[i].end >= lineStart {
						d.stmt = i
					}
					break
				}
			}
		} else {
			for i, s := range stmts {
				if s.start >= c.offset {
					d.stmt = i
					break
				}
			}
		}
		out = append(out, d)
	}
	return out
}

func suppressed(dirs []directive, f raw, line int) bool {
	for _, d := range dirs {
		if len(d.rules) > 0 && !d.rules[f.rule] {
			continue
		}
		target := d.line + 1
		if d.trailing {
			target = d.line
		}
		if (d.stmt >= 0 && d.stmt == f.stmt) || line == target {
			return true
		}
	}
	return false
}

// lineIndex maps byte offsets to line and column.
type lineIndex struct {
	src    string
	starts []int
}

func newLineIndex(src string) lineIndex {
	starts := []int{0}
	for i := 0; i < len(src); i++ {
		if src[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return lineIndex{src: src, starts: starts}
}

// position returns the 1-based line and column (in characters) of a byte
// offset.
func (li lineIndex) position(offset int) (line, col int) {
	offset = max(0, min(offset, len(li.src)))
	i, found := slices.BinarySearch(li.starts, offset)
	if !found {
		i--
	}
	return i + 1, utf8.RuneCountInString(li.src[li.starts[i]:offset]) + 1
}

// offsetOf returns the byte offset of a 1-based line and byte column.
func (li lineIndex) offsetOf(line, col int) int {
	if line < 1 {
		return 0
	}
	if line > len(li.starts) {
		return len(li.src)
	}
	return min(li.starts[line-1]+max(col-1, 0), len(li.src))
}

// ignoreEntry is a compiled Config.Ignore entry.
type ignoreEntry struct {
	files []glob
	rules map[string]bool // empty: the whole file
}

func (e ignoreEntry) matches(name string) bool {
	name = cleanPath(name)
	for _, g := range e.files {
		if g.match(name) {
			return true
		}
	}
	return false
}

func cleanPath(p string) string {
	p = path.Clean(filepath.ToSlash(p))
	return strings.TrimPrefix(p, "./")
}
