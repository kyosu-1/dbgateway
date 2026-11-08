package scim

import (
	"encoding/json"
	"strings"
)

// maxFilterLen bounds the filter and path expressions.
const maxFilterLen = 1024

// filterTerm is one `attr eq value` comparison. attr is lower case and
// dotted ("username", "emails.value", "members.value"); a bracket filter
// such as members[value eq "x"] is turned into "members.value".
type filterTerm struct {
	attr  string
	value string
}

// parseFilter parses the filters IdPs send: one or more `attr eq "value"`
// terms joined by "and". Anything else (or, not, other operators,
// parentheses) is rejected with invalidFilter.
func parseFilter(s string) ([]filterTerm, error) {
	if len(s) > maxFilterLen {
		return nil, badRequest("invalidFilter", "filter too long")
	}
	p := &exprParser{s: s}
	var terms []filterTerm
	for {
		p.skipSpace()
		t, err := p.term()
		if err != nil {
			return nil, err
		}
		terms = append(terms, t)
		p.skipSpace()
		if p.eof() {
			return terms, nil
		}
		if kw := p.word(); !strings.EqualFold(kw, "and") {
			return nil, badRequest("invalidFilter", "unsupported filter: only 'eq' comparisons joined by 'and' are supported")
		}
	}
}

type exprParser struct {
	s   string
	pos int
}

func (p *exprParser) eof() bool { return p.pos >= len(p.s) }

func (p *exprParser) skipSpace() {
	for !p.eof() && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t') {
		p.pos++
	}
}

// word reads an attribute path or keyword: letters, digits, '.', ':', '_',
// '-' and '$'.
func (p *exprParser) word() string {
	start := p.pos
	for !p.eof() {
		c := p.s[p.pos]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(".:_-$", c) >= 0 {
			p.pos++
			continue
		}
		break
	}
	return p.s[start:p.pos]
}

// term parses `attr eq value` or `attr[sub eq value]`.
func (p *exprParser) term() (filterTerm, error) {
	attr := p.word()
	if attr == "" {
		return filterTerm{}, badRequest("invalidFilter", "expected an attribute name at offset %d", p.pos)
	}
	attr = normalizeAttr(attr)
	if !p.eof() && p.s[p.pos] == '[' {
		p.pos++
		p.skipSpace()
		inner, err := p.term()
		if err != nil {
			return filterTerm{}, err
		}
		p.skipSpace()
		if p.eof() || p.s[p.pos] != ']' {
			return filterTerm{}, badRequest("invalidFilter", "expected ']'")
		}
		p.pos++
		return filterTerm{attr: attr + "." + inner.attr, value: inner.value}, nil
	}
	p.skipSpace()
	if op := p.word(); !strings.EqualFold(op, "eq") {
		return filterTerm{}, badRequest("invalidFilter", "unsupported operator %q: only 'eq' is supported", op)
	}
	p.skipSpace()
	v, err := p.value()
	if err != nil {
		return filterTerm{}, err
	}
	return filterTerm{attr: attr, value: v}, nil
}

// value parses a JSON string or a bare literal (true, false, a number).
func (p *exprParser) value() (string, error) {
	if p.eof() {
		return "", badRequest("invalidFilter", "expected a value")
	}
	if p.s[p.pos] != '"' {
		v := p.word()
		if v == "" {
			return "", badRequest("invalidFilter", "expected a value at offset %d", p.pos)
		}
		return strings.ToLower(v), nil
	}
	start := p.pos
	p.pos++
	for !p.eof() {
		switch p.s[p.pos] {
		case '\\':
			p.pos += 2
			continue
		case '"':
			p.pos++
			var v string
			if err := json.Unmarshal([]byte(p.s[start:p.pos]), &v); err != nil {
				return "", badRequest("invalidFilter", "invalid string value")
			}
			return v, nil
		}
		p.pos++
	}
	return "", badRequest("invalidFilter", "unterminated string")
}

// Core schema URNs that may prefix attribute names.
var corePrefixes = []string{
	strings.ToLower(schemaUser) + ":",
	strings.ToLower(schemaGroup) + ":",
}

// normalizeAttr lower-cases an attribute path and strips a core schema URN
// prefix. Extension attributes keep their URN (and are ignored by the
// callers).
func normalizeAttr(a string) string {
	a = strings.ToLower(a)
	for _, p := range corePrefixes {
		if rest, ok := strings.CutPrefix(a, p); ok {
			return rest
		}
	}
	return a
}

// attrPath is a parsed PATCH path: attr, attr.sub, attr[filter] or
// attr[filter].sub (all lower case).
type attrPath struct {
	attr   string
	filter *filterTerm // inner comparison of attr[...], attr relative to attr
	sub    string
}

func parsePath(s string) (attrPath, error) {
	if len(s) > maxFilterLen {
		return attrPath{}, badRequest("invalidPath", "path too long")
	}
	p := &exprParser{s: strings.TrimSpace(s)}
	// Read the attribute up to '[' or the end. URNs contain dots and
	// colons, so split the sub-attribute off after normalising.
	head := p.word()
	if head == "" {
		return attrPath{}, badRequest("invalidPath", "invalid path %q", s)
	}
	head = normalizeAttr(head)
	var ap attrPath
	if strings.HasPrefix(head, "urn:") {
		ap.attr = head // extension attribute
	} else {
		ap.attr, ap.sub, _ = strings.Cut(head, ".")
	}
	if !p.eof() && p.s[p.pos] == '[' {
		if ap.sub != "" {
			return attrPath{}, badRequest("invalidPath", "invalid path %q", s)
		}
		p.pos++
		p.skipSpace()
		inner, err := p.term()
		if err != nil {
			return attrPath{}, badRequest("invalidPath", "invalid path filter in %q", s)
		}
		p.skipSpace()
		if p.eof() || p.s[p.pos] != ']' {
			return attrPath{}, badRequest("invalidPath", "invalid path %q", s)
		}
		p.pos++
		ap.filter = &inner
		if !p.eof() {
			if p.s[p.pos] != '.' {
				return attrPath{}, badRequest("invalidPath", "invalid path %q", s)
			}
			p.pos++
			ap.sub = strings.ToLower(p.word())
			if ap.sub == "" {
				return attrPath{}, badRequest("invalidPath", "invalid path %q", s)
			}
		}
	}
	if !p.eof() {
		return attrPath{}, badRequest("invalidPath", "invalid path %q", s)
	}
	return ap, nil
}
