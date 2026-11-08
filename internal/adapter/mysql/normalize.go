package mysql

import (
	"strings"
	"unicode/utf8"

	"github.com/kyosu-1/dbgateway/internal/analysis"
)

// checkText rejects inputs on which the TiDB parser and the MySQL server
// could disagree about where comments, strings and statements are. It runs
// before parsing and is deliberately context-free (a forbidden sequence is
// rejected even inside a string literal) so that it cannot itself be
// confused by quoting.
//
//   - /*! ... */ and /*!NNNNN ... */: MySQL executes the content only when
//     its version is at least NNNNN, while the parser always includes it, so
//     the analyzed statement could differ from the executed one.
//   - /*T! ... */ (TiDB) and /*M! ... */ (MariaDB): treated as plain
//     comments by MySQL but possibly parsed by TiDB.
//   - /*+ ... */ optimizer hints: MAX_EXECUTION_TIME and SET_VAR can lift
//     the session limits dbgateway sets.
//   - control characters and invalid UTF-8: MySQL and the parser treat some
//     of them differently around "--" comments and whitespace.
func checkText(sql string) *analysis.Rejection {
	if !utf8.ValidString(sql) {
		return analysis.Reject("invalid_text", "The SQL contains invalid UTF-8 byte sequences.", "Send the SQL as UTF-8 text.")
	}
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return analysis.Reject("invalid_text", "The SQL contains control characters.", "Remove control characters other than newlines and tabs.")
		}
	}
	for _, p := range []struct{ seq, what string }{
		{"/*!", "executable comments (/*! ... */)"},
		{"/*+", "optimizer hints (/*+ ... */)"},
		{"/*T!", "TiDB executable comments (/*T! ... */)"},
		{"/*M!", "MariaDB executable comments (/*M! ... */)"},
	} {
		if strings.Contains(sql, p.seq) {
			code := "executable_comment"
			if p.seq == "/*+" {
				code = "optimizer_hint"
			}
			return analysis.Reject(code,
				"SQL containing "+p.what+" cannot be run, because what actually runs could differ from what was analyzed (this applies even inside string literals).",
				"Remove the comments or hints and send only the SQL statement itself.")
		}
	}
	return nil
}

// normalizeText replaces literal values with "?" and drops comments. It
// lexes with the fixed session SQL mode (ANSI_QUOTES and
// NO_BACKSLASH_ESCAPES): '...' is a string where only a doubled quote escapes a quote,
// "..." and `...` are identifiers. It returns "" for input it cannot lex.
func normalizeText(sql string) string {
	var b strings.Builder
	b.Grow(len(sql))
	prevWord := false // previous significant token was an identifier, keyword or ')'
	n := len(sql)
	for i := 0; i < n; {
		c := sql[i]
		switch {
		case isSpace(c):
			b.WriteByte(c)
			i++
			continue
		case c == '#':
			i = skipLine(sql, i)
			space(&b, sql, i)
			continue
		case c == '-' && i+1 < n && sql[i+1] == '-' && (i+2 == n || sql[i+2] <= ' '):
			i = skipLine(sql, i)
			space(&b, sql, i)
			continue
		case c == '/' && i+1 < n && sql[i+1] == '*':
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return ""
			}
			i += 2 + end + 2
			space(&b, sql, i)
			continue
		case c == '\'':
			end, ok := skipQuoted(sql, i, '\'')
			if !ok {
				return ""
			}
			b.WriteByte('?')
			i = end
			prevWord = false
			continue
		case c == '"' || c == '`':
			end, ok := skipQuoted(sql, i, c)
			if !ok {
				return ""
			}
			b.WriteString(sql[i:end])
			i = end
			prevWord = true
			continue
		case isDigit(c) || (c == '.' && i+1 < n && isDigit(sql[i+1]) && !prevWord):
			if end := scanNumber(sql, i); end > i {
				b.WriteByte('?')
				i = end
				prevWord = false
				continue
			}
		}
		if isWordByte(c) {
			j := i
			for j < n && isWordByte(sql[j]) {
				j++
			}
			word := sql[i:j]
			// Introducers: N'..', X'..', B'..', _charset'..'.
			if j < n && sql[j] == '\'' && isIntroducer(word) {
				end, ok := skipQuoted(sql, j, '\'')
				if !ok {
					return ""
				}
				b.WriteByte('?')
				i = end
				prevWord = false
				continue
			}
			b.WriteString(word)
			i = j
			prevWord = true
			continue
		}
		b.WriteByte(c)
		prevWord = c == ')'
		i++
	}
	return strings.TrimSpace(b.String())
}

// space separates the tokens around a dropped comment, unless whitespace
// already does.
func space(b *strings.Builder, s string, next int) {
	out := b.String()
	if out == "" || isSpace(out[len(out)-1]) || (next < len(s) && isSpace(s[next])) {
		return
	}
	b.WriteByte(' ')
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func skipLine(s string, i int) int {
	if j := strings.IndexByte(s[i:], '\n'); j >= 0 {
		return i + j
	}
	return len(s)
}

// skipQuoted returns the index just past the quoted token starting at i.
// A doubled quote character escapes itself.
func skipQuoted(s string, i int, q byte) (int, bool) {
	for j := i + 1; j < len(s); j++ {
		if s[j] == q {
			if j+1 < len(s) && s[j+1] == q {
				j++
				continue
			}
			return j + 1, true
		}
	}
	return 0, false
}

// scanNumber returns the end of a numeric literal starting at i, or i when
// the text is an identifier that merely starts with digits (MySQL allows
// identifiers such as 1abc).
func scanNumber(s string, i int) int {
	n := len(s)
	j := i
	if j+1 < n && s[j] == '0' && (s[j+1] == 'x' || s[j+1] == 'b') {
		k := j + 2
		for k < n && ((s[j+1] == 'x' && isHex(s[k])) || (s[j+1] == 'b' && (s[k] == '0' || s[k] == '1'))) {
			k++
		}
		if k > j+2 && (k == n || !isWordByte(s[k])) {
			return k
		}
	}
	for j < n && isDigit(s[j]) {
		j++
	}
	if j < n && s[j] == '.' {
		j++
		for j < n && isDigit(s[j]) {
			j++
		}
	}
	if j < n && (s[j] == 'e' || s[j] == 'E') {
		k := j + 1
		if k < n && (s[k] == '+' || s[k] == '-') {
			k++
		}
		if k < n && isDigit(s[k]) {
			for k < n && isDigit(s[k]) {
				k++
			}
			j = k
		}
	}
	if j < n && isWordByte(s[j]) {
		return i
	}
	return j
}

func isIntroducer(w string) bool {
	switch strings.ToLower(w) {
	case "n", "x", "b":
		return true
	}
	return len(w) > 1 && w[0] == '_'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isWordByte(c byte) bool {
	return c == '_' || c == '$' || isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}
