package ui

import (
	"strings"
	"unicode/utf8"
)

// InertText prepares text written by someone else (an agent's reason, a
// comment, SQL) for display: bidirectional-override and invisible
// formatting characters, which can make text read differently from what it
// is, are replaced with U+FFFD. HTML escaping is left to html/template, and
// nothing is ever turned into a link or a mention.
func InertText(s string) string {
	if !strings.ContainsFunc(s, isTrickyRune) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isTrickyRune(r) {
			return utf8.RuneError
		}
		return r
	}, s)
}

func isTrickyRune(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E, // LRE, RLE, PDF, LRO, RLO
		r >= 0x2066 && r <= 0x2069,            // LRI, RLI, FSI, PDI
		r == 0x200E, r == 0x200F, r == 0x061C, // LRM, RLM, ALM
		r == 0x200B, r == 0x2060, r == 0xFEFF: // zero-width space, word joiner, BOM
		return true
	}
	return false
}

// SQLToken is a piece of highlighted SQL. Class is "" (plain), "kw"
// (keyword), "str" (string literal), "num" (number), "param" (placeholder)
// or "comment".
type SQLToken struct {
	Class string
	Text  string
}

var sqlKeywords = map[string]bool{}

func init() {
	for _, k := range strings.Fields(`SELECT FROM WHERE AND OR NOT IN IS NULL AS ON JOIN LEFT RIGHT INNER OUTER FULL CROSS
		UPDATE SET INSERT INTO VALUES DELETE RETURNING MERGE USING WHEN MATCHED THEN ELSE END CASE TRUNCATE
		GROUP BY ORDER HAVING LIMIT OFFSET DISTINCT UNION ALL EXCEPT INTERSECT WITH RECURSIVE ASC DESC NULLS FIRST LAST
		CREATE ALTER DROP TABLE INDEX VIEW TRUE FALSE BETWEEN LIKE ILIKE EXISTS ANY SOME CAST DEFAULT CONFLICT DO NOTHING
		FOR LATERAL WINDOW OVER PARTITION FILTER ONLY`) {
		sqlKeywords[k] = true
	}
}

// HighlightSQL splits SQL into tokens for display. It never changes the
// text: concatenating the tokens yields InertText(sql).
func HighlightSQL(sql string) []SQLToken {
	s := InertText(sql)
	var out []SQLToken
	emit := func(class, text string) {
		if text == "" {
			return
		}
		if n := len(out); n > 0 && out[n-1].Class == class {
			out[n-1].Text += text
			return
		}
		out = append(out, SQLToken{Class: class, Text: text})
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '-' && strings.HasPrefix(s[i:], "--"):
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				j = len(s) - i
			}
			emit("comment", s[i:i+j])
			i += j
		case c == '/' && strings.HasPrefix(s[i:], "/*"):
			j := strings.Index(s[i+2:], "*/")
			end := len(s)
			if j >= 0 {
				end = i + 2 + j + 2
			}
			emit("comment", s[i:end])
			i = end
		case c == '\'':
			j := i + 1
			for j < len(s) {
				if s[j] == '\'' {
					if j+1 < len(s) && s[j+1] == '\'' {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			emit("str", s[i:j])
			i = j
		case c == '$' && i+1 < len(s) && isDigit(s[i+1]):
			j := i + 1
			for j < len(s) && isDigit(s[j]) {
				j++
			}
			emit("param", s[i:j])
			i = j
		case c == '$':
			// Dollar-quoted string: $tag$ ... $tag$
			j := i + 1
			for j < len(s) && (isIdent(s[j]) && !isDigit(s[j]) || j > i+1 && isDigit(s[j])) {
				j++
			}
			if j < len(s) && s[j] == '$' {
				tag := s[i : j+1]
				k := strings.Index(s[j+1:], tag)
				end := len(s)
				if k >= 0 {
					end = j + 1 + k + len(tag)
				}
				emit("str", s[i:end])
				i = end
			} else {
				emit("", "$")
				i++
			}
		case c == '?':
			emit("param", "?")
			i++
		case isDigit(c):
			j := i
			for j < len(s) && (isDigit(s[j]) || s[j] == '.' || s[j] == 'e' || s[j] == 'E') {
				j++
			}
			emit("num", s[i:j])
			i = j
		case isIdent(c) || c >= utf8.RuneSelf:
			j := i
			for j < len(s) && (isIdent(s[j]) || isDigit(s[j]) || s[j] >= utf8.RuneSelf) {
				j++
			}
			word := s[i:j]
			if sqlKeywords[strings.ToUpper(word)] {
				emit("kw", word)
			} else {
				emit("", word)
			}
			i = j
		case c == '"':
			j := strings.IndexByte(s[i+1:], '"')
			end := len(s)
			if j >= 0 {
				end = i + 1 + j + 1
			}
			emit("", s[i:end])
			i = end
		default:
			emit("", s[i:i+1])
			i++
		}
	}
	return out
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isIdent(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}
