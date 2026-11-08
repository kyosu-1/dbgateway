package mask

import (
	"encoding/json"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/kyosu-1/dbgateway/internal/config"
)

// Bounds on the work done per value. Detection is a safety net for columns
// that were not classified, so it trades completeness for a predictable
// cost: only the first maxPIIScanBytes of each string are scanned, and a
// nested value (JSON arrays and objects) is scanned up to maxPIIValueBytes
// in total, maxPIIElements elements and maxPIIDepth levels.
const (
	maxPIIScanBytes  = 4 << 10
	maxPIIValueBytes = 16 << 10
	maxPIIElements   = 1024
	maxPIIDepth      = 8
)

// PIIDetector finds personal information (e-mail addresses, Japanese phone
// numbers, credit card numbers and My Numbers) inside result values,
// including inside longer text. It is safe for concurrent use.
//
// Numbers are matched as runs of digit groups separated by spaces, hyphens
// or parentheses (ASCII and full-width). A candidate must have a plausible
// grouping (for example 4-4-4-4 for cards, 4-4-4 for My Numbers) and pass
// the checksum (Luhn, My Number check digit), and digit groups are never
// split, so plain long IDs and timestamps are not reported.
type PIIDetector struct {
	enabled bool
	action  string

	email, phone, card, myNumber bool
}

// PIIFinding is one column in which Apply found personal information.
type PIIFinding struct {
	Column int    // index in the row
	Kind   string // config.PIIEmail, config.PIIPhoneJP, ...
}

// NewPIIDetector returns a detector for the configuration. Empty detectors
// mean all of them and an empty action means mask, as in config validation.
func NewPIIDetector(cfg config.PIIDetection) *PIIDetector {
	d := &PIIDetector{enabled: cfg.Enabled, action: cfg.Action}
	if d.action != config.PIIActionDeny {
		d.action = config.PIIActionMask
	}
	dets := cfg.Detectors
	if len(dets) == 0 {
		dets = config.PIIDetectors
	}
	for _, name := range dets {
		switch name {
		case config.PIIEmail:
			d.email = true
		case config.PIIPhoneJP:
			d.phone = true
		case config.PIICreditCard:
			d.card = true
		case config.PIIMyNumber:
			d.myNumber = true
		}
	}
	return d
}

// Enabled reports whether detection is on and at least one detector is
// configured. A nil detector is disabled.
func (d *PIIDetector) Enabled() bool {
	return d != nil && d.enabled && (d.email || d.phone || d.card || d.myNumber)
}

// Action returns config.PIIActionMask or config.PIIActionDeny.
func (d *PIIDetector) Action() string {
	if d == nil {
		return config.PIIActionMask
	}
	return d.action
}

// Detect reports whether v contains personal information and of which kind
// (the first one found). Strings, integers, and string elements and keys of
// []any / map[string]any values are scanned. NULL never matches.
func (d *PIIDetector) Detect(v any) (kind string, ok bool) {
	if !d.Enabled() {
		return "", false
	}
	w := walker{d: d, bytes: maxPIIValueBytes, elems: maxPIIElements}
	_, kind, ok = w.walk(v, 0)
	return kind, ok
}

// Redact replaces each span of personal information in s with "****" and
// leaves the rest of the text as is. Only the first 4 KiB are scanned.
func (d *PIIDetector) Redact(s string) string {
	if !d.Enabled() {
		return s
	}
	w := walker{d: d, redact: true, bytes: maxPIIValueBytes, elems: maxPIIElements}
	out, _, _ := w.str(s)
	return out.(string)
}

// RedactValue returns v with personal information redacted and reports
// whether anything was found. Strings keep their surrounding text; numbers
// become "****"; slices and maps are copied (never modified in place) with
// their elements redacted. A map whose key contains personal information
// is replaced by "****" as a whole.
func (d *PIIDetector) RedactValue(v any) (any, bool) {
	if !d.Enabled() {
		return v, false
	}
	w := walker{d: d, redact: true, bytes: maxPIIValueBytes, elems: maxPIIElements}
	out, _, ok := w.walk(v, 0)
	if !ok {
		return v, false
	}
	return out, true
}

// Apply checks row[c] for each c in cols. With the mask action, values
// with personal information are replaced in row by their redacted form;
// with the deny action row is left untouched and the caller must refuse
// the whole result if any finding is returned. Out-of-range columns are
// ignored.
func (d *PIIDetector) Apply(row []any, cols []int) []PIIFinding {
	if !d.Enabled() {
		return nil
	}
	var found []PIIFinding
	for _, c := range cols {
		if c < 0 || c >= len(row) {
			continue
		}
		if d.action == config.PIIActionDeny {
			if kind, ok := d.Detect(row[c]); ok {
				found = append(found, PIIFinding{Column: c, Kind: kind})
			}
			continue
		}
		w := walker{d: d, redact: true, bytes: maxPIIValueBytes, elems: maxPIIElements}
		if out, kind, ok := w.walk(row[c], 0); ok {
			row[c] = out
			found = append(found, PIIFinding{Column: c, Kind: kind})
		}
	}
	return found
}

// walker scans (and optionally redacts) one value within a budget.
type walker struct {
	d      *PIIDetector
	redact bool
	bytes  int // remaining bytes to scan
	elems  int // remaining elements to visit
}

// walk returns the (redacted) value, the first kind found and whether
// anything was found. Without redact it stops at the first finding.
func (w *walker) walk(v any, depth int) (any, string, bool) {
	if w.elems <= 0 || w.bytes <= 0 {
		return v, "", false
	}
	w.elems--
	switch x := v.(type) {
	case nil, bool:
		return v, "", false
	case string:
		return w.str(x)
	case []byte:
		if !utf8.Valid(x) {
			return v, "", false
		}
		return w.str(string(x))
	case json.Number:
		return w.number(v, string(x))
	case int:
		return w.number(v, strconv.FormatInt(int64(x), 10))
	case int64:
		return w.number(v, strconv.FormatInt(x, 10))
	case int32:
		return w.number(v, strconv.FormatInt(int64(x), 10))
	case uint:
		return w.number(v, strconv.FormatUint(uint64(x), 10))
	case uint64:
		return w.number(v, strconv.FormatUint(x, 10))
	case uint32:
		return w.number(v, strconv.FormatUint(uint64(x), 10))
	case float64:
		if x != math.Trunc(x) || math.Abs(x) >= 1e20 {
			return v, "", false
		}
		return w.number(v, strconv.FormatFloat(x, 'f', -1, 64))
	case []string:
		if depth >= maxPIIDepth {
			return v, "", false
		}
		var out []string
		first, found := "", false
		for i, e := range x {
			r, kind, ok := w.str(e)
			if !ok {
				continue
			}
			if !found {
				first, found = kind, true
				if !w.redact {
					return v, first, true
				}
				out = slices.Clone(x)
			}
			out[i] = r.(string)
		}
		if !found {
			return v, "", false
		}
		return out, first, true
	case []any:
		if depth >= maxPIIDepth {
			return v, "", false
		}
		var out []any
		first, found := "", false
		for i, e := range x {
			r, kind, ok := w.walk(e, depth+1)
			if !ok {
				continue
			}
			if !found {
				first, found = kind, true
				if !w.redact {
					return v, first, true
				}
				out = slices.Clone(x)
			}
			out[i] = r
		}
		if !found {
			return v, "", false
		}
		return out, first, true
	case map[string]any:
		if depth >= maxPIIDepth {
			return v, "", false
		}
		// Sorted keys make the result (and the budget use) deterministic.
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if _, kind, ok := w.scanOnly(k); ok {
				return Redacted, kind, true
			}
		}
		var out map[string]any
		first, found := "", false
		for _, k := range keys {
			r, kind, ok := w.walk(x[k], depth+1)
			if !ok {
				continue
			}
			if !found {
				first, found = kind, true
				if !w.redact {
					return v, first, true
				}
				out = maps.Clone(x)
			}
			out[k] = r
		}
		if !found {
			return v, "", false
		}
		return out, first, true
	}
	return v, "", false
}

// str scans one string within the budget.
func (w *walker) str(s string) (any, string, bool) {
	n := min(len(s), maxPIIScanBytes, w.bytes)
	w.bytes -= n
	spans := w.d.scan(s[:n], !w.redact)
	if len(spans) == 0 {
		return s, "", false
	}
	if !w.redact {
		return s, spans[0].kind, true
	}
	return applySpans(s, spans), spans[0].kind, true
}

// scanOnly scans a string without redacting it (map keys).
func (w *walker) scanOnly(s string) (any, string, bool) {
	n := min(len(s), maxPIIScanBytes, w.bytes)
	w.bytes -= n
	spans := w.d.scan(s[:n], true)
	if len(spans) == 0 {
		return s, "", false
	}
	return s, spans[0].kind, true
}

// number checks the decimal text of a numeric value. A match replaces the
// whole value.
func (w *walker) number(v any, text string) (any, string, bool) {
	text = strings.TrimPrefix(text, "-")
	spans := w.d.scan(text, true)
	if len(spans) == 0 {
		return v, "", false
	}
	return Redacted, spans[0].kind, true
}

// span is a match: s[start:end].
type span struct {
	start, end int
	kind       string
}

// applySpans replaces the spans of s with Redacted. Overlapping and
// adjacent spans are merged into one placeholder.
func applySpans(s string, spans []span) string {
	slices.SortFunc(spans, func(a, b span) int { return a.start - b.start })
	var b strings.Builder
	b.Grow(len(s))
	pos, end := 0, -1 // end of the span being merged
	for _, sp := range spans {
		if end >= 0 && sp.start <= end {
			end = max(end, sp.end)
			continue
		}
		if end >= 0 {
			pos = end
		}
		b.WriteString(s[pos:sp.start])
		b.WriteString(Redacted)
		end = sp.end
	}
	if end >= 0 {
		pos = end
	}
	b.WriteString(s[pos:])
	return b.String()
}

// scan returns the matches in s (which the caller has already bounded).
// With first, it returns at most one match.
func (d *PIIDetector) scan(s string, first bool) []span {
	var out []span
	if d.email {
		out = scanEmails(s, out, first)
		if first && len(out) > 0 {
			return out
		}
	}
	if d.phone || d.card || d.myNumber {
		out = d.scanNumbers(s, out, first)
	}
	return out
}

// --- e-mail ---

const (
	maxEmailLocal  = 64
	maxEmailDomain = 253
)

func isLocalChar(c byte) bool {
	return isASCIIAlnum(c) || strings.IndexByte(".!#$%&*+=?^_{|}~-", c) >= 0
}

func isDomainChar(c byte) bool {
	return isASCIIAlnum(c) || c == '.' || c == '-'
}

func isASCIIAlnum(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// scanEmails finds addresses of the form local@domain.tld. The local part
// is accepted leniently (Japanese carrier addresses often break RFC 5322);
// the domain needs at least two labels and an alphabetic TLD.
func scanEmails(s string, out []span, first bool) []span {
	from := 0
	for from < len(s) {
		i := strings.IndexByte(s[from:], '@')
		if i < 0 {
			break
		}
		at := from + i
		l := at
		for l > 0 && at-l < maxEmailLocal && isLocalChar(s[l-1]) {
			l--
		}
		for l < at && s[l] == '.' {
			l++
		}
		r := at + 1
		for r < len(s) && r-at-1 < maxEmailDomain && isDomainChar(s[r]) {
			r++
		}
		for r > at+1 && (s[r-1] == '.' || s[r-1] == '-') {
			r--
		}
		if l < at && validDomain(s[at+1:r]) {
			out = append(out, span{l, r, config.PIIEmail})
			if first {
				return out
			}
			from = r
			continue
		}
		from = at + 1
	}
	return out
}

func validDomain(d string) bool {
	for labels := 1; ; labels++ {
		label, rest, more := strings.Cut(d, ".")
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		if more {
			d = rest
			continue
		}
		// label is the TLD.
		if labels < 2 || len(label) < 2 {
			return false
		}
		for i := 0; i < len(label); i++ {
			if !('a' <= label[i] && label[i] <= 'z' || 'A' <= label[i] && label[i] <= 'Z') {
				return false
			}
		}
		return true
	}
}

// --- numbers ---

// maxRunDigits is the most digits a candidate can have ("+81" plus an
// 11-digit number, or a 19-digit card).
const maxRunDigits = 21

// maxSepRunes is the most separator runes between two digit groups
// ("090 - 1234").
const maxSepRunes = 3

type digitGroup struct {
	start, end int // byte offsets in the string
	off, n     int // the group's digits are run.digits[off:off+n]
}

// numberRun is a sequence of digit groups joined by separators. digits
// holds the ASCII digits of all groups back to back, so the digits of
// consecutive groups are a contiguous slice.
type numberRun struct {
	plus     int // byte offset of a leading '+', or -1
	groups   []digitGroup
	digits   []byte
	cleanEnd bool // the last group ends at a word boundary
}

func digitValue(r rune) (byte, bool) {
	switch {
	case '0' <= r && r <= '9':
		return byte(r), true
	case '０' <= r && r <= '９':
		return byte('0' + r - '０'), true
	}
	return 0, false
}

func isDigitRune(r rune) bool {
	_, ok := digitValue(r)
	return ok
}

func isPlusRune(r rune) bool { return r == '+' || r == '＋' }

func isSepRune(r rune) bool {
	switch r {
	case ' ', ' ', '　', // spaces
		'-', '‐', '‑', '‒', '–', '—', '−', '－', 'ー', 'ｰ', // hyphens and look-alikes
		'(', ')', '（', '）':
		return true
	}
	return false
}

// isWordRune reports runes that glue a number to surrounding text, so that
// "A12345678901" or "x4111111111111111" are not taken as numbers.
// Japanese letters are not word runes: "電話09012345678" is a match.
func isWordRune(r rune) bool {
	switch {
	case r < utf8.RuneSelf:
		return isASCIIAlnum(byte(r)) || r == '_'
	case '０' <= r && r <= '９', 'Ａ' <= r && r <= 'Ｚ', 'ａ' <= r && r <= 'ｚ':
		return true
	}
	return false
}

// cleanStart reports whether a number may start at s[i].
func cleanStart(s string, i int) bool {
	if i == 0 {
		return true
	}
	r, w := utf8.DecodeLastRuneInString(s[:i])
	if isWordRune(r) {
		return false
	}
	switch r {
	case '.': // decimal fraction "3.14159..."
		p, _ := utf8.DecodeLastRuneInString(s[:i-w])
		return !isDigitRune(p)
	case '-': // identifier such as "ORD-123456789012" or a UUID tail
		p, _ := utf8.DecodeLastRuneInString(s[:i-w])
		return !isWordRune(p)
	}
	return true
}

// cleanEnd reports whether a number may end just before s[j].
func cleanEnd(s string, j int) bool {
	if j >= len(s) {
		return true
	}
	r, w := utf8.DecodeRuneInString(s[j:])
	if isWordRune(r) {
		return false
	}
	switch r {
	case '.':
		n, _ := utf8.DecodeRuneInString(s[j+w:])
		return !isDigitRune(n)
	case '-': // "123456789018-A"
		n, _ := utf8.DecodeRuneInString(s[j+w:])
		return !isWordRune(n)
	}
	return true
}

func (d *PIIDetector) scanNumbers(s string, out []span, first bool) []span {
	var run numberRun // buffers reused across runs
	for i := 0; i < len(s); {
		r, w := utf8.DecodeRuneInString(s[i:])
		plus := -1
		switch {
		case isPlusRune(r):
			next, _ := utf8.DecodeRuneInString(s[i+w:])
			if i+w >= len(s) || !isDigitRune(next) || !cleanStart(s, i) {
				i += w
				continue
			}
			plus = i
			i += w
		case !isDigitRune(r):
			i += w
			continue
		case !cleanStart(s, i):
			// Skip the whole digit group glued to a word.
			for i < len(s) {
				r, w := utf8.DecodeRuneInString(s[i:])
				if !isDigitRune(r) {
					break
				}
				i += w
			}
			continue
		}
		i = parseRun(s, i, plus, &run)
		before := len(out)
		out = d.evalRun(&run, out, first)
		if first && len(out) > before {
			return out
		}
	}
	return out
}

// parseRun reads digit groups starting at s[i] (a digit) into run and
// returns the offset just after the last group.
func parseRun(s string, i, plus int, run *numberRun) int {
	run.plus, run.groups, run.digits = plus, run.groups[:0], run.digits[:0]
	for {
		g := digitGroup{start: i, off: len(run.digits)}
		for i < len(s) {
			r, w := utf8.DecodeRuneInString(s[i:])
			b, ok := digitValue(r)
			if !ok {
				break
			}
			run.digits = append(run.digits, b)
			i += w
		}
		g.end, g.n = i, len(run.digits)-g.off
		run.groups = append(run.groups, g)

		k, seps := i, 0
		for k < len(s) && seps < maxSepRunes {
			r, w := utf8.DecodeRuneInString(s[k:])
			if !isSepRune(r) {
				break
			}
			k += w
			seps++
		}
		if seps > 0 && k < len(s) {
			if r, _ := utf8.DecodeRuneInString(s[k:]); isDigitRune(r) {
				i = k
				continue
			}
		}
		run.cleanEnd = cleanEnd(s, i)
		return i
	}
}

// evalRun finds matches made of whole consecutive groups of the run,
// preferring the earliest start and then the longest match.
func (d *PIIDetector) evalRun(run *numberRun, out []span, first bool) []span {
	gs := run.groups
	for i := 0; i < len(gs); {
		maxJ, total := i-1, 0
		for j := i; j < len(gs); j++ {
			total += gs[j].n
			if total > maxRunDigits {
				break
			}
			maxJ = j
		}
		plus := i == 0 && run.plus >= 0
		matched := false
		for j := maxJ; j >= i; j-- {
			// Only 10–19 digits (or "+81" and 9–11 digits) can match.
			n := gs[j].off + gs[j].n - gs[i].off
			if (n < 10 || n > 19) && !(plus && n >= 11 && n <= 13) {
				continue
			}
			if j == len(gs)-1 && !run.cleanEnd {
				continue
			}
			kind, usedPlus := d.classify(run, i, j, plus)
			if kind == "" {
				continue
			}
			start := gs[i].start
			if usedPlus {
				start = run.plus
			}
			out = append(out, span{start, gs[j].end, kind})
			if first {
				return out
			}
			i, matched = j+1, true
			break
		}
		if !matched {
			i++
		}
	}
	return out
}

// classify decides whether groups i..j of the run form a phone number, card
// number or My Number. plus means group i was preceded by '+'.
//
// A 4-4-4 or 4-4-4-4 candidate that is only part of a longer chain of
// 4-digit groups (such as the first 12 digits of a card-shaped ID that
// fails the Luhn check) is not a match.
func (d *PIIDetector) classify(run *numberRun, i, j int, plus bool) (kind string, usedPlus bool) {
	gs := run.groups[i : j+1]
	last := gs[len(gs)-1]
	digits := run.digits[gs[0].off : last.off+last.n]
	if plus && d.phone && isIntlPhoneJP(gs, digits) {
		return config.PIIPhoneJP, true
	}
	if len(gs) > maxRunDigits {
		return "", false
	}
	var lensBuf [maxRunDigits]int
	lens := lensBuf[:len(gs)]
	for k, g := range gs {
		lens[k] = g.n
	}
	prevLen, nextLen := 0, 0
	if i > 0 {
		prevLen = run.groups[i-1].n
	}
	if j+1 < len(run.groups) {
		nextLen = run.groups[j+1].n
	}
	switch n := len(digits); {
	case n == 10 || n == 11:
		if d.phone && phoneGrouping(lens, 2) && validNationalJP(digits) {
			return config.PIIPhoneJP, false
		}
	case n == 12:
		grouped := slices.Equal(lens, []int{4, 4, 4})
		if grouped && (prevLen == 4 || nextLen == 4) {
			break
		}
		if d.myNumber && (grouped || len(lens) == 1) && validMyNumber(digits) {
			return config.PIIMyNumber, false
		}
	case n >= 13 && n <= 19:
		if len(lens) >= 4 && (prevLen == 4 || nextLen == 4 && lens[len(lens)-1] == 4) {
			break
		}
		if d.card && cardGrouping(lens) && validCard(digits) {
			return config.PIICreditCard, false
		}
	}
	return "", false
}

// Prefixes of 11-digit Japanese numbers: mobile, IP phone, M2M, and
// 0800 toll-free. Every other number is 10 digits.
var elevenDigitPrefixes = []string{"070", "080", "090", "050", "060", "020"}

// validNationalJP checks a domestic number (with its leading 0).
func validNationalJP(n []byte) bool {
	if len(n) < 10 || len(n) > 11 || n[0] != '0' || n[1] == '0' {
		return false
	}
	eleven := slices.Contains(elevenDigitPrefixes, string(n[:3]))
	return (len(n) == 11) == eleven
}

// phoneGrouping accepts an unseparated number or two or three groups whose
// last group has 3–4 digits and first group firstMin..5 digits.
func phoneGrouping(lens []int, firstMin int) bool {
	switch len(lens) {
	case 1:
		return true
	case 2, 3:
		last := lens[len(lens)-1]
		return lens[0] >= firstMin && lens[0] <= 5 && last >= 3 && last <= 4
	}
	return false
}

// isIntlPhoneJP checks +81 numbers: "+81 90-1234-5678", "+819012345678",
// and the common "+81 (0)90..." mistake written as "+81 090-...". digits
// are the digits of gs.
func isIntlPhoneJP(gs []digitGroup, digits []byte) bool {
	if len(digits) < 3 || digits[0] != '8' || digits[1] != '1' || len(gs) > 4 {
		return false
	}
	// National groups: the rest of the first group (if any), then the others.
	var lensBuf [4]int
	lens := lensBuf[:0]
	if rest := gs[0].n - 2; rest > 0 {
		lens = append(lens, rest)
	}
	for _, g := range gs[1:] {
		lens = append(lens, g.n)
	}
	national := digits[2:]
	if national[0] == '0' {
		national = national[1:]
		if lens[0]--; lens[0] == 0 {
			lens = lens[1:]
		}
	}
	if len(lens) == 0 || len(national) > 10 {
		return false
	}
	var buf [11]byte
	buf[0] = '0'
	n := 1 + copy(buf[1:], national)
	return phoneGrouping(lens, 1) && validNationalJP(buf[:n])
}

// cardGrouping accepts an unseparated number, groups of four (the last may
// be shorter), and the American Express / Diners 4-6-5 and 4-6-4 forms.
func cardGrouping(lens []int) bool {
	if len(lens) == 1 || slices.Equal(lens, []int{4, 6, 5}) || slices.Equal(lens, []int{4, 6, 4}) {
		return true
	}
	if len(lens) < 4 {
		return false
	}
	for _, l := range lens[:len(lens)-1] {
		if l != 4 {
			return false
		}
	}
	last := lens[len(lens)-1]
	return last >= 1 && last <= 4
}

// validCard checks the major industry identifier (2–6: Mastercard 2-series,
// Amex/JCB/Diners, Visa, Mastercard, Discover/UnionPay) and the Luhn
// checksum.
func validCard(digits []byte) bool {
	if digits[0] < '2' || digits[0] > '6' || allSame(digits) {
		return false
	}
	sum := 0
	for i := len(digits) - 1; i >= 0; i-- {
		v := int(digits[i] - '0')
		if (len(digits)-1-i)%2 == 1 {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
	}
	return sum%10 == 0
}

// validMyNumber checks the check digit of a 12-digit individual number
// (総務省令: Pn is the n-th digit from the right excluding the check digit,
// Qn = n+1 for n ≤ 6 and n-5 for n ≥ 7).
func validMyNumber(digits []byte) bool {
	if len(digits) != 12 || allSame(digits) {
		return false
	}
	sum := 0
	for n := 1; n <= 11; n++ {
		p := int(digits[11-n] - '0')
		q := n + 1
		if n >= 7 {
			q = n - 5
		}
		sum += p * q
	}
	check := 0
	if r := sum % 11; r > 1 {
		check = 11 - r
	}
	return int(digits[11]-'0') == check
}

func allSame(s []byte) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}
