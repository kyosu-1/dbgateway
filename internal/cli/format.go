package cli

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/width"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	dbgatewayv1 "github.com/kyosu-1/dbgateway/gen/dbgateway/v1"
)

// Output formats.
const (
	formatTable = "table"
	formatJSON  = "json"
	formatCSV   = "csv"
)

func checkFormat(f string, allowed ...string) error {
	for _, a := range allowed {
		if f == a {
			return nil
		}
	}
	return fmt.Errorf("unknown --format %q (use %s)", f, strings.Join(allowed, ", "))
}

// writeProtoJSON prints a message as indented JSON with proto field names.
// protojson output is deliberately unstable, so it is re-indented with
// encoding/json for stable output.
func writeProtoJSON(w io.Writer, m proto.Message) error {
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, b, "", "  "); err != nil {
		return err
	}
	buf.WriteByte('\n')
	_, err = buf.WriteTo(w)
	return err
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// sanitize makes text from the database or the server safe to print on a
// terminal: control characters (which could carry terminal escape
// sequences) and bidirectional overrides are shown escaped, and line
// breaks cannot break the table layout.
func sanitize(s string) string {
	clean := true
	for _, r := range s {
		if unsafeRune(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x100 && unsafeRune(r):
			fmt.Fprintf(&b, `\x%02x`, r)
		case unsafeRune(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func unsafeRune(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200e || r == 0x200f || r == 0x061c
}

// displayWidth is the number of terminal columns s occupies (East Asian
// wide and fullwidth characters take two).
func displayWidth(s string) int {
	n := 0
	for _, r := range s {
		switch width.LookupRune(r).Kind() {
		case width.EastAsianWide, width.EastAsianFullwidth:
			n += 2
		default:
			n++
		}
	}
	return n
}

func pad(s string, w int, right bool) string {
	gap := w - displayWidth(s)
	if gap <= 0 {
		return s
	}
	if right {
		return strings.Repeat(" ", gap) + s
	}
	return s + strings.Repeat(" ", gap)
}

// cell is a table cell; numbers are right-aligned.
type cell struct {
	text  string
	right bool
}

// writeGrid prints an aligned table in the style of psql:
//
//	 id | email
//	----+------------------
//	  1 | t***@example.com
func writeGrid(w io.Writer, header []string, rows [][]cell) error {
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = displayWidth(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(widths) {
				widths[i] = max(widths[i], displayWidth(c.text))
			}
		}
	}
	var b strings.Builder
	line := func(cells []cell) {
		for i, c := range cells {
			if i > 0 {
				b.WriteString(" |")
			}
			b.WriteString(" ")
			if i == len(cells)-1 && !c.right {
				b.WriteString(c.text) // no trailing spaces
			} else {
				b.WriteString(pad(c.text, widths[i], c.right))
			}
		}
		b.WriteString("\n")
	}
	hc := make([]cell, len(header))
	for i, h := range header {
		hc[i] = cell{text: h}
	}
	line(hc)
	for i, wd := range widths {
		if i > 0 {
			b.WriteString("+")
		}
		b.WriteString(strings.Repeat("-", wd+2))
	}
	b.WriteString("\n")
	for _, r := range rows {
		line(r)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// Markers appended to column names in table output.
const (
	markMasked   = "*"
	markWithheld = "!"
)

// resultTable prints result rows as an aligned table with a footer: the
// row count and a legend of masked and withheld columns.
func resultTable(w io.Writer, cols []*dbgatewayv1.ResultColumn, rows []*dbgatewayv1.Row, count int64) error {
	header := make([]string, len(cols))
	var masked, withheld []string
	for i, c := range cols {
		name := sanitize(c.Name)
		switch {
		case c.Withheld:
			header[i] = name + markWithheld
			withheld = append(withheld, name)
		case c.Masked:
			header[i] = name + markMasked
			masked = append(masked, name)
		default:
			header[i] = name
		}
	}
	grid := make([][]cell, len(rows))
	for r, row := range rows {
		grid[r] = make([]cell, len(cols))
		for i := range cols {
			var v *structpb.Value
			if i < len(row.Values) {
				v = row.Values[i]
			}
			if cols[i].Withheld {
				grid[r][i] = cell{text: "(withheld)"}
				continue
			}
			grid[r][i] = tableCell(v)
		}
	}
	if err := writeGrid(w, header, grid); err != nil {
		return err
	}
	fmt.Fprintln(w, rowCount(count))
	if len(masked) > 0 {
		fmt.Fprintf(w, "%s masked: %s\n", markMasked, strings.Join(masked, ", "))
	}
	if len(withheld) > 0 {
		fmt.Fprintf(w, "%s withheld (values not returned): %s\n", markWithheld, strings.Join(withheld, ", "))
	}
	return nil
}

func rowCount(n int64) string {
	if n == 1 {
		return "(1 row)"
	}
	return fmt.Sprintf("(%d rows)", n)
}

func tableCell(v *structpb.Value) cell {
	if v == nil {
		return cell{text: "NULL"}
	}
	switch k := v.Kind.(type) {
	case *structpb.Value_NullValue:
		return cell{text: "NULL"}
	case *structpb.Value_NumberValue:
		return cell{text: formatNumber(k.NumberValue), right: true}
	}
	return cell{text: sanitize(plainText(v))}
}

// plainText renders a value without quoting: strings as they are,
// numbers in plain notation, lists and structs as JSON, null as "".
func plainText(v *structpb.Value) string {
	if v == nil {
		return ""
	}
	switch k := v.Kind.(type) {
	case *structpb.Value_NullValue:
		return ""
	case *structpb.Value_StringValue:
		return k.StringValue
	case *structpb.Value_NumberValue:
		return formatNumber(k.NumberValue)
	case *structpb.Value_BoolValue:
		return strconv.FormatBool(k.BoolValue)
	}
	b, err := json.Marshal(v.AsInterface())
	if err != nil {
		return fmt.Sprint(v.AsInterface())
	}
	return string(b)
}

func formatNumber(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// resultCSV prints the header and rows as CSV (RFC 4180). NULL is an empty
// field.
func resultCSV(w io.Writer, cols []*dbgatewayv1.ResultColumn, rows []*dbgatewayv1.Row) error {
	cw := csv.NewWriter(w)
	header := make([]string, len(cols))
	for i, c := range cols {
		header[i] = c.Name
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, row := range rows {
		rec := make([]string, len(cols))
		for i := range cols {
			if i < len(row.Values) {
				rec[i] = plainText(row.Values[i])
			}
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// rowValues converts rows for JSON output.
func rowValues(rows []*dbgatewayv1.Row) [][]any {
	out := make([][]any, len(rows))
	for i, r := range rows {
		vals := make([]any, len(r.Values))
		for j, v := range r.Values {
			vals[j] = v.AsInterface()
		}
		out[i] = vals
	}
	return out
}

// truncateText shortens s to at most n runes (for list views).
func truncateText(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}
