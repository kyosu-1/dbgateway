package pgproxy

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// Values reach the proxy already converted by the gateway into JSON-friendly
// Go values (see the PostgreSQL adapter): strings, booleans, integers,
// floats, nil, []any and map[string]any, with times as RFC 3339 strings.
// They are rendered here in PostgreSQL's text output format so that clients
// can parse them according to the advertised type OID.

// field describes one result column.
type field struct {
	name    string
	oid     uint32
	typName string // pgx type name used for rendering ("text" when unknown or masked)
}

// typeSizes holds pg_type.typlen for fixed-size types reported in
// RowDescription; everything else is variable length (-1).
var typeSizes = map[uint32]int16{
	pgtype.BoolOID: 1, pgtype.Int2OID: 2, pgtype.Int4OID: 4, pgtype.Int8OID: 8, pgtype.OIDOID: 4,
	pgtype.Float4OID: 4, pgtype.Float8OID: 8, pgtype.DateOID: 4, pgtype.TimeOID: 8,
	pgtype.TimestampOID: 8, pgtype.TimestamptzOID: 8, pgtype.IntervalOID: 16, pgtype.UUIDOID: 16,
}

func typeSize(oid uint32) int16 {
	if n, ok := typeSizes[oid]; ok {
		return n
	}
	return -1
}

// resolveType maps a gateway type name to an OID. Unknown names (custom
// types, enums, domains) are reported as text.
func resolveType(m *pgtype.Map, name string) (uint32, string) {
	if name != "" {
		if t, ok := m.TypeForName(name); ok {
			return t.OID, t.Name
		}
	}
	return pgtype.TextOID, "text"
}

// renderText renders v in PostgreSQL text format for a column of type typ.
// nil means SQL NULL.
func renderText(typ string, v any) []byte {
	if v == nil {
		return nil
	}
	return []byte(textValue(typ, v))
}

func textValue(typ string, v any) string {
	if typ == "json" || typ == "jsonb" {
		return jsonText(v)
	}
	switch x := v.(type) {
	case string:
		return textString(typ, x)
	case bool:
		if x {
			return "t"
		}
		return "f"
	case int:
		return strconv.Itoa(x)
	case int8:
		return strconv.FormatInt(int64(x), 10)
	case int16:
		return strconv.FormatInt(int64(x), 10)
	case int32:
		return strconv.FormatInt(int64(x), 10)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint32:
		return strconv.FormatUint(uint64(x), 10)
	case float32:
		return formatFloat(float64(x), 32)
	case float64:
		return formatFloat(x, 64)
	case []any:
		return arrayLiteral(strings.TrimPrefix(typ, "_"), x)
	case map[string]any:
		return jsonText(x)
	case []byte:
		return string(x)
	}
	return fmt.Sprint(v)
}

// jsonText renders a decoded JSON value back as JSON text.
func jsonText(v any) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Sprint(v)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// textString fixes up string values whose JSON-friendly form differs from
// PostgreSQL's text output: times (RFC 3339 → ISO with a space) and
// special float and numeric values.
func textString(typ, s string) string {
	switch typ {
	case "timestamptz":
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UTC().Format("2006-01-02 15:04:05.999999") + "+00"
		}
	case "timestamp":
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.Format("2006-01-02 15:04:05.999999")
		}
	case "date":
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.Format(time.DateOnly)
		}
	case "float4", "float8":
		switch s {
		case "+Inf":
			return "Infinity"
		case "-Inf":
			return "-Infinity"
		}
	case "numeric":
		return strings.Trim(s, `"`)
	}
	return s
}

// formatFloat mimics PostgreSQL's shortest-exact float output
// (extra_float_digits > 0): plain notation for decimal exponents in
// [-4, 15), scientific notation otherwise.
func formatFloat(f float64, bits int) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		if math.Signbit(f) {
			return "-0"
		}
		return "0"
	}
	exp := int(math.Floor(math.Log10(math.Abs(f))))
	limit := 15
	if bits == 32 {
		limit = 6
	}
	if exp < -4 || exp >= limit {
		return strconv.FormatFloat(f, 'e', -1, bits)
	}
	return strconv.FormatFloat(f, 'f', -1, bits)
}

// arrayLiteral renders a (possibly nested) array in PostgreSQL's array
// text format, e.g. {1,2,NULL} or {"a b",c}.
func arrayLiteral(elemType string, elems []any) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, e := range elems {
		if i > 0 {
			b.WriteByte(',')
		}
		switch x := e.(type) {
		case nil:
			b.WriteString("NULL")
		case []any:
			b.WriteString(arrayLiteral(elemType, x))
		default:
			b.WriteString(quoteArrayElem(textValue(elemType, x)))
		}
	}
	b.WriteByte('}')
	return b.String()
}

func quoteArrayElem(s string) string {
	if s != "" && !strings.EqualFold(s, "NULL") && !strings.ContainsAny(s, "{}\",\\ \t\n\r\v\f") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		if r == '"' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

// encodeValue converts a text-format value to the requested format.
// Binary output is produced by decoding the text with pgx's codec for the
// column type and re-encoding it, so the binary form is exactly what a
// PostgreSQL server would send for that value.
func encodeValue(m *pgtype.Map, f field, format int16, text []byte) ([]byte, error) {
	if text == nil || format == pgtype.TextFormatCode {
		return text, nil
	}
	switch f.oid {
	case pgtype.TextOID, pgtype.VarcharOID, pgtype.BPCharOID, pgtype.NameOID, pgtype.UnknownOID:
		return text, nil // binary format of character types is the raw bytes
	}
	t, ok := m.TypeForOID(f.oid)
	if !ok {
		return nil, fmt.Errorf("type OID %d has no binary encoding", f.oid)
	}
	v, err := t.Codec.DecodeValue(m, f.oid, pgtype.TextFormatCode, text)
	if err != nil {
		return nil, err
	}
	out, err := m.Encode(f.oid, pgtype.BinaryFormatCode, v, nil)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return []byte{}, nil
	}
	return out, nil
}
