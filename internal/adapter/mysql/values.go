package mysql

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// jsonValue converts a value scanned by go-sql-driver/mysql (int64,
// uint64, float32, float64, []byte, time.Time or nil) into a JSON-friendly Go
// value (string, bool, int64, float64, nil, []any, map[string]any), using the
// column's database type name:
//
//   - DECIMAL: exact decimal text
//   - DATETIME / TIMESTAMP: RFC 3339 in UTC (sessions use time_zone '+00:00')
//   - DATE: YYYY-MM-DD
//   - binary strings, BLOB, GEOMETRY: "\x" + hex, like PostgreSQL bytea
//   - BIT: integer
//   - JSON: the parsed document
func jsonValue(v any, typ string) any {
	switch x := v.(type) {
	case nil:
		return nil
	case int64, bool, string:
		return x
	case int32:
		return int64(x)
	case uint64:
		if x > math.MaxInt64 {
			return strconv.FormatUint(x, 10)
		}
		return int64(x)
	case float32:
		return float64(x)
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return fmt.Sprint(x)
		}
		return x
	case time.Time:
		if x.IsZero() {
			// Zero dates ('0000-00-00') stored before NO_ZERO_DATE.
			if typ == "DATE" {
				return "0000-00-00"
			}
			return "0000-00-00 00:00:00"
		}
		if typ == "DATE" {
			return x.UTC().Format(time.DateOnly)
		}
		return x.UTC().Format(time.RFC3339Nano)
	case []byte:
		return bytesValue(x, typ)
	}
	return fmt.Sprint(v)
}

func bytesValue(b []byte, typ string) any {
	switch typ {
	case "JSON":
		var out any
		if err := json.Unmarshal(b, &out); err == nil {
			return out
		}
		return string(b)
	case "DECIMAL":
		return string(b)
	case "BIT":
		if len(b) <= 8 {
			var n uint64
			for _, c := range b {
				n = n<<8 | uint64(c)
			}
			return jsonValue(n, typ)
		}
		return `\x` + hex.EncodeToString(b)
	case "BINARY", "VARBINARY", "TINYBLOB", "BLOB", "MEDIUMBLOB", "LONGBLOB", "GEOMETRY", "VECTOR":
		return `\x` + hex.EncodeToString(b)
	}
	if strings.HasSuffix(typ, "INT") || typ == "YEAR" {
		if n, err := strconv.ParseInt(string(b), 10, 64); err == nil {
			return n
		}
	}
	if typ == "DOUBLE" || typ == "FLOAT" {
		if f, err := strconv.ParseFloat(string(b), 64); err == nil {
			return jsonValue(f, typ)
		}
	}
	if !utf8.Valid(b) {
		return `\x` + hex.EncodeToString(b)
	}
	return string(b)
}

// valueSize approximates the wire size of a scanned value for the byte
// limit.
func valueSize(v any) int64 {
	switch x := v.(type) {
	case nil:
		return 0
	case []byte:
		return int64(len(x))
	case string:
		return int64(len(x))
	default:
		return 8
	}
}
