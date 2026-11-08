package postgres

import (
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// jsonValue converts a value decoded by pgx into a JSON-friendly Go value
// (string, bool, int64, float64, nil, []any, map[string]any).
func jsonValue(v any) any {
	switch x := v.(type) {
	case nil, bool, string, int64, int32, int16, int8, int, uint32, float32:
		return x
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return fmt.Sprint(x)
		}
		return x
	case time.Time:
		return x.Format(time.RFC3339Nano)
	case []byte:
		return `\x` + hex.EncodeToString(x)
	case [16]byte: // uuid
		return fmt.Sprintf("%x-%x-%x-%x-%x", x[0:4], x[4:6], x[6:8], x[8:10], x[10:16])
	case netip.Prefix:
		return x.String()
	case netip.Addr:
		return x.String()
	case *big.Int:
		return x.String()
	case pgtype.Numeric:
		if !x.Valid {
			return nil
		}
		if b, err := x.MarshalJSON(); err == nil {
			// Keep exact decimal text rather than a lossy float.
			return string(b)
		}
	case pgtype.Interval:
		if v, err := x.Value(); err == nil {
			return v
		}
	case pgtype.Time:
		if v, err := x.Value(); err == nil {
			return v
		}
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = jsonValue(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = jsonValue(e)
		}
		return out
	}
	if m, ok := v.(json.Marshaler); ok {
		if b, err := m.MarshalJSON(); err == nil {
			var out any
			if json.Unmarshal(b, &out) == nil {
				return out
			}
		}
	}
	if dv, ok := v.(driver.Valuer); ok {
		if val, err := dv.Value(); err == nil {
			return jsonValue(val)
		}
	}
	if s, ok := v.(fmt.Stringer); ok {
		return s.String()
	}
	return fmt.Sprint(v)
}
