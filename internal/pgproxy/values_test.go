package pgproxy

import (
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestRenderText(t *testing.T) {
	for _, tt := range []struct {
		typ  string
		v    any
		want string
	}{
		{"int4", int32(-5), "-5"},
		{"int8", int64(1) << 40, "1099511627776"},
		{"bool", false, "f"},
		{"float8", 1.5, "1.5"},
		{"float8", 123456789.0, "123456789"},
		{"float8", 1e20, "1e+20"},
		{"float8", 0.00001, "1e-05"},
		{"float8", "+Inf", "Infinity"},
		{"float8", "NaN", "NaN"},
		{"float4", float32(0.1), "0.1"},
		{"float8", math.Copysign(0, -1), "-0"},
		{"numeric", "12.30", "12.30"},
		{"numeric", `"NaN"`, "NaN"},
		{"timestamptz", "2026-01-02T03:04:05.123456+09:00", "2026-01-01 18:04:05.123456+00"},
		{"timestamp", "2026-01-02T03:04:05Z", "2026-01-02 03:04:05"},
		{"date", "2026-01-02T00:00:00Z", "2026-01-02"},
		{"text", "2026-01-02T00:00:00Z", "2026-01-02T00:00:00Z"},
		{"_int4", []any{int32(1), nil, int32(3)}, "{1,NULL,3}"},
		{"_text", []any{"", "NULL", `a"b`, `c\d`, "plain"}, `{"","NULL","a\"b","c\\d",plain}`},
		{"_int4", []any{[]any{int32(1), int32(2)}, []any{int32(3), int32(4)}}, "{{1,2},{3,4}}"},
		{"json", "just a string", `"just a string"`},
		{"jsonb", map[string]any{"a": []any{1.0, true}}, `{"a":[1,true]}`},
		{"json", []any{"x"}, `["x"]`},
		{"uuid", "0b8f2c3e-1111-2222-3333-444455556666", "0b8f2c3e-1111-2222-3333-444455556666"},
	} {
		if got := string(renderText(tt.typ, tt.v)); got != tt.want {
			t.Errorf("renderText(%s, %#v) = %q, want %q", tt.typ, tt.v, got, tt.want)
		}
	}
	if renderText("text", nil) != nil {
		t.Error("NULL must render as nil")
	}
}

func TestResolveType(t *testing.T) {
	m := pgtype.NewMap()
	for name, want := range map[string]uint32{
		"int8": pgtype.Int8OID, "text": pgtype.TextOID, "timestamptz": pgtype.TimestamptzOID, "_text": pgtype.TextArrayOID,
		"numeric": pgtype.NumericOID, "my_enum": pgtype.TextOID, "16384": pgtype.TextOID, "": pgtype.TextOID,
	} {
		if got, _ := resolveType(m, name); got != want {
			t.Errorf("resolveType(%q) = %d, want %d", name, got, want)
		}
	}
}

func TestEncodeBinary(t *testing.T) {
	m := pgtype.NewMap()
	for _, tt := range []struct {
		typ  string
		text string
	}{
		{"int8", "42"}, {"int4", "-7"}, {"bool", "t"}, {"float8", "0.25"}, {"numeric", "12.50"},
		{"timestamptz", "2026-01-01 18:04:05.123456+00"}, {"date", "2026-01-02"}, {"uuid", "0b8f2c3e-1111-2222-3333-444455556666"},
		{"_text", `{a,"b c",NULL}`}, {"jsonb", `{"a":1}`}, {"text", "héllo"}, {"interval", "1 day 02:00:00"},
	} {
		oid, name := resolveType(m, tt.typ)
		f := field{name: "c", oid: oid, typName: name}
		bin, err := encodeValue(m, f, pgtype.BinaryFormatCode, []byte(tt.text))
		if err != nil {
			t.Errorf("%s: %v", tt.typ, err)
			continue
		}
		// Decoding the binary form must give back the same value as the text.
		typ, _ := m.TypeForOID(oid)
		fromText, err1 := typ.Codec.DecodeValue(m, oid, pgtype.TextFormatCode, []byte(tt.text))
		fromBin, err2 := typ.Codec.DecodeValue(m, oid, pgtype.BinaryFormatCode, bin)
		if err1 != nil || err2 != nil {
			t.Errorf("%s: decode %v %v", tt.typ, err1, err2)
			continue
		}
		if !sameValue(fromText, fromBin) {
			t.Errorf("%s: text %#v != binary %#v", tt.typ, fromText, fromBin)
		}
	}
	if out, _ := encodeValue(m, field{oid: pgtype.Int8OID}, pgtype.BinaryFormatCode, nil); out != nil {
		t.Error("NULL must stay nil")
	}
	if _, err := encodeValue(m, field{oid: pgtype.Int8OID}, pgtype.BinaryFormatCode, []byte("****")); err == nil {
		t.Error("an unparsable value must fail rather than be sent corrupted")
	}
}

func sameValue(a, b any) bool {
	if ta, ok := a.(time.Time); ok {
		tb, ok := b.(time.Time)
		return ok && ta.Equal(tb)
	}
	return reflect.DeepEqual(a, b)
}
