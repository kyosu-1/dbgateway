package postgres

import (
	"strings"

	pg "github.com/pganalyze/pg_query_go/v6"
)

// FunctionAllowlist decides which functions a query may call.
//
// Only functions known to be free of side effects are allowed by default.
// Functions that execute SQL text (query_to_xml, ts_stat), touch server
// files (pg_read_file, lo_import), signal backends (pg_terminate_backend),
// open connections (dblink), change settings (set_config) or sequences
// (nextval) are deliberately absent.
type FunctionAllowlist struct {
	bare      map[string]bool // unqualified names (resolve to pg_catalog first)
	qualified map[string]bool // "schema.name"
}

// NewFunctionAllowlist returns the default allowlist extended with extra
// entries ("name" or "schema.name").
func NewFunctionAllowlist(extra []string) *FunctionAllowlist {
	f := &FunctionAllowlist{bare: map[string]bool{}, qualified: map[string]bool{}}
	for _, n := range defaultFunctions {
		f.bare[n] = true
	}
	for _, e := range extra {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if s, n, ok := strings.Cut(e, "."); ok {
			if s == "pg_catalog" {
				f.bare[n] = true
			} else {
				f.qualified[e] = true
			}
			continue
		}
		f.bare[e] = true
	}
	return f
}

// Allowed reports whether the function named by parts may be called.
func (f *FunctionAllowlist) Allowed(parts []*pg.Node) bool {
	var names []string
	for _, p := range parts {
		s := p.GetString_()
		if s == nil {
			return false
		}
		names = append(names, strings.ToLower(s.Sval))
	}
	switch len(names) {
	case 1:
		return f.bare[names[0]]
	case 2:
		if names[0] == "pg_catalog" {
			return f.bare[names[1]]
		}
		return f.qualified[names[0]+"."+names[1]]
	default:
		return false
	}
}

var defaultFunctions = []string{
	// Aggregates
	"count", "sum", "avg", "min", "max", "array_agg", "string_agg", "json_agg", "jsonb_agg",
	"json_object_agg", "jsonb_object_agg", "bool_and", "bool_or", "every", "bit_and", "bit_or", "bit_xor",
	"stddev", "stddev_pop", "stddev_samp", "variance", "var_pop", "var_samp",
	"percentile_cont", "percentile_disc", "mode", "corr", "covar_pop", "covar_samp",
	"regr_avgx", "regr_avgy", "regr_count", "regr_intercept", "regr_r2", "regr_slope",
	"regr_sxx", "regr_sxy", "regr_syy", "any_value", "range_agg", "range_intersect_agg",
	"json_agg_strict", "jsonb_agg_strict", "json_object_agg_strict", "jsonb_object_agg_strict",
	"json_object_agg_unique", "jsonb_object_agg_unique", "json_object_agg_unique_strict", "jsonb_object_agg_unique_strict",
	"json_objectagg", "json_arrayagg",
	// Window functions
	"row_number", "rank", "dense_rank", "percent_rank", "cume_dist", "ntile",
	"lag", "lead", "first_value", "last_value", "nth_value",
	// Strings
	"lower", "upper", "initcap", "length", "char_length", "character_length", "octet_length", "bit_length",
	"substr", "substring", "position", "strpos", "left", "right", "lpad", "rpad",
	"ltrim", "rtrim", "btrim", "trim", "replace", "concat", "concat_ws", "split_part", "reverse",
	"repeat", "translate", "format", "regexp_replace", "regexp_match", "regexp_matches",
	"regexp_split_to_array", "regexp_split_to_table", "regexp_like", "regexp_count", "regexp_instr",
	"regexp_substr", "starts_with", "overlay", "ascii", "chr", "string_to_array", "string_to_table",
	"array_to_string", "quote_ident", "quote_literal", "quote_nullable", "md5", "sha224", "sha256",
	"sha384", "sha512", "encode", "decode", "convert_from", "convert_to", "normalize", "is_normalized",
	"unistr", "to_hex", "to_ascii", "like_escape", "similar_to_escape", "similar_escape", "casefold",
	// Formatting
	"to_char", "to_number", "to_date", "to_timestamp",
	// Math
	"abs", "ceil", "ceiling", "floor", "round", "trunc", "sign", "sqrt", "cbrt", "power", "pow", "exp",
	"ln", "log", "log10", "mod", "div", "greatest", "least", "width_bucket", "pi", "degrees", "radians",
	"sin", "cos", "tan", "asin", "acos", "atan", "atan2", "sind", "cosd", "tand", "asind", "acosd", "atand", "atan2d",
	"sinh", "cosh", "tanh", "asinh", "acosh", "atanh",
	"gcd", "lcm", "scale", "min_scale", "trim_scale", "factorial", "random", "random_normal",
	// Date/time
	"now", "clock_timestamp", "statement_timestamp", "transaction_timestamp", "timeofday",
	"date_trunc", "date_part", "extract", "age", "make_date", "make_time", "make_timestamp",
	"make_timestamptz", "make_interval", "justify_days", "justify_hours", "justify_interval",
	"date_bin", "isfinite", "timezone", "overlaps", "date_add", "date_subtract",
	// JSON
	"to_json", "to_jsonb", "row_to_json", "array_to_json", "json_build_object", "jsonb_build_object",
	"json_build_array", "jsonb_build_array", "json_object", "jsonb_object",
	"json_extract_path", "jsonb_extract_path", "json_extract_path_text", "jsonb_extract_path_text",
	"json_array_elements", "jsonb_array_elements", "json_array_elements_text", "jsonb_array_elements_text",
	"json_each", "jsonb_each", "json_each_text", "jsonb_each_text", "json_object_keys", "jsonb_object_keys",
	"json_array_length", "jsonb_array_length", "json_typeof", "jsonb_typeof", "jsonb_pretty",
	"json_strip_nulls", "jsonb_strip_nulls", "jsonb_set", "jsonb_set_lax", "jsonb_insert",
	"jsonb_path_query", "jsonb_path_exists", "jsonb_path_match", "jsonb_path_query_array", "jsonb_path_query_first",
	"json_to_record", "jsonb_to_record", "json_to_recordset", "jsonb_to_recordset",
	"json_populate_record", "jsonb_populate_record", "json_populate_recordset", "jsonb_populate_recordset",
	"json_scalar", "json_serialize",
	// Arrays and sets
	"array_length", "array_lower", "array_upper", "cardinality", "unnest", "array_append", "array_prepend",
	"array_cat", "array_position", "array_positions", "array_remove", "array_replace", "array_dims",
	"array_ndims", "array_fill", "array_sample", "array_shuffle", "trim_array", "generate_series", "generate_subscripts",
	// Ranges
	"int4range", "int8range", "numrange", "tsrange", "tstzrange", "daterange", "isempty", "lower_inc",
	"upper_inc", "lower_inf", "upper_inf", "range_merge", "multirange",
	// Text search
	"to_tsvector", "to_tsquery", "plainto_tsquery", "phraseto_tsquery", "websearch_to_tsquery",
	"ts_rank", "ts_rank_cd", "ts_headline", "setweight", "strip", "numnode", "querytree", "tsvector_to_array",
	// Network
	"host", "hostmask", "masklen", "netmask", "network", "family", "broadcast", "abbrev", "inet_same_family", "inet_merge",
	// Misc (pure)
	"pg_typeof", "num_nonnulls", "num_nulls", "gen_random_uuid", "uuidv4", "uuidv7", "uuid_extract_timestamp",
	"uuid_extract_version", "format_type", "pg_collation_for", "col_description", "obj_description",
	"pg_size_pretty", "pg_size_bytes", "version",
	"bool", "int2", "int4", "int8", "float4", "float8", "numeric", "text", "varchar", "date", "time",
	"timestamp", "timestamptz", "interval", "uuid", "inet", "cidr", "json", "jsonb",
}
