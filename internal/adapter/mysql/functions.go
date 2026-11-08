package mysql

import "strings"

// FunctionAllowlist decides which functions a query may call.
//
// Only built-in functions known to be free of side effects are allowed by
// default. The following are deliberately absent:
//
//   - server file access: LOAD_FILE
//   - delays and resource abuse: SLEEP, BENCHMARK
//   - locks: GET_LOCK, RELEASE_LOCK, RELEASE_ALL_LOCKS, IS_FREE_LOCK, IS_USED_LOCK
//   - replication waits and control: MASTER_POS_WAIT, SOURCE_POS_WAIT,
//     WAIT_FOR_EXECUTED_GTID_SET, WAIT_UNTIL_SQL_THREAD_AFTER_GTIDS,
//     asynchronous_connection_failover_*, group_replication_*
//   - session state: LAST_INSERT_ID (LAST_INSERT_ID(expr) sets it), FOUND_ROWS,
//     ROW_COUNT, user variables (rejected separately)
//   - server-wide counters: UUID_SHORT (increments a global counter)
//   - sequences (TiDB syntax): NEXTVAL, SETVAL, LASTVAL
//   - removed or password related functions: PASSWORD, ENCODE, DECODE,
//     VALIDATE_PASSWORD_STRENGTH
//   - loadable (UDF) and stored functions, e.g. sys_exec / sys_eval
//     (anything not listed here, unless added via sql.allowed_functions)
type FunctionAllowlist struct {
	bare      map[string]bool // unqualified built-in names
	qualified map[string]bool // "db.name" stored functions
}

// NewFunctionAllowlist returns the default allowlist extended with extra
// entries ("name" or "db.name"). Names are case-insensitive.
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
		if strings.Contains(e, ".") {
			f.qualified[e] = true
			continue
		}
		f.bare[e] = true
	}
	return f
}

// Allowed reports whether the function schema.name may be called. schema is
// empty for unqualified calls (which MySQL resolves to built-in functions
// before loadable and stored functions).
func (f *FunctionAllowlist) Allowed(schema, name string) bool {
	name = strings.ToLower(name)
	if schema == "" {
		return f.bare[name]
	}
	return f.qualified[strings.ToLower(schema)+"."+name]
}

var defaultFunctions = []string{
	// Aggregates
	"count", "sum", "avg", "min", "max", "group_concat", "json_arrayagg", "json_objectagg",
	"bit_and", "bit_or", "bit_xor", "std", "stddev", "stddev_pop", "stddev_samp",
	"variance", "var_pop", "var_samp", "any_value", "grouping",
	// Window functions
	"row_number", "rank", "dense_rank", "percent_rank", "cume_dist", "ntile",
	"lag", "lead", "first_value", "last_value", "nth_value",
	// Strings
	"ascii", "bin", "bit_length", "char_func", "char", "char_length", "character_length",
	"concat", "concat_ws", "elt", "export_set", "field", "find_in_set", "format",
	"from_base64", "to_base64", "hex", "unhex", "insert_func", "insert", "instr", "lcase",
	"lower", "ucase", "upper", "left", "right", "length", "octet_length", "locate",
	"position", "lpad", "rpad", "ltrim", "rtrim", "trim", "make_set", "mid", "oct", "ord",
	"quote", "repeat", "replace", "reverse", "soundex", "space", "strcmp", "substr",
	"substring", "substring_index", "weight_string", "convert",
	"regexp_like", "regexp_instr", "regexp_replace", "regexp_substr",
	// Math
	"abs", "acos", "asin", "atan", "atan2", "ceil", "ceiling", "conv", "cos", "cot",
	"crc32", "degrees", "exp", "floor", "ln", "log", "log2", "log10", "mod", "pi",
	"pow", "power", "radians", "rand", "round", "sign", "sin", "sqrt", "tan", "truncate",
	"bit_count",
	// Date and time
	"adddate", "addtime", "convert_tz", "curdate", "current_date", "current_time",
	"current_timestamp", "curtime", "date", "date_add", "date_format", "date_sub",
	"datediff", "day", "dayname", "dayofmonth", "dayofweek", "dayofyear", "extract",
	"from_days", "from_unixtime", "get_format", "hour", "last_day", "localtime",
	"localtimestamp", "makedate", "maketime", "microsecond", "minute", "month",
	"monthname", "now", "period_add", "period_diff", "quarter", "sec_to_time", "second",
	"str_to_date", "subdate", "subtime", "sysdate", "time", "time_format", "time_to_sec",
	"timediff", "timestamp", "timestampadd", "timestampdiff", "to_days", "to_seconds",
	"unix_timestamp", "utc_date", "utc_time", "utc_timestamp", "week", "weekday",
	"weekofyear", "year", "yearweek",
	// Control flow and comparison
	"if", "ifnull", "nullif", "coalesce", "greatest", "least", "interval", "isnull",
	// JSON
	"json_array", "json_array_append", "json_array_insert", "json_contains",
	"json_contains_path", "json_depth", "json_extract", "json_insert", "json_keys",
	"json_length", "json_merge", "json_merge_patch", "json_merge_preserve",
	"json_object", "json_overlaps", "json_pretty", "json_quote", "json_remove",
	"json_replace", "json_schema_valid", "json_schema_validation_report", "json_search",
	"json_set", "json_storage_free", "json_storage_size", "json_type", "json_unquote",
	"json_valid", "json_value", "json_memberof",
	// Hashing, encoding, compression (pure)
	"md5", "sha", "sha1", "sha2", "compress", "uncompress", "uncompressed_length",
	"aes_encrypt", "aes_decrypt", "random_bytes", "statement_digest", "statement_digest_text",
	// Information (no side effects)
	"version", "database", "schema", "current_user", "user", "session_user", "system_user",
	"current_role", "connection_id", "charset", "collation", "coercibility", "icu_version",
	"format_bytes", "format_pico_time",
	// Miscellaneous
	"inet_aton", "inet_ntoa", "inet6_aton", "inet6_ntoa", "is_ipv4", "is_ipv4_compat",
	"is_ipv4_mapped", "is_ipv6", "is_uuid", "uuid", "uuid_to_bin", "bin_to_uuid",
	"default_func", "values",
}
