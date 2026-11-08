package mysql

import (
	"errors"
	"fmt"
	"strconv"

	gomysql "github.com/go-sql-driver/mysql"
)

// MySQL error numbers referred to by DescribeError.
const (
	ErrQueryTimeout     = 3024 // ER_QUERY_TIMEOUT (max_execution_time exceeded)
	ErrLockWaitTimeout  = 1205 // ER_LOCK_WAIT_TIMEOUT
	ErrReadOnlyTx       = 1792 // ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION
	ErrQueryInterrupted = 1317 // ER_QUERY_INTERRUPTED
)

// errorsWithIdentifiers are error numbers whose messages mention only
// identifiers, types and privileges, never stored values. Messages of other
// errors (for example 1292 "Truncated incorrect DOUBLE value: '...'") can
// quote data and must not be returned to callers.
var errorsWithIdentifiers = map[uint16]bool{
	1044: true, // access denied to database
	1046: true, // no database selected
	1049: true, // unknown database
	1051: true, // unknown table
	1052: true, // ambiguous column
	1054: true, // unknown column
	1055: true, // ONLY_FULL_GROUP_BY
	1056: true, // can't group on
	1064: true, // syntax error
	1109: true, // unknown table in multi-table statement
	1111: true, // invalid use of group function
	1142: true, // command denied on table
	1143: true, // command denied on column
	1146: true, // table doesn't exist
	1222: true, // different number of columns in SELECT
	1235: true, // feature not supported
	1241: true, // operand should contain N columns
	1242: true, // subquery returns more than 1 row
	1248: true, // derived table must have an alias
	1305: true, // function does not exist
	1370: true, // execute command denied on routine
	1792: true, // read-only transaction
	3065: true, // ORDER BY not in select list (DISTINCT)
}

// DescribeError converts a MySQL error into a message that is safe to
// return to the caller, plus a stable code ("mysql:<number>"). ok is false
// for errors that do not come from the MySQL server.
func DescribeError(err error) (msg, code string, ok bool) {
	var me *gomysql.MySQLError
	if !errors.As(err, &me) {
		return "", "", false
	}
	code = "mysql:" + strconv.Itoa(int(me.Number))
	switch {
	case me.Number == ErrQueryTimeout || me.Number == ErrQueryInterrupted:
		return "Canceled because it timed out (max_execution_time). Narrow the conditions or rewrite the query so it can use an index.", code, true
	case me.Number == ErrLockWaitTimeout:
		return "Canceled because a lock could not be acquired (lock_wait_timeout).", code, true
	case errorsWithIdentifiers[me.Number]:
		return "Database error: " + me.Message, code, true
	default:
		return fmt.Sprintf("Database error (MySQL %d). Details are withheld because they may contain values.", me.Number), code, true
	}
}
