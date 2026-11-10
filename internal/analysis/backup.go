package analysis

import "errors"

// BackupPlan describes how to copy the rows an UPDATE or DELETE is about to
// change, so that the change can be undone later. Adapters that support
// backups produce it with PlanBackup.
type BackupPlan struct {
	Kind StmtKind // KindUpdate or KindDelete
	// Target is the table the statement changes.
	Target TableRef
	// Select returns the current version of every row the statement will
	// change, with all of the target's columns followed by the row's
	// identity (BackupTableOIDColumn, BackupCTIDColumn). It runs in the
	// same transaction and snapshot as the statement.
	Select string
	// SetColumns are the columns an UPDATE assigns (empty for DELETE).
	SetColumns []string
}

// Identity columns added to every backup table. Execute uses them to check
// that the backup holds exactly the rows the statement changed.
const (
	BackupTableOIDColumn = "_dbgw_tableoid"
	BackupCTIDColumn     = "_dbgw_ctid"
)

// BackupSpec asks Execute to save the rows a write changes before running
// it. The copy is a new table Schema.Table created in the same transaction
// as the write, so it exists exactly when the write committed.
type BackupSpec struct {
	Schema string
	Table  string
	Plan   *BackupPlan
	// RequestID is recorded in the backup table's comment.
	RequestID string
}

// BackupResult describes a backup taken by Execute.
type BackupResult struct {
	Schema string `json:"schema"`
	Table  string `json:"table"`
	// Source is the schema-qualified table that was changed.
	Source string `json:"source"`
	Rows   int64  `json:"rows"`
	// RestoreSQL undoes the change from the backup. It is an ordinary
	// statement that goes through analysis, policies and approval like any
	// other write; it is the only statement allowed to read the backup.
	// Empty when RestoreUnavailable is set.
	RestoreSQL string `json:"restore_sql,omitempty"`
	// RestoreUnavailable explains why no restore statement could be
	// generated (the backup itself may still have been taken).
	RestoreUnavailable string `json:"restore_unavailable,omitempty"`
}

// BackupRecord is what a backup table records about itself (its comment):
// where its rows came from and the only statement allowed to read it.
type BackupRecord struct {
	RequestID  string `json:"dbgateway_request"`
	Source     string `json:"source"`
	Kind       string `json:"kind"`
	RestoreSQL string `json:"restore_sql,omitempty"`
}

// BackupError is returned by Execute when the backup could not be taken
// or did not match the write. The transaction has been rolled back.
// Reason never contains values; Err is the underlying database error, if
// any, and must be described like any database error (it may quote values).
type BackupError struct {
	Reason string
	Err    error
}

func (e *BackupError) Error() string {
	if e.Err != nil {
		return "backup: " + e.Reason + ": " + e.Err.Error()
	}
	return "backup: " + e.Reason
}

func (e *BackupError) Unwrap() error { return e.Err }

// ErrBackupUnsupported wraps the reasons a statement cannot be backed up.
var ErrBackupUnsupported = errors.New("cannot be backed up")
