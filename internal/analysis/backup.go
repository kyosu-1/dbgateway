package analysis

// BackupPlan describes how to copy the rows an UPDATE or DELETE is about to
// change, so that the change can be undone later. Adapters that support
// backups produce it with PlanBackup.
type BackupPlan struct {
	Kind StmtKind // KindUpdate or KindDelete
	// Target is the table the statement changes.
	Target TableRef
	// Select returns the current version of every row the statement will
	// change, with all of the target's columns, and nothing else. It is
	// run in the same transaction and snapshot as the statement.
	Select string
	// SetColumns are the columns an UPDATE assigns (empty for DELETE).
	SetColumns []string
}

// BackupSpec asks Execute to save the rows a write changes before running
// it. The copy is a new table Schema.Table created in the same transaction
// as the write, so it exists exactly when the write committed.
type BackupSpec struct {
	Schema string
	Table  string
	Plan   *BackupPlan
	// Comment is stored as the backup table's comment (metadata such as
	// the request ID; never row values).
	Comment string
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
	// other write. Empty when RestoreUnavailable is set.
	RestoreSQL string `json:"restore_sql,omitempty"`
	// RestoreUnavailable explains why no restore statement could be
	// generated (the backup itself was still taken).
	RestoreUnavailable string `json:"restore_unavailable,omitempty"`
}

// BackupError is returned by Execute when the backup could not be taken
// or did not match the write. The transaction has been rolled back.
type BackupError struct {
	Reason string
}

func (e *BackupError) Error() string { return "backup: " + e.Reason }
