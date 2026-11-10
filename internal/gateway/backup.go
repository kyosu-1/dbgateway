package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/config"
)

// BackupPlanner is implemented by adapters that can back up the rows a
// write changes (PostgreSQL).
type BackupPlanner interface {
	PlanBackup(sql string, cat *analysis.Catalog) (*analysis.BackupPlan, error)
	// BackupRecord reads what a backup table records about itself; nil when
	// there is no such backup.
	BackupRecord(ctx context.Context, c analysis.Conn, schema, table string) (*analysis.BackupRecord, error)
}

// RestoreFunc looks up the backup table of request table (nil when there
// is none). Evaluate uses it to recognize restore statements.
type RestoreFunc func(ctx context.Context, table string) (*analysis.BackupRecord, error)

// Backup describes the backup of an executed write, for the requester,
// approvers and get_request. It never contains row values.
type Backup = analysis.BackupResult

const (
	ruleBackupUnsupported = "builtin:backup-unsupported"
	ruleBackupProtected   = "builtin:backup-protected"
)

// backupKind reports whether a backup is attempted for statements of kind k.
func backupKind(k analysis.StmtKind) bool {
	return k == analysis.KindUpdate || k == analysis.KindDelete || k == analysis.KindMerge
}

// planBackup returns the backup to take for an evaluated write on d, or
// nil when none is configured or needed. When the statement cannot be
// backed up it returns nil and the reason; the caller refuses the write if
// the backup is required.
func (g *Gateway) planBackup(ctx context.Context, d *database, sql string, ev *Evaluation) (*analysis.BackupPlan, string) {
	b := d.cfg.Backup
	if b == nil || ev.Analysis == nil || !backupKind(ev.Analysis.Statement.Kind) {
		return nil, ""
	}
	bp, ok := d.adapter.(BackupPlanner)
	if !ok {
		return nil, "this database type does not support backups"
	}
	cat, err := d.catalog(ctx, catalogTTL)
	if err != nil {
		return nil, "the catalog could not be loaded"
	}
	plan, err := bp.PlanBackup(sql, cat)
	if err != nil {
		if errors.Is(err, analysis.ErrBackupUnsupported) {
			return nil, err.Error()
		}
		return nil, "the statement cannot be backed up"
	}
	return plan, ""
}

// restoreFunc returns the RestoreFunc of database d on conn, or nil.
func restoreFunc(d *database, conn analysis.Conn) RestoreFunc {
	bp, ok := d.adapter.(BackupPlanner)
	if !ok || d.cfg.Backup == nil || conn == nil {
		return nil
	}
	return func(ctx context.Context, table string) (*analysis.BackupRecord, error) {
		return bp.BackupRecord(ctx, conn, d.cfg.Backup.Schema, table)
	}
}

func backupSpec(b *config.Backup, id string, plan *analysis.BackupPlan) *analysis.BackupSpec {
	return &analysis.BackupSpec{Schema: b.Schema, Table: id, Plan: plan, RequestID: id}
}

func backupUnsupported(reason string) (string, string) {
	return fmt.Sprintf("This database requires a backup of the rows a write changes, and this statement cannot be backed up (%s).", reason),
		"Write it as a plain UPDATE or DELETE on one table with a WHERE clause (no WITH, FROM, USING or MERGE), " +
			"for example by selecting the target rows with a subquery in WHERE."
}

const hintBackupProtected = "Query the original tables instead. To undo a backed-up change, submit the restore statement shown with the request, unchanged."

// checkRestore decides whether a statement may reference the backup
// schema. Backup tables hold copies of rows outside the data classes, so
// the only statement allowed to touch one is the exact restore statement
// dbgateway generated for it (recorded in the backup table). For that
// statement it returns the column references with the backup columns
// mapped to the columns they were copied from, so that classification and
// policies treat them like the source. ok is false (with a message) when
// the statement must be denied.
func checkRestore(ctx context.Context, db *config.Database, sql string, qa *analysis.QueryAnalysis, restore RestoreFunc) (refs []analysis.ColumnRef, msg string, ok bool) {
	refs = qa.Statement.Columns
	if db.Backup == nil {
		return refs, "", true
	}
	schema := db.Backup.Schema
	var table string
	for _, t := range qa.Statement.Tables {
		if t.Schema != schema {
			continue
		}
		if t.Write {
			return nil, "Backup tables cannot be changed.", false
		}
		if table != "" && table != t.Name {
			return nil, "A statement may read only one backup table.", false
		}
		table = t.Name
	}
	if table == "" {
		for _, c := range refs {
			if c.Schema == schema {
				return nil, "Backup tables can only be read by their restore statement.", false
			}
		}
		return refs, "", true
	}
	if restore == nil {
		return nil, "Backup tables can only be read by their restore statement.", false
	}
	rec, err := restore(ctx, table)
	if err != nil || rec == nil || rec.RestoreSQL == "" || strings.TrimSuffix(strings.TrimSpace(sql), ";") != rec.RestoreSQL {
		return nil, "Backup tables can only be read by the restore statement dbgateway generated for them, unchanged.", false
	}
	src := strings.SplitN(rec.Source, ".", 2)
	if len(src) != 2 {
		return nil, "The backup does not record its source table.", false
	}
	mapped := make([]analysis.ColumnRef, len(refs))
	for i, c := range refs {
		if c.Schema == schema && c.Table == table {
			c.Schema, c.Table = src[0], src[1]
		}
		mapped[i] = c
	}
	return mapped, "", true
}

// BackupUnsupportedError is returned by ExecuteApproved when the database
// requires backups and the statement cannot be backed up.
type BackupUnsupportedError struct{ Reason string }

func (e *BackupUnsupportedError) Error() string { return "backup unsupported: " + e.Reason }

// firstWritten returns the first table a statement writes.
func firstWritten(qa *analysis.QueryAnalysis) string {
	if qa != nil {
		for _, t := range qa.Statement.Tables {
			if t.Write {
				return t.FQN()
			}
		}
	}
	return ""
}

// addBackupAudit records where the backup of a write is (never values).
func addBackupAudit(extra map[string]any, b *Backup) {
	if b == nil || extra == nil {
		return
	}
	if b.Table != "" {
		extra["backup_table"] = b.Schema + "." + b.Table
		extra["backup_rows"] = b.Rows
	} else {
		extra["backup"] = "none"
	}
}
