package gateway

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/config"
)

// BackupPlanner is implemented by adapters that can back up the rows a
// write changes (PostgreSQL).
type BackupPlanner interface {
	PlanBackup(sql string, cat *analysis.Catalog) (*analysis.BackupPlan, error)
}

// Backup describes the backup of an executed write, for the requester,
// approvers and get_request. It never contains row values.
type Backup = analysis.BackupResult

const (
	ruleBackupUnsupported = "builtin:backup-unsupported"
	ruleBackupProtected   = "builtin:backup-protected"
)

// backupKinds are the statements a backup is attempted for.
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
		return nil, err.Error()
	}
	return plan, ""
}

// backupSpec builds the execution options for a backup of request id.
func backupSpec(b *config.Backup, id string, plan *analysis.BackupPlan) *analysis.BackupSpec {
	comment, _ := json.Marshal(map[string]string{"dbgateway_request": id, "source": plan.Target.FQN(), "kind": string(plan.Kind)})
	return &analysis.BackupSpec{Schema: b.Schema, Table: id, Plan: plan, Comment: string(comment)}
}

func backupUnsupported(reason string) (string, string) {
	return fmt.Sprintf("This database requires a backup of the rows a write changes, and this statement cannot be backed up (%s).", reason),
		"Write it as a plain UPDATE or DELETE on one table with a WHERE clause (no WITH, FROM, USING or MERGE), " +
			"for example by selecting the target rows with a subquery in WHERE."
}

// guardBackupSchema refuses statements that write to the backup schema,
// read it in anything but an INSERT or UPDATE (a restore, which needs
// approval) or return its columns. Backup tables hold copies of rows
// without data classes; they are only a source for restores.
func guardBackupSchema(db *config.Database, qa *analysis.QueryAnalysis) (string, bool) {
	if db.Backup == nil || qa == nil {
		return "", false
	}
	schema := db.Backup.Schema
	st := &qa.Statement
	for _, t := range st.Tables {
		if t.Schema != schema {
			continue
		}
		if t.Write {
			return "Backup tables cannot be changed.", true
		}
		if st.Kind != analysis.KindInsert && st.Kind != analysis.KindUpdate {
			return "Backup tables can only be read by a restore (an INSERT or UPDATE that copies rows back).", true
		}
	}
	for _, o := range qa.Output {
		for _, s := range o.Sources {
			if s.Schema == schema {
				return "Columns of backup tables cannot be returned; they can only be used to restore rows.", true
			}
		}
	}
	return "", false
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
