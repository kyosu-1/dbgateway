package gateway

import (
	"context"
	"time"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/audit"
)

// BackupJanitor is implemented by adapters that can list and drop backup
// tables (backup.retention).
type BackupJanitor interface {
	ListBackups(ctx context.Context, c analysis.Conn, schema string) ([]analysis.BackupTable, error)
	DropBackup(ctx context.Context, c analysis.Conn, schema, table string) error
}

// ExpireBackups drops the backup tables older than their database's
// backup.retention and returns how many were dropped. Tables without a
// backup record (not created by dbgateway, or by a version that did not
// record the creation time) are left alone. Each drop is audited.
func (g *Gateway) ExpireBackups(ctx context.Context, now time.Time) int {
	dropped := 0
	for _, d := range g.dbs {
		b := d.cfg.Backup
		if b == nil || b.Retention <= 0 {
			continue
		}
		j, ok := d.adapter.(BackupJanitor)
		if !ok {
			continue
		}
		conn, err := d.connection(ctx)
		if err != nil {
			continue
		}
		tables, err := j.ListBackups(ctx, conn, b.Schema)
		if err != nil {
			g.logger.Warn("backup retention: list backups failed", "database", d.cfg.Name, "err", err)
			continue
		}
		for _, t := range tables {
			if t.Record == nil || t.Record.CreatedAt.IsZero() || now.Sub(t.Record.CreatedAt) < b.Retention.D() {
				continue
			}
			// Audit first: a backup is never dropped without a record.
			e := &audit.Entry{RequestID: NewRequestID(), Event: "backup_expired", Database: d.cfg.Name,
				Principal: audit.PrincipalInfo{Kind: "system", Human: "dbgateway"}, Decision: "allow",
				Extra: map[string]any{"backup_table": b.Schema + "." + t.Table, "source": t.Record.Source,
					"backup_request": t.Record.RequestID, "created_at": t.Record.CreatedAt}}
			if g.writeAudit(e) != nil {
				return dropped
			}
			if err := j.DropBackup(ctx, conn, b.Schema, t.Table); err != nil {
				g.logger.Warn("backup retention: drop failed", "database", d.cfg.Name, "table", t.Table, "err", err)
				continue
			}
			dropped++
		}
		d.invalidateCatalog()
	}
	return dropped
}

// RunBackupRetention calls ExpireBackups every interval until ctx is done.
func (g *Gateway) RunBackupRetention(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := g.ExpireBackups(ctx, time.Now()); n > 0 {
				g.logger.Info("backup retention: dropped expired backups", "count", n)
			}
		}
	}
}
