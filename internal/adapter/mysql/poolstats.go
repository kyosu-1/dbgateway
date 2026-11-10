package mysql

import (
	"database/sql"

	"github.com/kyosu-1/dbgateway/internal/analysis"
)

var _ analysis.PoolStatser = (*conn)(nil)

// PoolStats implements analysis.PoolStatser.
func (c *conn) PoolStats() []analysis.PoolStats {
	out := []analysis.PoolStats{poolStats("read", c.read)}
	if c.replica != nil {
		out = append(out, poolStats("replica", c.replica))
	}
	if c.write != nil {
		out = append(out, poolStats("write", c.write))
	}
	return out
}

func poolStats(name string, db *sql.DB) analysis.PoolStats {
	s := db.Stats()
	return analysis.PoolStats{Pool: name, Open: int64(s.OpenConnections), InUse: int64(s.InUse), Idle: int64(s.Idle),
		Max: int64(s.MaxOpenConnections), WaitCount: s.WaitCount, WaitDuration: s.WaitDuration}
}
