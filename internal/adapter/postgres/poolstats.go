package postgres

import (
	"github.com/jackc/pgx/v5/pgxpool"

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

func poolStats(name string, p *pgxpool.Pool) analysis.PoolStats {
	s := p.Stat()
	return analysis.PoolStats{Pool: name, Open: int64(s.TotalConns()), InUse: int64(s.AcquiredConns()), Idle: int64(s.IdleConns()),
		Max: int64(s.MaxConns()), WaitCount: s.EmptyAcquireCount(), WaitDuration: s.EmptyAcquireWaitTime()}
}
