package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgreSQL audit sink (audit.output: postgres).
//
// Every dbgateway instance appends to one table, audit_log, forming a
// single hash chain. Append serializes the writers of all instances with a
// transaction-scoped advisory lock, reads the hash of the last row and
// chains the new line to it, so the instances never fork the chain. The
// stored lines have exactly the format of the file sink's lines and are
// verified by the same rules (VerifyPostgres).
//
// Retention deletes the oldest rows (a prefix of the chain) after
// recording a checkpoint row with the hash of the last deleted line, like
// the file sink's checkpoints.jsonl.

const (
	// pgLockChain serializes appends (and retention) across instances.
	pgLockChain int64 = 0x64626777_00000010 // "dbgw" + 0x10
	// pgLockSchema serializes the creation of the audit tables.
	pgLockSchema int64 = 0x64626777_00000011

	pgAppendTimeout     = 10 * time.Second
	pgRetentionInterval = time.Hour
	pgRetentionBatch    = 10000
	pgVerifyBatch       = 1000
)

const pgAuditSchema = `
CREATE TABLE IF NOT EXISTS audit_log (
    seq             bigserial PRIMARY KEY,
    ts              timestamptz NOT NULL,
    hash            text NOT NULL UNIQUE,
    prev_hash       text NOT NULL,
    request_id      text NOT NULL DEFAULT '',
    event           text NOT NULL DEFAULT '',
    decision        text NOT NULL DEFAULT '',
    database_name   text NOT NULL DEFAULT '',
    principal_human text NOT NULL DEFAULT '',
    principal_agent text NOT NULL DEFAULT '',
    tables          text[] NOT NULL DEFAULT '{}',
    line            text NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_ts ON audit_log (ts);
CREATE INDEX IF NOT EXISTS audit_log_request_id ON audit_log (request_id);
CREATE INDEX IF NOT EXISTS audit_log_database_seq ON audit_log (database_name, seq);
CREATE TABLE IF NOT EXISTS audit_checkpoints (
    id             bigserial PRIMARY KEY,
    last_seq       bigint NOT NULL,
    last_hash      text NOT NULL,
    deleted_rows   bigint NOT NULL,
    deleted_before timestamptz NOT NULL,
    created_at     timestamptz NOT NULL
);
`

// PostgresSink stores audit lines in PostgreSQL. It is safe for concurrent
// use, also by several processes sharing the database.
type PostgresSink struct {
	pool      *pgxpool.Pool
	retention time.Duration
	logger    *slog.Logger

	fwd *MultiSink // forwarders of the stored lines; nil without any

	stop context.CancelFunc
	wg   sync.WaitGroup
}

var _ Sink = (*PostgresSink)(nil)

// OpenPostgresSink connects to dsn, creates the audit tables when missing
// and applies retention (rows older than retention are deleted after a
// checkpoint; 0 keeps everything). Retention is applied again every hour
// until Close.
func OpenPostgresSink(ctx context.Context, dsn string, retention time.Duration, logger *slog.Logger) (*PostgresSink, error) {
	if logger == nil {
		logger = slog.Default()
	}
	pool, err := openAuditPool(ctx, dsn)
	if err != nil {
		return nil, err
	}
	s := &PostgresSink{pool: pool, retention: retention, logger: logger}
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, pgLockSchema); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, pgAuditSchema)
		return err
	}); err != nil {
		pool.Close()
		return nil, fmt.Errorf("audit: create tables: %w", err)
	}
	if err := s.applyRetention(ctx, time.Now()); err != nil {
		pool.Close()
		return nil, err
	}
	if retention > 0 {
		bg, cancel := context.WithCancel(context.Background())
		s.stop = cancel
		s.wg.Go(func() { s.retentionLoop(bg) })
	}
	return s, nil
}

func openAuditPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: parse dsn: %w", err) // pgx redacts the password
	}
	cfg.ConnConfig.RuntimeParams["timezone"] = "UTC"
	if cfg.ConnConfig.RuntimeParams["application_name"] == "" {
		cfg.ConnConfig.RuntimeParams["application_name"] = "dbgateway-audit"
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("audit: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("audit: connect: %w", err)
	}
	return pool, nil
}

// SetForwarders copies every stored line (as stored, i.e. chained to the
// shared tail) to forwarders, best effort, like MultiSink. Call it before
// the first Append. Use it instead of wrapping the sink in a MultiSink,
// which would forward the lines as the Logger encoded them, before they
// were chained to the other instances' entries.
func (s *PostgresSink) SetForwarders(logger *slog.Logger, forwarders ...Forwarder) {
	if len(forwarders) == 0 {
		return
	}
	s.fwd = NewMultiSink(discardSink{}, forwarders...)
	s.fwd.SetLogger(logger)
}

// Stats returns the counters of the forwarders.
func (s *PostgresSink) Stats() []ForwarderStats {
	if s.fwd == nil {
		return nil
	}
	return s.fwd.Stats()
}

// LastHash returns the hash of the newest row (or of the last checkpoint
// when retention deleted every row; GenesisHash when there is none).
func (s *PostgresSink) LastHash() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pgAppendTimeout)
	defer cancel()
	return pgTailHash(ctx, s.pool)
}

type pgQueryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func pgTailHash(ctx context.Context, q pgQueryRower) (string, error) {
	var hash string
	err := q.QueryRow(ctx, `SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&hash)
	if err == nil {
		return hash, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	err = q.QueryRow(ctx, `SELECT last_hash FROM audit_checkpoints ORDER BY id DESC LIMIT 1`).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return GenesisHash, nil
	}
	return hash, err
}

// Append chains line to the shared tail and stores it. The line's own
// prev_hash (the Logger's view, which is stale when another instance wrote
// in between) is replaced by the hash of the last stored row and the line
// is re-encoded with Encode; when it already matches, the line is stored
// byte for byte.
func (s *PostgresSink) Append(line []byte, at time.Time) error {
	e, err := decodeLine(line)
	if err != nil {
		return err
	}
	ts, err := time.Parse(time.RFC3339Nano, e.TS)
	if err != nil {
		ts = at
	}
	tables := []string{}
	if e.Analysis != nil {
		for _, t := range e.Analysis.Tables {
			tables = append(tables, strings.ToLower(t))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), pgAppendTimeout)
	defer cancel()
	var stored []byte
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, pgLockChain); err != nil {
			return err
		}
		prev, err := pgTailHash(ctx, tx)
		if err != nil {
			return err
		}
		stored = line
		hash := lineHash(line)
		if e.PrevHash != prev {
			e.PrevHash = prev
			if stored, hash, err = Encode(e); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log (ts, hash, prev_hash, request_id, event, decision, database_name,
				principal_human, principal_agent, tables, line)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			ts.UTC(), hash, prev, e.RequestID, e.Event, e.Decision, e.Database,
			e.Principal.Human, e.Principal.Agent, tables, string(stored))
		return err
	})
	if err != nil {
		return err
	}
	if s.fwd != nil {
		_ = s.fwd.Append(stored, at) // never fails: the primary discards
	}
	return nil
}

// decodeLine checks a line's own hash and decodes it into an entry that
// re-encodes to the same bytes: unknown fields are refused (nothing may be
// dropped) and numbers in Extra keep their literal form.
func decodeLine(line []byte) (*Entry, error) {
	if _, _, err := checkLine(line); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	var se StoredEntry
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&se); err != nil {
		return nil, fmt.Errorf("audit: decode line: %w", err)
	}
	return &se.Entry, nil
}

// Close stops retention, drains the forwarders and closes the pool.
func (s *PostgresSink) Close() error {
	if s.stop != nil {
		s.stop()
		s.wg.Wait()
	}
	var err error
	if s.fwd != nil {
		err = s.fwd.Close()
	}
	s.pool.Close()
	return err
}

func (s *PostgresSink) retentionLoop(ctx context.Context) {
	t := time.NewTicker(pgRetentionInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if err := s.applyRetention(ctx, now); err != nil && ctx.Err() == nil {
				s.logger.Error("audit retention failed", "err", err)
			}
		}
	}
}

// applyRetention deletes the rows older than the retention period, oldest
// first in batches. Each batch is a prefix of the chain; before deleting
// it, a checkpoint row records the hash of its last line so that the
// remaining rows can still be verified.
func (s *PostgresSink) applyRetention(ctx context.Context, now time.Time) error {
	if s.retention <= 0 {
		return nil
	}
	cutoff := now.UTC().Add(-s.retention)
	var target *int64
	if err := s.pool.QueryRow(ctx, `SELECT max(seq) FROM audit_log WHERE ts < $1`, cutoff).Scan(&target); err != nil {
		return fmt.Errorf("audit retention: %w", err)
	}
	if target == nil {
		return nil
	}
	for {
		done, err := s.retentionStep(ctx, *target, cutoff, now)
		if err != nil {
			return fmt.Errorf("audit retention: %w", err)
		}
		if done {
			return nil
		}
	}
}

func (s *PostgresSink) retentionStep(ctx context.Context, target int64, cutoff, now time.Time) (done bool, err error) {
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, pgLockChain); err != nil {
			return err
		}
		var seq int64
		var hash, line string
		err := tx.QueryRow(ctx, `SELECT seq, hash, line FROM (
				SELECT seq, hash, line FROM audit_log WHERE seq <= $1 ORDER BY seq LIMIT $2
			) batch ORDER BY seq DESC LIMIT 1`, target, pgRetentionBatch).Scan(&seq, &hash, &line)
		if errors.Is(err, pgx.ErrNoRows) {
			done = true // nothing left (or another instance did it)
			return nil
		}
		if err != nil {
			return err
		}
		if h, _, err := checkLine([]byte(line)); err != nil || h != hash {
			return fmt.Errorf("seq %d: refusing to delete rows that fail verification: %w", seq, errors.Join(err, errChain))
		}
		tag, err := tx.Exec(ctx, `DELETE FROM audit_log WHERE seq <= $1`, seq)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_checkpoints (last_seq, last_hash, deleted_rows, deleted_before, created_at)
			VALUES ($1, $2, $3, $4, $5)`, seq, hash, tag.RowsAffected(), cutoff, now.UTC()); err != nil {
			return err
		}
		// Also emit it to the process log so it lands in an external
		// system, independent of the database.
		s.logger.Info("audit checkpoint", "last_seq", seq, "last_hash", hash, "deleted_rows", tag.RowsAffected())
		done = seq >= target
		return nil
	})
	return done, err
}

// VerifyPostgres verifies the audit chain stored in the PostgreSQL
// database at dsn, oldest row first. The first row must chain to the
// genesis hash or to the latest retention checkpoint; every row's own hash
// must match its line and its indexed hash columns.
func VerifyPostgres(ctx context.Context, dsn string) (*VerifyReport, error) {
	pool, err := openAuditPool(ctx, dsn)
	if err != nil {
		return nil, err
	}
	defer pool.Close()
	return verifyPostgres(ctx, pool)
}

func verifyPostgres(ctx context.Context, pool *pgxpool.Pool) (*VerifyReport, error) {
	// One snapshot: retention running meanwhile must not make the rows and
	// the checkpoints disagree.
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('audit_log') IS NOT NULL AND to_regclass('audit_checkpoints') IS NOT NULL`).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("audit: no audit_log table in this database (audit.output: postgres never ran here)")
	}
	checkpoint := ""
	if err := tx.QueryRow(ctx, `SELECT last_hash FROM audit_checkpoints ORDER BY id DESC LIMIT 1`).Scan(&checkpoint); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	rep := &VerifyReport{}
	prev := ""
	var after int64
	for {
		rows, err := tx.Query(ctx, `SELECT seq, hash, prev_hash, line FROM audit_log WHERE seq > $1 ORDER BY seq LIMIT $2`, after, pgVerifyBatch)
		if err != nil {
			return rep, err
		}
		n := 0
		for rows.Next() {
			n++
			var seq int64
			var colHash, colPrev, line string
			if err := rows.Scan(&seq, &colHash, &colPrev, &line); err != nil {
				rows.Close()
				return rep, err
			}
			after = seq
			hash, p, err := checkLine([]byte(line))
			if err != nil {
				rows.Close()
				return rep, fmt.Errorf("seq %d: %w", seq, err)
			}
			if hash != colHash || p != colPrev {
				rows.Close()
				return rep, fmt.Errorf("seq %d: %w: hash columns do not match the line", seq, errChain)
			}
			switch {
			case prev == "" && p == GenesisHash:
			case prev == "" && checkpoint != "" && p == checkpoint:
				rep.StartedFromCheckpoint = true
			case prev == "":
				rows.Close()
				return rep, fmt.Errorf("seq %d: %w: first entry does not chain to genesis or the last checkpoint", seq, errChain)
			case p != prev:
				rows.Close()
				return rep, fmt.Errorf("seq %d: %w: prev_hash does not match the previous entry (entries removed or reordered)", seq, errChain)
			}
			prev = hash
			rep.Entries++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return rep, err
		}
		if n < pgVerifyBatch {
			break
		}
	}
	rep.LastHash = prev
	return rep, nil
}

// discardSink is the primary of the forwarding MultiSink of a
// PostgresSink: the line is already stored when it is handed over.
type discardSink struct{}

func (discardSink) LastHash() (string, error)      { return GenesisHash, nil }
func (discardSink) Append([]byte, time.Time) error { return nil }
func (discardSink) Close() error                   { return nil }
