package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/kyosu-1/dbgateway/internal/identity"
)

// CreateApprovalRequest stores a new approval request.
func (s *Postgres) CreateApprovalRequest(ctx context.Context, r *ApprovalRequest) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO approval_requests (`+approvalColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
			$21, $22, $23, $24, $25, $26, $27, $28)`,
		r.ID, string(r.RequesterKind), r.RequesterHuman, r.RequesterAgent, r.RequesterClientID, r.Database,
		r.RawSQL, r.NormalizedSQL, r.Reason, pgJSON(r.AnalysisJSON, "{}"), r.EstimateRows, r.MaxAffectedRows, r.Risk, r.ApprovalRule,
		pgJSON(r.StepsJSON, "[]"), pgJSON(r.ApprovalsJSON, "[]"), r.ConfigVersion, r.BindingHash, string(r.Status), r.Version,
		pgTime(r.CreatedAt), pgTime(r.ExpiresAt), pgNullTime(r.DecidedAt), r.DecidedBy, r.Comment,
		pgNullTime(r.StartedAt), pgNullTime(r.FinishedAt), pgNullJSON(r.ResultJSON))
	return pgInsertErr(err)
}

func pgScanApproval(sc scanner) (*ApprovalRequest, error) {
	var r ApprovalRequest
	var kind, status, analysis, steps, approvals string
	var result []byte
	err := sc.Scan(&r.ID, &kind, &r.RequesterHuman, &r.RequesterAgent, &r.RequesterClientID, &r.Database,
		&r.RawSQL, &r.NormalizedSQL, &r.Reason, &analysis, &r.EstimateRows, &r.MaxAffectedRows, &r.Risk, &r.ApprovalRule,
		&steps, &approvals, &r.ConfigVersion, &r.BindingHash, &status, &r.Version, &r.CreatedAt, &r.ExpiresAt,
		&r.DecidedAt, &r.DecidedBy, &r.Comment, &r.StartedAt, &r.FinishedAt, &result)
	if err != nil {
		return nil, pgNotFound(err)
	}
	r.RequesterKind, r.Status = identity.Kind(kind), ApprovalStatus(status)
	r.AnalysisJSON, r.StepsJSON, r.ApprovalsJSON = []byte(analysis), []byte(steps), []byte(approvals)
	if len(result) > 0 {
		r.ResultJSON = result
	}
	r.CreatedAt, r.ExpiresAt = fromPGTime(r.CreatedAt), fromPGTime(r.ExpiresAt)
	r.DecidedAt, r.StartedAt, r.FinishedAt = fromPGNullTime(r.DecidedAt), fromPGNullTime(r.StartedAt), fromPGNullTime(r.FinishedAt)
	return &r, nil
}

// GetApprovalRequest returns a request by ID.
func (s *Postgres) GetApprovalRequest(ctx context.Context, id string) (*ApprovalRequest, error) {
	return pgScanApproval(s.pool.QueryRow(ctx, `SELECT `+approvalColumns+` FROM approval_requests WHERE id = $1`, id))
}

// ListApprovalRequests returns matching requests, newest first.
func (s *Postgres) ListApprovalRequests(ctx context.Context, f ApprovalFilter) ([]*ApprovalRequest, error) {
	var where []string
	var args pgArgs
	if f.RequesterHuman != "" {
		where = append(where, "requester_human = "+args.add(f.RequesterHuman))
	}
	if f.Database != "" {
		where = append(where, "database_name = "+args.add(f.Database))
	}
	if len(f.Statuses) > 0 {
		statuses := make([]string, len(f.Statuses))
		for i, st := range f.Statuses {
			statuses[i] = string(st)
		}
		where = append(where, "status = ANY("+args.add(statuses)+")")
	}
	if !f.ExpiresBefore.IsZero() {
		where = append(where, "expires_at < "+args.add(pgTime(f.ExpiresBefore)))
	}
	q := `SELECT ` + approvalColumns + ` FROM approval_requests`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	q += " ORDER BY created_at DESC, id LIMIT " + args.add(min(limit, 1000))
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return pgCollect(rows, pgScanApproval)
}

// UpdateApprovals records approvals with optimistic concurrency.
func (s *Postgres) UpdateApprovals(ctx context.Context, id string, version int64, approvalsJSON []byte, status ApprovalStatus, decidedAt *time.Time) error {
	if status != ApprovalPending && status != ApprovalApproved {
		return fmt.Errorf("store: UpdateApprovals: invalid status %q", status)
	}
	tag, err := s.pool.Exec(ctx, `UPDATE approval_requests
		SET approvals_json = $1, status = $2, decided_at = COALESCE($3, decided_at), version = version + 1
		WHERE id = $4 AND status = 'pending' AND version = $5`,
		pgJSON(approvalsJSON, "[]"), string(status), pgNullTime(decidedAt), id, version)
	if err != nil {
		return err
	}
	return s.pgConditionalResult(ctx, tag, id)
}

// TransitionApprovalRequest performs a conditional status change. The
// UPDATE re-checks the status after waiting for a concurrent writer's row
// lock, so of concurrent callers on any instance exactly one wins.
func (s *Postgres) TransitionApprovalRequest(ctx context.Context, id string, from, to ApprovalStatus, t ApprovalTransition) error {
	var col string
	switch to {
	case ApprovalApproved, ApprovalRejected, ApprovalExpired, ApprovalCanceled:
		col = "decided_at"
	case ApprovalRunning:
		col = "started_at"
	case ApprovalSucceeded, ApprovalFailed:
		col = "finished_at"
	default:
		return fmt.Errorf("store: invalid transition to %q", to)
	}
	var args pgArgs
	q := `UPDATE approval_requests SET status = ` + args.add(string(to)) + `, version = version + 1, ` + col + ` = ` + args.add(pgTime(t.At))
	if t.DecidedBy != "" || t.Comment != "" {
		q += `, decided_by = ` + args.add(t.DecidedBy) + `, decision_comment = ` + args.add(t.Comment)
	}
	if t.Result != nil {
		q += `, result_json = ` + args.add(pgNullJSON(t.Result))
	}
	q += ` WHERE id = ` + args.add(id) + ` AND status = ` + args.add(string(from))
	tag, err := s.pool.Exec(ctx, q, args...)
	if err != nil {
		return err
	}
	return s.pgConditionalResult(ctx, tag, id)
}

// pgConditionalResult maps "no row updated" to ErrNotFound or ErrConflict.
func (s *Postgres) pgConditionalResult(ctx context.Context, tag pgconn.CommandTag, id string) error {
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM approval_requests WHERE id = $1)`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return ErrConflict
}

// CreateGrant stores a break-glass grant.
func (s *Postgres) CreateGrant(ctx context.Context, g *Grant) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO break_glass_grants (id, human, databases, reason, step_up_method, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		g.ID, g.Human, encodeList(g.Databases), g.Reason, g.StepUpMethod, pgTime(g.CreatedAt), pgTime(g.ExpiresAt))
	return pgInsertErr(err)
}

// ListActiveGrants returns unexpired grants of a human, newest first.
func (s *Postgres) ListActiveGrants(ctx context.Context, human string, now time.Time) ([]*Grant, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, human, databases, reason, step_up_method, created_at, expires_at
		FROM break_glass_grants WHERE human = $1 AND expires_at > $2 ORDER BY created_at DESC, id`, human, pgTime(now))
	if err != nil {
		return nil, err
	}
	return pgCollect(rows, func(row scanner) (*Grant, error) {
		var g Grant
		var dbs string
		if err := row.Scan(&g.ID, &g.Human, &dbs, &g.Reason, &g.StepUpMethod, &g.CreatedAt, &g.ExpiresAt); err != nil {
			return nil, err
		}
		var err error
		if g.Databases, err = decodeList(dbs); err != nil {
			return nil, err
		}
		g.CreatedAt, g.ExpiresAt = fromPGTime(g.CreatedAt), fromPGTime(g.ExpiresAt)
		return &g, nil
	})
}
