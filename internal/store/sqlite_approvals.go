package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/identity"
)

const approvalColumns = `id, requester_kind, requester_human, requester_agent, requester_client_id, database_name,
	raw_sql, normalized_sql, reason, analysis_json, estimate_rows, max_affected_rows, risk, approval_rule,
	steps_json, approvals_json, config_version, binding_hash, status, version, created_at, expires_at,
	decided_at, decided_by, decision_comment, started_at, finished_at, result_json`

// CreateApprovalRequest stores a new approval request.
func (s *SQLite) CreateApprovalRequest(ctx context.Context, r *ApprovalRequest) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO approval_requests (`+approvalColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, string(r.RequesterKind), r.RequesterHuman, r.RequesterAgent, r.RequesterClientID, r.Database,
		r.RawSQL, r.NormalizedSQL, r.Reason, jsonText(r.AnalysisJSON, "{}"), r.EstimateRows, r.MaxAffectedRows, r.Risk, r.ApprovalRule,
		jsonText(r.StepsJSON, "[]"), jsonText(r.ApprovalsJSON, "[]"), r.ConfigVersion, r.BindingHash, string(r.Status), r.Version,
		ms(r.CreatedAt), ms(r.ExpiresAt), nullMS(r.DecidedAt), r.DecidedBy, r.Comment, nullMS(r.StartedAt), nullMS(r.FinishedAt),
		string(r.ResultJSON))
	return insertErr(err)
}

func jsonText(b []byte, def string) string {
	if len(b) == 0 {
		return def
	}
	return string(b)
}

func scanApproval(sc scanner) (*ApprovalRequest, error) {
	var r ApprovalRequest
	var kind, status, analysis, steps, approvals, result string
	var created, expires int64
	var decided, started, finished sql.NullInt64
	err := sc.Scan(&r.ID, &kind, &r.RequesterHuman, &r.RequesterAgent, &r.RequesterClientID, &r.Database,
		&r.RawSQL, &r.NormalizedSQL, &r.Reason, &analysis, &r.EstimateRows, &r.MaxAffectedRows, &r.Risk, &r.ApprovalRule,
		&steps, &approvals, &r.ConfigVersion, &r.BindingHash, &status, &r.Version, &created, &expires,
		&decided, &r.DecidedBy, &r.Comment, &started, &finished, &result)
	if err != nil {
		return nil, notFound(err)
	}
	r.RequesterKind, r.Status = identity.Kind(kind), ApprovalStatus(status)
	r.AnalysisJSON, r.StepsJSON, r.ApprovalsJSON = []byte(analysis), []byte(steps), []byte(approvals)
	if result != "" {
		r.ResultJSON = []byte(result)
	}
	r.CreatedAt, r.ExpiresAt = fromMS(created), fromMS(expires)
	r.DecidedAt, r.StartedAt, r.FinishedAt = fromNullMS(decided), fromNullMS(started), fromNullMS(finished)
	return &r, nil
}

// GetApprovalRequest returns a request by ID.
func (s *SQLite) GetApprovalRequest(ctx context.Context, id string) (*ApprovalRequest, error) {
	return scanApproval(s.db.QueryRowContext(ctx, `SELECT `+approvalColumns+` FROM approval_requests WHERE id = ?`, id))
}

// ListApprovalRequests returns matching requests, newest first.
func (s *SQLite) ListApprovalRequests(ctx context.Context, f ApprovalFilter) ([]*ApprovalRequest, error) {
	var where []string
	var args []any
	if f.RequesterHuman != "" {
		where, args = append(where, "requester_human = ?"), append(args, f.RequesterHuman)
	}
	if f.Database != "" {
		where, args = append(where, "database_name = ?"), append(args, f.Database)
	}
	if len(f.Statuses) > 0 {
		where = append(where, "status IN (?"+strings.Repeat(", ?", len(f.Statuses)-1)+")")
		for _, st := range f.Statuses {
			args = append(args, string(st))
		}
	}
	if !f.ExpiresBefore.IsZero() {
		where, args = append(where, "expires_at < ?"), append(args, ms(f.ExpiresBefore))
	}
	q := `SELECT ` + approvalColumns + ` FROM approval_requests`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC, id LIMIT %d", min(limit, 1000))
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ApprovalRequest
	for rows.Next() {
		r, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateApprovals records approvals with optimistic concurrency.
func (s *SQLite) UpdateApprovals(ctx context.Context, id string, version int64, approvalsJSON []byte, status ApprovalStatus, decidedAt *time.Time) error {
	if status != ApprovalPending && status != ApprovalApproved {
		return fmt.Errorf("store: UpdateApprovals: invalid status %q", status)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE approval_requests
		SET approvals_json = ?, status = ?, decided_at = COALESCE(?, decided_at), version = version + 1
		WHERE id = ? AND status = 'pending' AND version = ?`,
		jsonText(approvalsJSON, "[]"), string(status), nullMS(decidedAt), id, version)
	if err != nil {
		return err
	}
	return s.conditionalResult(ctx, res, id)
}

// TransitionApprovalRequest performs a conditional status change.
func (s *SQLite) TransitionApprovalRequest(ctx context.Context, id string, from, to ApprovalStatus, t ApprovalTransition) error {
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
	q := `UPDATE approval_requests SET status = ?, version = version + 1, ` + col + ` = ?`
	args := []any{string(to), ms(t.At)}
	if t.DecidedBy != "" || t.Comment != "" {
		q += `, decided_by = ?, decision_comment = ?`
		args = append(args, t.DecidedBy, t.Comment)
	}
	if t.Result != nil {
		q += `, result_json = ?`
		args = append(args, string(t.Result))
	}
	q += ` WHERE id = ? AND status = ?`
	args = append(args, id, string(from))
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	return s.conditionalResult(ctx, res, id)
}

// conditionalResult maps "no row updated" to ErrNotFound or ErrConflict.
func (s *SQLite) conditionalResult(ctx context.Context, res sql.Result, id string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	var one int
	err = s.db.QueryRowContext(ctx, `SELECT 1 FROM approval_requests WHERE id = ?`, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return ErrConflict
}

// CreateGrant stores a break-glass grant.
func (s *SQLite) CreateGrant(ctx context.Context, g *Grant) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO break_glass_grants (id, human, databases, reason, step_up_method, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		g.ID, g.Human, encodeList(g.Databases), g.Reason, g.StepUpMethod, ms(g.CreatedAt), ms(g.ExpiresAt))
	return insertErr(err)
}

// ListActiveGrants returns unexpired grants of a human, newest first.
func (s *SQLite) ListActiveGrants(ctx context.Context, human string, now time.Time) ([]*Grant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, human, databases, reason, step_up_method, created_at, expires_at
		FROM break_glass_grants WHERE human = ? AND expires_at > ? ORDER BY created_at DESC`, human, ms(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Grant
	for rows.Next() {
		var g Grant
		var dbs string
		var created, expires int64
		if err := rows.Scan(&g.ID, &g.Human, &dbs, &g.Reason, &g.StepUpMethod, &created, &expires); err != nil {
			return nil, err
		}
		if g.Databases, err = decodeList(dbs); err != nil {
			return nil, err
		}
		g.CreatedAt, g.ExpiresAt = fromMS(created), fromMS(expires)
		out = append(out, &g)
	}
	return out, rows.Err()
}

// ListUsers returns every user ordered by e-mail.
func (s *SQLite) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT email, idp_groups, created_at, last_login_at FROM users ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		var u User
		var groups string
		var created, last int64
		if err := rows.Scan(&u.Email, &groups, &created, &last); err != nil {
			return nil, err
		}
		if u.IDPGroups, err = decodeList(groups); err != nil {
			return nil, err
		}
		u.CreatedAt, u.LastLoginAt = fromMS(created), fromMS(last)
		out = append(out, &u)
	}
	return out, rows.Err()
}
