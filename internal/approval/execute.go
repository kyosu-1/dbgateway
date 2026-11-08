package approval

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/events"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// startExecution runs an approved request in the background.
func (s *Service) startExecution(ctx context.Context, id string) {
	s.wg.Go(func() { s.execute(ctx, id) })
}

// execute claims an approved request (approved → running, a conditional
// update: exactly one worker wins and the approval is consumed) and runs
// it. It returns false if the request was not claimed.
func (s *Service) execute(ctx context.Context, id string) bool {
	now := s.now()
	err := s.st.TransitionApprovalRequest(ctx, id, StatusApproved, StatusRunning, store.ApprovalTransition{At: now})
	if err != nil {
		if !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrNotFound) {
			s.logger.Error("claim approved request failed", "err", err, "request_id", id)
		}
		return false
	}
	r, err := s.load(ctx, id)
	if err != nil {
		s.logger.Error("load claimed request failed", "err", err, "request_id", id)
		s.finishFailed(ctx, &Request{ID: id, Status: StatusRunning}, "Not executed because the request could not be loaded.")
		return true
	}
	if r.computeHash() != r.bindingHash {
		s.finishFailed(ctx, r, "Not executed because the binding hash does not match (the request may have been changed after it was submitted).")
		return true
	}
	if err := s.writeAudit(r, "running", "dbgateway", nil, nil); err != nil {
		s.finishFailed(ctx, r, "Not executed because the audit log could not be written.")
		return true
	}
	p, err := s.requesterPrincipal(ctx, r)
	if err != nil {
		s.finishFailed(ctx, r, "Not executed because the requester's permissions could not be verified.")
		return true
	}

	wr, err := s.exec.ExecuteApproved(ctx, p, gateway.ApprovedWrite{RequestID: r.ID, Database: r.Database, SQL: r.SQL,
		ApprovalRule: r.ApprovalRule, MaxAffectedRows: r.MaxAffectedRows})
	res := &Result{}
	status := StatusSucceeded
	if wr != nil {
		res.RowsAffected, res.Columns, res.Rows, res.RowCount, res.Truncated, res.DurationMS =
			wr.RowsAffected, wr.Columns, wr.Rows, wr.RowCount, wr.Truncated, wr.DurationMS
	}
	if err != nil {
		res.Error, res.Code = gateway.DescribeError(err)
		if wr == nil {
			// Nothing was committed. (A non-nil result with an error means
			// the write committed but its RETURNING rows were withheld.)
			status = StatusFailed
		}
	}
	s.finish(ctx, r, status, res, wr)
	return true
}

// requesterPrincipal rebuilds the requester for re-evaluation: groups are
// resolved now (IdP snapshot of the last login and the current
// configuration). An agent is assumed to still hold the write scope it
// needed to submit; its human's current roles still bound it.
func (s *Service) requesterPrincipal(ctx context.Context, r *Request) (*identity.Principal, error) {
	groups, err := s.groupsOf(ctx, r.Requester.Human)
	if err != nil {
		return nil, err
	}
	p := &identity.Principal{Kind: r.Requester.Kind, Human: r.Requester.Human, Agent: r.Requester.Agent,
		ClientID: r.Requester.ClientID, Groups: groups, Scopes: []string{identity.ScopeRead}}
	if p.IsAgent() {
		p.Scopes = append(p.Scopes, identity.ScopeWrite)
	}
	return p, nil
}

func (s *Service) finishFailed(ctx context.Context, r *Request, msg string) {
	s.finish(ctx, r, StatusFailed, &Result{Error: msg}, nil)
}

// finish moves a running request to its final state, audits it and emits
// execution_finished.
func (s *Service) finish(ctx context.Context, r *Request, status Status, res *Result, wr *gateway.WriteResult) {
	now := s.now()
	raw, _ := json.Marshal(res)
	if err := s.st.TransitionApprovalRequest(ctx, r.ID, StatusRunning, status, store.ApprovalTransition{At: now, Result: raw}); err != nil {
		s.logger.Error("record execution result failed", "err", err, "request_id", r.ID, "status", status)
	}
	r.Status, r.Result, r.FinishedAt = status, res, &now
	ri := &audit.ResultInfo{Rows: res.RowCount, DurationMS: res.DurationMS, Truncated: res.Truncated}
	if wr != nil {
		ri.Bytes, ri.MaskedColumns = wr.Bytes, wr.MaskedColumns
	}
	if res.Error != "" {
		msg := res.Error
		ri.Error = &msg
	}
	_ = s.writeAudit(r, string(status), "dbgateway", map[string]any{"rows_affected": res.RowsAffected}, ri)
	detail := map[string]string{"rows_affected": itoa(res.RowsAffected)}
	if res.Error != "" {
		detail["error"] = res.Error
	}
	s.publish(ctx, events.ExecutionFinished, r, "", nil, detail)
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// Run expires pending requests, fails requests left running by a crash,
// and starts approved requests that are not running (e.g. after a
// restart). It returns when ctx is done, after in-flight executions end.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		s.Sweep(ctx)
		select {
		case <-ctx.Done():
			s.wg.Wait()
			return
		case <-t.C:
		}
	}
}

// Sweep performs one pass of the Run loop. Exported for tests and for
// callers that drive their own schedule.
func (s *Service) Sweep(ctx context.Context) {
	now := s.now()
	expired, err := s.st.ListApprovalRequests(ctx, store.ApprovalFilter{Statuses: []Status{StatusPending}, ExpiresBefore: now, Limit: scanLimit})
	if err != nil {
		s.logger.Error("list expired requests failed", "err", err)
	}
	for _, row := range expired {
		if r, err := fromStore(row, s.cfg.Server.PublicURL); err == nil {
			s.expire(ctx, r, now)
		}
	}

	running, err := s.st.ListApprovalRequests(ctx, store.ApprovalFilter{Statuses: []Status{StatusRunning}, Limit: scanLimit})
	if err != nil {
		s.logger.Error("list running requests failed", "err", err)
	}
	stale := s.staleAfter()
	for _, row := range running {
		if row.StartedAt == nil || now.Sub(*row.StartedAt) < stale {
			continue
		}
		r, err := fromStore(row, s.cfg.Server.PublicURL)
		if err != nil {
			continue
		}
		// The process stopped mid-execution: the outcome is unknown and
		// the write must never run again.
		s.finish(ctx, r, StatusFailed, &Result{Error: "dbgateway stopped during the execution, so the result is unknown. Check the database."}, nil)
	}

	approved, err := s.st.ListApprovalRequests(ctx, store.ApprovalFilter{Statuses: []Status{StatusApproved}, Limit: scanLimit})
	if err != nil {
		s.logger.Error("list approved requests failed", "err", err)
	}
	for _, row := range approved {
		s.startExecution(context.WithoutCancel(ctx), row.ID)
	}
}

// staleAfter is how long a request may stay running before it is
// considered abandoned: longer than an execution can take. An execution
// runs up to three bounded database operations (catalog, EXPLAIN, the
// write), each limited to the statement timeout plus 5 seconds.
func (s *Service) staleAfter() time.Duration {
	longest := 10 * time.Second
	for _, db := range s.cfg.Databases {
		longest = max(longest, db.Limits.StatementTimeout.D())
	}
	return 3*(longest+5*time.Second) + time.Minute
}
