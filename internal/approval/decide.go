package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/events"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// maxCommentLen bounds rejection and cancellation comments.
const maxCommentLen = 1000

// stepUpSkew tolerates small clock differences for step-up timestamps.
const stepUpSkew = 30 * time.Second

func (s *Service) stepUpFresh(su StepUp, now time.Time) bool {
	if su.Method == "" || su.At.IsZero() || su.At.After(now.Add(stepUpSkew)) {
		return false
	}
	return now.Sub(su.At) <= s.cfg.Approvals.StepUpMaxAge.D()
}

// pendingCheck verifies that r can still be decided: pending, unexpired
// and intact. Expired and tampered requests are closed on the way.
func (s *Service) pendingCheck(ctx context.Context, r *Request, now time.Time) error {
	if r.Status != StatusPending {
		return ErrNotPending
	}
	if !now.Before(r.ExpiresAt) {
		s.expire(ctx, r, now)
		return ErrExpired
	}
	if r.computeHash() != r.bindingHash {
		s.logger.Error("approval request failed its integrity check", "request_id", r.ID)
		if err := s.st.TransitionApprovalRequest(ctx, r.ID, StatusPending, StatusRejected,
			store.ApprovalTransition{At: now, DecidedBy: "dbgateway", Comment: "integrity check failed"}); err == nil {
			r.Status = StatusRejected
			_ = s.writeAudit(r, "integrity_failed", "dbgateway", nil, nil)
			s.publish(ctx, events.ApprovalDecided, r, "dbgateway", nil, map[string]string{"error": "integrity check failed"})
		}
		return ErrIntegrity
	}
	return nil
}

// Approve records approver's approval of the current step of request id.
// Only humans can approve, with a step-up no older than
// approvals.step_up_max_age. After the last step the request becomes
// approved and is executed asynchronously; the returned request reflects
// the state right after the approval.
func (s *Service) Approve(ctx context.Context, approver *identity.Principal, id string, su StepUp) (*Request, error) {
	if approver == nil || approver.Kind != identity.KindHuman {
		return nil, ErrAgent
	}
	for range 3 {
		r, err := s.Get(ctx, approver, id)
		if err != nil {
			return nil, err
		}
		now := s.now()
		if err := s.pendingCheck(ctx, r, now); err != nil {
			return nil, err
		}
		if err := s.canApproveCurrent(approver, r); err != nil {
			return nil, err
		}
		if !s.stepUpFresh(su, now) {
			return nil, ErrStepUpRequired
		}
		step := r.CurrentStep
		approvals := append(slices.Clone(r.Approvals), Approval{Step: step, Approver: strings.ToLower(approver.Human), At: now,
			StepUpMethod: su.Method, StepUpAt: su.At})
		status, decidedAt := StatusPending, (*time.Time)(nil)
		if currentStep(r.Steps, approvals) == len(r.Steps) {
			status, decidedAt = StatusApproved, &now
		}
		raw, _ := json.Marshal(approvals)
		err = s.st.UpdateApprovals(ctx, r.ID, r.version, raw, status, decidedAt)
		if errors.Is(err, store.ErrConflict) {
			continue // someone else changed the request; re-check everything
		}
		if err != nil {
			return nil, err
		}
		r.Approvals, r.Status, r.DecidedAt, r.CurrentStep = approvals, status, decidedAt, currentStep(r.Steps, approvals)
		r.version++
		_ = s.writeAudit(r, "approved", approver.Human, map[string]any{"step": step, "step_up_method": su.Method,
			"step_up_at": su.At.UTC().Format(time.RFC3339)}, nil)
		var next []string
		if status == StatusPending {
			next, _ = s.Approvers(ctx, r)
		}
		s.publish(ctx, events.ApprovalDecided, r, approver.Human, next, map[string]string{"step": fmt.Sprint(step)})
		if status == StatusApproved {
			s.startExecution(context.WithoutCancel(ctx), r.ID)
		}
		return r, nil
	}
	return nil, ErrConflict
}

// Reject closes a pending request. Any human eligible for one of its steps
// may reject (no step-up required); the requester cancels instead.
func (s *Service) Reject(ctx context.Context, approver *identity.Principal, id, comment string) (*Request, error) {
	if approver == nil || approver.Kind != identity.KindHuman {
		return nil, ErrAgent
	}
	r, err := s.Get(ctx, approver, id)
	if err != nil {
		return nil, err
	}
	now := s.now()
	if err := s.pendingCheck(ctx, r, now); err != nil {
		return nil, err
	}
	if sameHuman(approver.Human, r.Requester.Human) {
		return nil, ErrSelfApproval
	}
	db := s.cfg.Database(r.Database)
	if !slices.ContainsFunc(r.Steps, func(st Step) bool { return s.eligible(approver.Human, approver.Groups, db, st) }) {
		return nil, ErrNotEligible
	}
	return s.close(ctx, r, StatusRejected, "rejected", approver.Human, comment, now)
}

// Cancel withdraws a pending request. Only the requester (the human or
// any of their agents) may cancel.
func (s *Service) Cancel(ctx context.Context, requester *identity.Principal, id string) (*Request, error) {
	r, err := s.Get(ctx, requester, id)
	if err != nil {
		return nil, err
	}
	if !sameHuman(requester.Human, r.Requester.Human) {
		return nil, ErrNotRequester
	}
	now := s.now()
	if err := s.pendingCheck(ctx, r, now); err != nil {
		return nil, err
	}
	actor := requester.Human
	if requester.IsAgent() {
		actor = requester.Agent + " (" + requester.Human + ")"
	}
	return s.close(ctx, r, StatusCanceled, "canceled", actor, "", now)
}

// close moves a pending request to a final state.
func (s *Service) close(ctx context.Context, r *Request, to Status, action, actor, comment string, now time.Time) (*Request, error) {
	if len([]rune(comment)) > maxCommentLen {
		comment = string([]rune(comment)[:maxCommentLen])
	}
	err := s.st.TransitionApprovalRequest(ctx, r.ID, StatusPending, to, store.ApprovalTransition{At: now, DecidedBy: actor, Comment: comment})
	if errors.Is(err, store.ErrConflict) {
		return nil, ErrNotPending
	}
	if err != nil {
		return nil, err
	}
	r.Status, r.DecidedAt, r.DecidedBy, r.Comment = to, &now, actor, comment
	_ = s.writeAudit(r, action, actor, map[string]any{"comment_len": len(comment)}, nil)
	s.publish(ctx, events.ApprovalDecided, r, actor, nil, nil)
	return r, nil
}

// expire closes a pending request whose deadline has passed.
func (s *Service) expire(ctx context.Context, r *Request, now time.Time) {
	err := s.st.TransitionApprovalRequest(ctx, r.ID, StatusPending, StatusExpired, store.ApprovalTransition{At: now})
	if err != nil {
		return // already decided elsewhere
	}
	r.Status, r.DecidedAt = StatusExpired, &now
	_ = s.writeAudit(r, "expired", "dbgateway", nil, nil)
	s.publish(ctx, events.ApprovalDecided, r, "", nil, nil)
}

func sha256Hex(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
