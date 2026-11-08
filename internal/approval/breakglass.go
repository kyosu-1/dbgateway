package approval

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/events"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

// Elevate grants p a break-glass elevation on dbs for d (at most
// break_glass.max_duration; zero means the maximum). p must be a human
// with the approver role on every database, each selected by
// break_glass.databases, give a reason and a fresh step-up. The elevation
// is audited (event "break_glass") and break_glass_used is emitted.
func (s *Service) Elevate(ctx context.Context, p *identity.Principal, dbs []string, reason string, d time.Duration, su StepUp) (*Grant, error) {
	bg := s.cfg.BreakGlass
	if !s.cfg.Approvals.Enabled || bg == nil {
		return nil, ErrBreakGlassOff
	}
	if p == nil || p.Kind != identity.KindHuman {
		return nil, ErrAgent
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, ErrReasonRequired
	}
	now := s.now()
	if !s.stepUpFresh(su, now) {
		return nil, ErrStepUpRequired
	}
	if d <= 0 {
		d = bg.MaxDuration.D()
	}
	if d > bg.MaxDuration.D() {
		return nil, fmt.Errorf("%w: duration exceeds break_glass.max_duration (%s)", ErrInvalidRequest, bg.MaxDuration)
	}
	if len(dbs) == 0 {
		return nil, fmt.Errorf("%w: no database", ErrInvalidRequest)
	}
	dbs = slices.Compact(slices.Sorted(slices.Values(dbs)))
	for _, name := range dbs {
		if !s.elevatable(p, s.cfg.Database(name)) {
			return nil, fmt.Errorf("%w: %s", ErrNotEligible, name)
		}
	}
	g := &Grant{ID: newID("bg_"), Human: p.Human, Databases: dbs, Reason: reason, StepUpMethod: su.Method,
		CreatedAt: now, ExpiresAt: now.Add(d)}
	if s.audit == nil {
		return nil, fmt.Errorf("approval: no audit log configured")
	}
	if err := s.audit.Write(&audit.Entry{
		RequestID: g.ID, Event: "break_glass", Principal: audit.PrincipalInfo{Kind: string(p.Kind), Human: p.Human},
		Database: strings.Join(dbs, ","), Reason: reason, Decision: config.ActionAllow, Stage: "break_glass", ConfigVersion: s.cfg.Version,
		Extra: map[string]any{"databases": dbs, "expires_at": g.ExpiresAt.UTC().Format(time.RFC3339), "step_up_method": su.Method},
	}); err != nil {
		return nil, fmt.Errorf("approval: audit: %w", err)
	}
	if err := s.st.CreateGrant(ctx, g); err != nil {
		return nil, err
	}
	e := events.Event{Type: events.BreakGlassUsed, Time: now, RequestID: g.ID, Database: dbs[0],
		Principal: &events.Principal{Kind: string(p.Kind), Human: p.Human}, Reason: reason, Actor: p.Human,
		Detail: map[string]string{"databases": strings.Join(dbs, ","), "expires_at": g.ExpiresAt.UTC().Format(time.RFC3339)}}
	if db := s.cfg.Database(dbs[0]); db != nil {
		e.Labels = db.Labels
	}
	s.events.Publish(context.WithoutCancel(ctx), e)
	return g, nil
}

// elevatable reports whether p may hold a break-glass elevation on db.
func (s *Service) elevatable(p *identity.Principal, db *config.Database) bool {
	bg := s.cfg.BreakGlass
	return bg != nil && db != nil && p.Kind == identity.KindHuman && bg.Databases.Matches(db) &&
		s.rbac.Has(p, db, identity.RoleApprover)
}

// ElevationActive implements gateway.Approvals: whether the human p has an
// unexpired elevation covering db, and still qualifies for it under the
// current configuration. Errors count as "not elevated".
func (s *Service) ElevationActive(ctx context.Context, p *identity.Principal, db string) bool {
	if !s.cfg.Approvals.Enabled || p == nil || !s.elevatable(p, s.cfg.Database(db)) {
		return false
	}
	grants, err := s.st.ListActiveGrants(ctx, p.Human, s.now())
	if err != nil {
		s.logger.Error("list break-glass grants failed", "err", err)
		return false
	}
	return slices.ContainsFunc(grants, func(g *Grant) bool { return slices.Contains(g.Databases, db) })
}

// ActiveGrants returns p's unexpired elevations (for the web UI).
func (s *Service) ActiveGrants(ctx context.Context, p *identity.Principal) ([]*Grant, error) {
	if p == nil || p.Kind != identity.KindHuman {
		return nil, nil
	}
	return s.st.ListActiveGrants(ctx, p.Human, s.now())
}

func newID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return prefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
}
