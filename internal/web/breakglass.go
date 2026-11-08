package web

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/auth"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/web/ui"
)

// breakGlassDurations are the offered elevation lengths (up to
// break_glass.max_duration, which is always offered).
var breakGlassDurations = []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 12 * time.Hour, 24 * time.Hour}

type durationOption struct {
	Value string
	D     time.Duration
}

func (a *App) durationOptions() []durationOption {
	max := a.cfg.BreakGlass.MaxDuration.D()
	var out []durationOption
	for _, d := range breakGlassDurations {
		if d < max {
			out = append(out, durationOption{Value: d.String(), D: d})
		}
	}
	return append(out, durationOption{Value: max.String(), D: max})
}

type grantView struct {
	Databases string
	Reason    string
	ExpiresAt time.Time
	Left      time.Duration
}

// handleBreakGlass shows the break-glass form and the active elevations.
func (a *App) handleBreakGlass(w http.ResponseWriter, r *http.Request) {
	v, ok := a.viewer(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	var notice string
	if q.Get("granted") == "1" {
		notice = "breakglass.granted"
	}
	a.renderBreakGlass(w, r, v, http.StatusOK, q["db"], q.Get("d"), clip(q.Get("reason"), 1000), notice, "")
}

func (a *App) renderBreakGlass(w http.ResponseWriter, r *http.Request, v *viewer, status int, selDBs []string, dur, reason, notice, errKey string) {
	if a.svc == nil || a.cfg.BreakGlass == nil {
		a.notice(w, r, v.ws.Email, http.StatusNotFound, "breakglass.disabled")
		return
	}
	eligible := a.breakGlassDatabases(v.p)
	if len(eligible) == 0 {
		a.forbidden(w, r, v, "breakglass.not_eligible")
		return
	}
	grants, err := a.svc.ActiveGrants(r.Context(), v.p)
	if err != nil {
		a.serverError(w, r, v.ws.Email, err)
		return
	}
	now := a.now()
	var gv []grantView
	for _, g := range grants {
		gv = append(gv, grantView{Databases: strings.Join(g.Databases, ", "), Reason: ui.InertText(g.Reason), ExpiresAt: g.ExpiresAt, Left: g.ExpiresAt.Sub(now)})
	}
	var names []string
	for _, db := range eligible {
		names = append(names, db.Name)
	}
	if dur == "" {
		dur = a.cfg.BreakGlass.MaxDuration.D().String()
	}
	if len(selDBs) == 0 && len(names) == 1 {
		selDBs = names
	}
	a.render(w, r, v, status, "breakglass", "title.breakglass", "", ui.WidthDefault, map[string]any{
		"Databases": names, "SelDBs": selDBs, "Durations": a.durationOptions(), "Duration": dur, "Reason": reason,
		"Grants": gv, "Notice": notice, "Error": errKey, "Max": a.cfg.BreakGlass.MaxDuration.D(),
	})
}

// handleElevate grants a break-glass elevation. A fresh step-up is
// required; eligibility is checked by the approval service.
func (a *App) handleElevate(w http.ResponseWriter, r *http.Request) {
	v, ok := a.post(w, r)
	if !ok {
		return
	}
	if a.svc == nil || a.cfg.BreakGlass == nil {
		a.notice(w, r, v.ws.Email, http.StatusNotFound, "breakglass.disabled")
		return
	}
	dbs := r.PostForm["db"]
	dur := r.PostFormValue("duration")
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	eligible := a.breakGlassDatabases(v.p)
	if len(eligible) == 0 {
		a.forbidden(w, r, v, "breakglass.not_eligible")
		return
	}
	for _, name := range dbs {
		if !slices.ContainsFunc(eligible, func(db *config.Database) bool { return db.Name == name }) {
			a.renderBreakGlass(w, r, v, http.StatusForbidden, nil, dur, reason, "", "breakglass.error_database")
			return
		}
	}
	d, err := time.ParseDuration(dur)
	if err != nil || d <= 0 || d > a.cfg.BreakGlass.MaxDuration.D() {
		a.renderBreakGlass(w, r, v, http.StatusBadRequest, dbs, "", reason, "", "breakglass.error_duration")
		return
	}
	if len(dbs) == 0 {
		a.renderBreakGlass(w, r, v, http.StatusBadRequest, dbs, dur, reason, "", "breakglass.error_no_database")
		return
	}
	if reason == "" {
		a.renderBreakGlass(w, r, v, http.StatusBadRequest, dbs, dur, reason, "", "breakglass.error_reason")
		return
	}
	su, fresh := a.auth.StepUp(r)
	back := "/breakglass?" + url.Values{"db": dbs, "d": {dur}, "reason": {reason}}.Encode()
	if !fresh {
		http.Redirect(w, r, auth.StepUpURL(back), http.StatusSeeOther)
		return
	}
	g, err := a.svc.Elevate(r.Context(), v.p, dbs, reason, d, su)
	if err != nil {
		if status, key := approvalError(err); status != http.StatusInternalServerError {
			if errors.Is(err, approval.ErrStepUpRequired) {
				http.Redirect(w, r, auth.StepUpURL(back), http.StatusSeeOther)
				return
			}
			a.renderBreakGlass(w, r, v, status, dbs, dur, reason, "", key)
			return
		}
		a.serverError(w, r, v.ws.Email, err)
		return
	}
	a.log.Warn("web: break-glass elevation granted", "human", v.p.Human, "grant_id", g.ID, "databases", g.Databases, "expires_at", g.ExpiresAt)
	http.Redirect(w, r, "/breakglass?granted=1", http.StatusSeeOther)
}
