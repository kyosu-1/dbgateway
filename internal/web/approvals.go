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
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/web/i18n"
	"github.com/kyosu-1/dbgateway/internal/web/ui"
)

// requestRow is one request in a list.
type requestRow struct {
	ID        string
	Href      string
	Status    pill
	Risk      pill
	Title     string
	Sub       string
	Database  string
	When      string // time left (pending) or creation time
	Comment   string
	CanCancel bool
}

func (a *App) requestRow(p *i18n.Printer, r *approval.Request, now time.Time) requestRow {
	row := requestRow{
		ID: r.ID, Href: "/approvals/" + url.PathEscape(r.ID), Status: statusPill(r.Status), Risk: riskPill(r.Risk),
		Title:    requestTitle(p, r.Analysis.Kind, r.Analysis.Tables, r.EstimateRows),
		Sub:      requesterLabel(p, r.Requester),
		Database: r.Database,
		Comment:  ui.InertText(r.Comment),
	}
	if r.Status == approval.StatusPending {
		row.When = timeLeft(p, r.ExpiresAt, now)
	} else {
		row.When = p.Time(r.CreatedAt)
	}
	return row
}

// handleApprovals lists requests awaiting the viewer (or decided ones).
func (a *App) handleApprovals(w http.ResponseWriter, r *http.Request) {
	v, ok := a.viewer(w, r)
	if !ok {
		return
	}
	if a.svc == nil {
		a.notice(w, r, v.ws.Email, http.StatusNotFound, "approvals.disabled")
		return
	}
	if !a.isApprover(v.p) {
		a.forbidden(w, r, v, "approvals.not_approver")
		return
	}
	ctx := r.Context()
	tab := r.URL.Query().Get("tab")
	if tab != "decided" {
		tab = "awaiting"
	}
	awaiting, err := a.svc.List(ctx, v.p, approval.ListFilter{Scope: approval.ScopeAwaitingMe, Limit: 200})
	if err != nil {
		a.serverError(w, r, v.ws.Email, err)
		return
	}
	list := awaiting
	if tab == "decided" {
		if list, err = a.svc.List(ctx, v.p, approval.ListFilter{Scope: approval.ScopeDecided, Limit: 100}); err != nil {
			a.serverError(w, r, v.ws.Email, err)
			return
		}
	}
	p, now := a.ui.Printer(r), a.now()
	var rows []requestRow
	for _, req := range list {
		rows = append(rows, a.requestRow(p, req, now))
	}
	a.render(w, r, v, http.StatusOK, "approvals", "title.approvals", "approvals", ui.WidthWide, map[string]any{
		"Tab": tab, "Rows": rows, "AwaitingCount": len(awaiting), "BreakGlass": len(a.breakGlassDatabases(v.p)) > 0,
	})
}

// stepView is one approval step on the detail page.
type stepView struct {
	Number    int
	Label     string
	State     string // done | current | todo
	Approvals []approvalView
}

type approvalView struct {
	Approver string
	At       time.Time
	Method   string // message key
}

// handleApproval shows one request.
func (a *App) handleApproval(w http.ResponseWriter, r *http.Request) {
	v, ok := a.viewer(w, r)
	if !ok {
		return
	}
	if a.svc == nil {
		a.notice(w, r, v.ws.Email, http.StatusNotFound, "approvals.disabled")
		return
	}
	var notice string
	q := r.URL.Query()
	switch {
	case q.Get("done") == "approved":
		notice = "approval.notice_approved"
	case q.Get("done") == "rejected":
		notice = "approval.notice_rejected"
	case q.Get("done") == "canceled":
		notice = "approval.notice_canceled"
	case q.Get("stepped") == "1":
		if _, fresh := a.auth.StepUp(r); fresh {
			notice = "approval.notice_stepped_up"
		}
	}
	a.renderApproval(w, r, v, http.StatusOK, r.PathValue("id"), notice, "")
}

// renderApproval renders the detail page of request id for v.
func (a *App) renderApproval(w http.ResponseWriter, r *http.Request, v *viewer, status int, id, notice, errKey string) {
	ctx := r.Context()
	req, err := a.svc.Get(ctx, v.p, id)
	if errors.Is(err, approval.ErrNotFound) {
		a.notice(w, r, v.ws.Email, http.StatusNotFound, "approval.error_not_found")
		return
	}
	if err != nil {
		a.serverError(w, r, v.ws.Email, err)
		return
	}
	p, now := a.ui.Printer(r), a.now()
	pending := req.Status == approval.StatusPending && now.Before(req.ExpiresAt)
	var approvers []string
	if pending {
		if approvers, err = a.svc.Approvers(ctx, req); err != nil {
			a.log.Warn("web: list approvers", "err", err)
		}
	}
	isRequester := sameHuman(v.p.Human, req.Requester.Human)
	canApprove := pending && !isRequester && slices.ContainsFunc(approvers, func(e string) bool { return sameHuman(e, v.p.Human) })
	canReject := pending && !isRequester && a.eligibleForAnyStep(v.p, req)

	var steps []stepView
	for i, st := range req.Steps {
		sv := stepView{Number: i + 1, Label: stepLabel(p, st), State: "todo"}
		switch {
		case i < req.CurrentStep:
			sv.State = "done"
		case i == req.CurrentStep && req.Status == approval.StatusPending:
			sv.State = "current"
		}
		for _, ap := range req.Approvals {
			if ap.Step == i {
				sv.Approvals = append(sv.Approvals, approvalView{Approver: ap.Approver, At: ap.At, Method: stepUpMethodKey(ap.StepUpMethod)})
			}
		}
		steps = append(steps, sv)
	}

	sub := ""
	switch {
	case req.Requester.Kind == identity.KindAgent:
		sub = p.T("approval.sub_agent", req.Requester.Agent, req.Requester.Human, req.Database)
	case req.Requester.ClientID == ConsoleClientID:
		sub = p.T("approval.sub_console", req.Requester.Human, req.Database)
	default:
		sub = p.T("approval.sub_human", req.Requester.Human, req.Database)
	}
	var columns []string
	for _, c := range req.Analysis.Columns {
		columns = append(columns, c.Name+" ("+c.Class+")")
	}
	data := map[string]any{
		"Req":          req,
		"Title":        requestTitle(p, req.Analysis.Kind, req.Analysis.Tables, req.EstimateRows),
		"Sub":          sub,
		"Status":       statusPill(req.Status),
		"Risk":         riskLongPill(req.Risk),
		"Pending":      pending,
		"TimeLeft":     timeLeft(p, req.ExpiresAt, now),
		"Rows":         rowsPhrase(p, req.EstimateRows),
		"Tables":       tableList(p, req.Analysis.Tables),
		"Columns":      strings.Join(columns, ", "),
		"RawSQL":       ui.HighlightSQL(req.SQL),
		"NormSQL":      ui.HighlightSQL(req.NormalizedSQL),
		"Reason":       ui.InertText(req.Reason),
		"AgentReason":  req.Requester.Kind == identity.KindAgent,
		"Comment":      ui.InertText(req.Comment),
		"Steps":        steps,
		"StepCount":    len(req.Steps),
		"StepNumber":   min(req.CurrentStep+1, len(req.Steps)),
		"Approvers":    approvers,
		"CanApprove":   canApprove,
		"CanReject":    canReject,
		"CanCancel":    req.Status == approval.StatusPending && isRequester,
		"StepUpFresh":  false,
		"Notice":       notice,
		"Error":        errKey,
		"ExpireAfter":  req.ExpiresAt.Sub(req.CreatedAt),
		"ApproveURL":   "/approvals/" + url.PathEscape(req.ID) + "/approve",
		"RejectURL":    "/approvals/" + url.PathEscape(req.ID) + "/reject",
		"CancelURL":    "/requests/" + url.PathEscape(req.ID) + "/cancel",
		"AuditURL":     "",
		"DecidedLabel": "",
	}
	if _, fresh := a.auth.StepUp(r); fresh {
		data["StepUpFresh"] = true
	}
	if a.isAuditor(v.p) {
		data["AuditURL"] = "/audit/" + url.PathEscape(req.ID)
	}
	if req.Result != nil {
		data["Result"] = req.Result
		if len(req.Result.Columns) > 0 {
			data["ResultTable"] = newTableView(req.Result.Columns, req.Result.Rows)
		}
		data["ResultError"] = ui.InertText(req.Result.Error)
		if b := req.Result.Backup; b != nil && b.RestoreSQL != "" {
			data["RestoreSQL"] = ui.HighlightSQL(b.RestoreSQL)
			data["RestoreURL"] = "/console?restore=" + url.QueryEscape(req.ID)
		}
	}
	a.render(w, r, v, status, "approval", "title.approval", "approvals", ui.WidthDefault, data)
}

// eligibleForAnyStep mirrors the service's rejection rule for display (the
// service enforces it).
func (a *App) eligibleForAnyStep(p *identity.Principal, req *approval.Request) bool {
	db := a.cfg.Database(req.Database)
	if db == nil {
		return false
	}
	for _, st := range req.Steps {
		if st.Group != "" && slices.Contains(p.Groups, st.Group) {
			return true
		}
		if st.Role != "" && a.rbac.HumanHas(p.Human, p.Groups, db, st.Role) {
			return true
		}
	}
	return false
}

// handleApprove approves the current step. A fresh step-up is required:
// without one the user is sent to /stepup and back to the detail page.
func (a *App) handleApprove(w http.ResponseWriter, r *http.Request) {
	v, ok := a.post(w, r)
	if !ok {
		return
	}
	if a.svc == nil {
		a.notice(w, r, v.ws.Email, http.StatusNotFound, "approvals.disabled")
		return
	}
	id := r.PathValue("id")
	back := "/approvals/" + url.PathEscape(id)
	su, fresh := a.auth.StepUp(r)
	if !fresh {
		http.Redirect(w, r, auth.StepUpURL(back+"?stepped=1#decide"), http.StatusSeeOther)
		return
	}
	_, err := a.svc.Approve(r.Context(), v.p, id, su)
	if errors.Is(err, approval.ErrStepUpRequired) {
		http.Redirect(w, r, auth.StepUpURL(back+"?stepped=1#decide"), http.StatusSeeOther)
		return
	}
	if err != nil {
		a.decisionError(w, r, v, id, err)
		return
	}
	a.log.Info("web: approved", "request_id", id, "approver", v.p.Human, "step_up", su.Method)
	http.Redirect(w, r, back+"?done=approved", http.StatusSeeOther)
}

// handleReject rejects a pending request with an optional comment.
func (a *App) handleReject(w http.ResponseWriter, r *http.Request) {
	v, ok := a.post(w, r)
	if !ok {
		return
	}
	if a.svc == nil {
		a.notice(w, r, v.ws.Email, http.StatusNotFound, "approvals.disabled")
		return
	}
	id := r.PathValue("id")
	if _, err := a.svc.Reject(r.Context(), v.p, id, strings.TrimSpace(r.PostFormValue("comment"))); err != nil {
		a.decisionError(w, r, v, id, err)
		return
	}
	a.log.Info("web: rejected", "request_id", id, "approver", v.p.Human)
	http.Redirect(w, r, "/approvals/"+url.PathEscape(id)+"?done=rejected", http.StatusSeeOther)
}

// decisionError shows a failed decision on the detail page (or as a page
// of its own when the request is not visible).
func (a *App) decisionError(w http.ResponseWriter, r *http.Request, v *viewer, id string, err error) {
	status, key := approvalError(err)
	if status == http.StatusInternalServerError {
		a.serverError(w, r, v.ws.Email, err)
		return
	}
	if errors.Is(err, approval.ErrNotFound) {
		a.notice(w, r, v.ws.Email, status, key)
		return
	}
	a.renderApproval(w, r, v, status, id, "", key)
}

// approvalError maps service errors to a status and a message key.
func approvalError(err error) (int, string) {
	for _, m := range []struct {
		err    error
		status int
		key    string
	}{
		{approval.ErrNotFound, http.StatusNotFound, "approval.error_not_found"},
		{approval.ErrAgent, http.StatusForbidden, "approval.error_agent"},
		{approval.ErrSelfApproval, http.StatusForbidden, "approval.error_self"},
		{approval.ErrAlreadyActed, http.StatusConflict, "approval.error_already"},
		{approval.ErrNotEligible, http.StatusForbidden, "approval.error_not_eligible"},
		{approval.ErrNotRequester, http.StatusForbidden, "approval.error_not_requester"},
		{approval.ErrStepUpRequired, http.StatusForbidden, "approval.error_stepup"},
		{approval.ErrNotPending, http.StatusConflict, "approval.error_not_pending"},
		{approval.ErrExpired, http.StatusConflict, "approval.error_expired"},
		{approval.ErrIntegrity, http.StatusConflict, "approval.error_integrity"},
		{approval.ErrConflict, http.StatusConflict, "approval.error_conflict"},
		{approval.ErrUnavailable, http.StatusNotFound, "approvals.disabled"},
		{approval.ErrBreakGlassOff, http.StatusNotFound, "breakglass.disabled"},
		{approval.ErrReasonRequired, http.StatusBadRequest, "breakglass.error_reason"},
		{approval.ErrInvalidRequest, http.StatusBadRequest, "approval.error_invalid"},
	} {
		if errors.Is(err, m.err) {
			return m.status, m.key
		}
	}
	return http.StatusInternalServerError, "error.internal"
}

// handleRequests lists the viewer's requests (and their agents').
func (a *App) handleRequests(w http.ResponseWriter, r *http.Request) {
	v, ok := a.viewer(w, r)
	if !ok {
		return
	}
	if a.svc == nil {
		a.notice(w, r, v.ws.Email, http.StatusNotFound, "approvals.disabled")
		return
	}
	list, err := a.svc.List(r.Context(), v.p, approval.ListFilter{Scope: approval.ScopeMine, Limit: 200})
	if err != nil {
		a.serverError(w, r, v.ws.Email, err)
		return
	}
	tab := r.URL.Query().Get("status")
	groups := map[string][]approval.Status{
		"pending": {approval.StatusPending, approval.StatusApproved, approval.StatusRunning},
		"done":    {approval.StatusSucceeded, approval.StatusFailed},
		"closed":  {approval.StatusRejected, approval.StatusExpired, approval.StatusCanceled},
	}
	if _, ok := groups[tab]; !ok {
		tab = "all"
	}
	p, now := a.ui.Printer(r), a.now()
	var rows []requestRow
	pendingCount := 0
	for _, req := range list {
		if slices.Contains(groups["pending"], req.Status) {
			pendingCount++
		}
		if tab != "all" && !slices.Contains(groups[tab], req.Status) {
			continue
		}
		row := a.requestRow(p, req, now)
		parts := []string{}
		if src := sourceLabel(p, req.Requester); src != "" {
			parts = append(parts, src)
		}
		parts = append(parts, req.Database)
		if row.Comment != "" {
			parts = append(parts, p.T("req.quoted", row.Comment))
		}
		row.Sub = strings.Join(parts, " · ")
		row.When = p.Time(req.CreatedAt)
		row.CanCancel = req.Status == approval.StatusPending && now.Before(req.ExpiresAt)
		rows = append(rows, row)
	}
	var notice string
	if r.URL.Query().Get("canceled") == "1" {
		notice = "requests.canceled_notice"
	}
	a.render(w, r, v, http.StatusOK, "requests", "title.requests", "requests", ui.WidthWide, map[string]any{
		"Tab": tab, "Rows": rows, "PendingCount": pendingCount, "Notice": notice,
	})
}

// handleCancel withdraws one of the viewer's pending requests.
func (a *App) handleCancel(w http.ResponseWriter, r *http.Request) {
	v, ok := a.post(w, r)
	if !ok {
		return
	}
	if a.svc == nil {
		a.notice(w, r, v.ws.Email, http.StatusNotFound, "approvals.disabled")
		return
	}
	id := r.PathValue("id")
	if _, err := a.svc.Cancel(r.Context(), v.p, id); err != nil {
		status, key := approvalError(err)
		if status == http.StatusInternalServerError {
			a.serverError(w, r, v.ws.Email, err)
			return
		}
		a.notice(w, r, v.ws.Email, status, key)
		return
	}
	a.log.Info("web: request canceled", "request_id", id, "requester", v.p.Human)
	if r.PostFormValue("from") == "detail" {
		http.Redirect(w, r, "/approvals/"+url.PathEscape(id)+"?done=canceled", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/requests?canceled=1", http.StatusSeeOther)
}
