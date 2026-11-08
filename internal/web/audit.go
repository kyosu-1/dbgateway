package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/web/i18n"
	"github.com/kyosu-1/dbgateway/internal/web/ui"
)

// auditPeriod is a selectable time range of the audit search.
type auditPeriod struct {
	Value string
	Key   string
	D     time.Duration
}

var auditPeriods = []auditPeriod{
	{"24h", "audit.period_24h", 24 * time.Hour},
	{"7d", "audit.period_7d", 7 * 24 * time.Hour},
	{"30d", "audit.period_30d", 30 * 24 * time.Hour},
	{"all", "audit.period_all", 0},
}

var auditDecisions = []string{"allow", "approve", "deny", "error"}

// auditRow is one entry in the audit list.
type auditRow struct {
	Href     string
	Time     time.Time
	Decision pill
	Title    string
	Sub      string
}

// auditTitle summarizes an entry: "users の読み取り · 3行".
func auditTitle(p *i18n.Printer, e *audit.StoredEntry) string {
	switch e.Event {
	case "query", "explain":
		key := "audit.title.query"
		if e.Event == "explain" {
			key = "audit.title.explain"
		}
		if e.Analysis == nil || len(e.Analysis.Tables) == 0 {
			return p.T(key + ".unknown")
		}
		tables := tableList(p, e.Analysis.Tables)
		var s string
		switch {
		case e.Analysis.Kind == "select" && !e.Analysis.IsWrite:
			s = p.T(key+".read", tables)
		case e.Analysis.Kind == "ddl":
			s = p.T(key+".ddl", tables)
		default:
			s = p.T(key+".write", tables)
		}
		if e.Result != nil && e.Result.Error == nil && e.Event == "query" && e.Decision == "allow" && e.Result.Rows > 0 {
			s += " · " + rowsPhrase(p, float64(e.Result.Rows))
		}
		return s
	case "approval":
		action, _ := e.Extra["action"].(string)
		label := p.T("audit.action." + action)
		if label == "audit.action."+action {
			label = action
		}
		return p.T("audit.title.approval", label)
	case "search":
		return p.T("audit.title.search")
	case "list":
		return p.T("audit.title.list")
	case "break_glass":
		return p.T("audit.title.break_glass", e.Database)
	}
	return e.Event
}

// auditPrincipal is "claude-code（taro@example.com）" or the e-mail.
func auditPrincipal(p *i18n.Printer, pi audit.PrincipalInfo) string {
	switch {
	case pi.Agent != "":
		return p.T("audit.principal_agent", pi.Agent, pi.Human)
	case pi.ClientID == ConsoleClientID:
		return p.T("audit.principal_console", pi.Human)
	}
	return pi.Human
}

func entryTime(e *audit.StoredEntry) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, e.TS)
	return t
}

// handleAudit searches the audit log (auditors and admins).
func (a *App) handleAudit(w http.ResponseWriter, r *http.Request) {
	v, ok := a.viewer(w, r)
	if !ok {
		return
	}
	if !a.isAuditor(v.p) {
		a.forbidden(w, r, v, "audit.forbidden")
		return
	}
	q := r.URL.Query()
	period := q.Get("period")
	if !slices.ContainsFunc(auditPeriods, func(p auditPeriod) bool { return p.Value == period }) {
		period = "24h"
	}
	decision := q.Get("decision")
	if !slices.Contains(auditDecisions, decision) {
		decision = ""
	}
	dbName := q.Get("db")
	if a.cfg.Database(dbName) == nil {
		dbName = ""
	}
	f := audit.Filter{
		Principal: clip(q.Get("principal"), 254),
		Database:  dbName,
		Decision:  decision,
		Table:     clip(q.Get("table"), 128),
		Cursor:    clip(q.Get("cursor"), 1024),
		Limit:     50,
	}
	for _, p := range auditPeriods {
		if p.Value == period && p.D > 0 {
			f.Since = a.now().Add(-p.D)
		}
	}
	data := map[string]any{
		"Periods": auditPeriods, "Decisions": auditDecisions, "Databases": a.cfg.Databases,
		"Period": period, "Decision": decision, "DB": dbName, "Principal": f.Principal, "Table": f.Table,
	}
	if a.cfg.Audit.Output != "file" {
		data["NotFile"] = true
		a.render(w, r, v, http.StatusOK, "audit", "title.audit", "audit", ui.WidthWide, data)
		return
	}
	page, err := audit.Search(a.cfg.Audit.Dir, f)
	if errors.Is(err, audit.ErrInvalidCursor) {
		a.notice(w, r, v.ws.Email, http.StatusBadRequest, "error.bad_request")
		return
	}
	if err != nil {
		a.serverError(w, r, v.ws.Email, err)
		return
	}
	p := a.ui.Printer(r)
	var rows []auditRow
	for i := range page.Entries {
		e := &page.Entries[i]
		sub := auditPrincipal(p, e.Principal)
		if e.Database != "" && e.Event != "break_glass" {
			sub += " · " + e.Database
		}
		rows = append(rows, auditRow{Href: "/audit/" + url.PathEscape(e.RequestID), Time: entryTime(e), Decision: decisionPill(e.Decision),
			Title: auditTitle(p, e), Sub: sub})
	}
	data["Rows"] = rows
	data["Skipped"] = page.Skipped
	if page.NextCursor != "" {
		nq := url.Values{}
		for k, vs := range q {
			if k != "cursor" {
				nq[k] = vs
			}
		}
		nq.Set("cursor", page.NextCursor)
		data["NextURL"] = "/audit?" + nq.Encode()
	}
	a.render(w, r, v, http.StatusOK, "audit", "title.audit", "audit", ui.WidthWide, data)
}

// timelineRow is one entry on the audit detail page.
type timelineRow struct {
	Time     time.Time
	Title    string
	Actor    string
	Decision pill
}

// handleAuditEntry shows every entry of one request ID.
func (a *App) handleAuditEntry(w http.ResponseWriter, r *http.Request) {
	v, ok := a.viewer(w, r)
	if !ok {
		return
	}
	if !a.isAuditor(v.p) {
		a.forbidden(w, r, v, "audit.forbidden")
		return
	}
	if a.cfg.Audit.Output != "file" {
		a.notice(w, r, v.ws.Email, http.StatusNotFound, "audit.not_file")
		return
	}
	id := r.PathValue("request_id")
	if id == "" || len(id) > 128 {
		a.notice(w, r, v.ws.Email, http.StatusNotFound, "audit.entry_not_found")
		return
	}
	page, err := audit.Search(a.cfg.Audit.Dir, audit.Filter{RequestID: id, Limit: audit.MaxSearchLimit})
	if err != nil {
		a.serverError(w, r, v.ws.Email, err)
		return
	}
	if len(page.Entries) == 0 {
		a.notice(w, r, v.ws.Email, http.StatusNotFound, "audit.entry_not_found")
		return
	}
	// Entries are newest first; the main one is the original query (or
	// the oldest entry).
	main := &page.Entries[len(page.Entries)-1]
	for i := range page.Entries {
		if page.Entries[i].Event == "query" {
			main = &page.Entries[i]
		}
	}
	p := a.ui.Printer(r)
	var timeline []timelineRow
	for i := len(page.Entries) - 1; i >= 0; i-- {
		e := &page.Entries[i]
		actor, _ := e.Extra["actor"].(string)
		if actor == "" {
			actor = auditPrincipal(p, e.Principal)
		}
		timeline = append(timeline, timelineRow{Time: entryTime(e), Title: auditTitle(p, e), Actor: actor, Decision: decisionPill(e.Decision)})
	}
	sub := p.T("audit.entry_sub_human", auditPrincipal(p, main.Principal))
	if main.Principal.Agent != "" {
		sub = p.T("audit.entry_sub_agent", main.Principal.Agent, main.Principal.Human)
	}
	if main.Database != "" {
		sub += " · " + main.Database
	}
	filterBy := main.Principal.Human
	if main.Principal.Agent != "" {
		filterBy = main.Principal.Agent
	}
	data := map[string]any{
		"E":         main,
		"Time":      entryTime(main),
		"Decision":  decisionPill(main.Decision),
		"Title":     auditTitle(p, main),
		"Sub":       sub,
		"SQL":       ui.HighlightSQL(main.SQL),
		"RawLogged": a.cfg.Audit.LogRawSQL,
		"Reason":    ui.InertText(main.Reason),
		"Agent":     main.Principal.Agent != "",
		"Timeline":  timeline,
		"Extra":     extraRows(main.Extra),
		"MoreURL":   "/audit?" + url.Values{"principal": {filterBy}, "period": {"7d"}}.Encode(),
		"Approval":  "",
	}
	if main.Result != nil && main.Result.Error != nil {
		data["ResultError"] = ui.InertText(*main.Result.Error)
	}
	if a.svc != nil && strings.HasPrefix(id, "req_") {
		if _, err := a.svc.Get(r.Context(), v.p, id); err == nil {
			data["Approval"] = "/approvals/" + url.PathEscape(id)
		}
	}
	a.render(w, r, v, http.StatusOK, "audit_entry", "title.audit_entry", "audit", ui.WidthDefault, data)
}

// kv is one technical detail.
type kv struct{ Key, Value string }

// extraRows formats the free-form extra fields (sorted by key).
func extraRows(extra map[string]any) []kv {
	var out []kv
	for k, v := range extra {
		out = append(out, kv{k, ui.InertText(clip(fmt.Sprint(v), 500))})
	}
	slices.SortFunc(out, func(a, b kv) int { return strings.Compare(a.Key, b.Key) })
	return out
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}
