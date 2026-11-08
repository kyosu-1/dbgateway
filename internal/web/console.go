package web

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/web/ui"
)

// maxConsoleSQL bounds the statement accepted by the console.
const maxConsoleSQL = 32 << 10

// consolePrincipal is the viewer acting through the console. It is the
// same human principal (no extra rights); the client ID marks the channel
// in the audit log and in approval requests.
func consolePrincipal(p *identity.Principal) *identity.Principal {
	c := *p
	c.ClientID, c.ClientName = ConsoleClientID, "dbgw web console"
	return &c
}

// handleConsole shows the SQL console.
func (a *App) handleConsole(w http.ResponseWriter, r *http.Request) {
	v, ok := a.viewer(w, r)
	if !ok {
		return
	}
	dbs := a.readableDatabases(v.p)
	if len(dbs) == 0 {
		a.forbidden(w, r, v, "console.no_databases")
		return
	}
	q := r.URL.Query()
	a.renderConsole(w, r, v, http.StatusOK, dbs, consoleForm{DB: q.Get("db"), Search: q.Get("q")}, nil)
}

// consoleForm is the console input.
type consoleForm struct {
	DB, SQL, Reason, Search string
}

// consoleResult is what the console shows below the editor.
type consoleResult struct {
	Exec    *gateway.ExecuteResponse
	Explain *gateway.ExplainResponse
	Table   *tableView
	// Error is a message key for input problems.
	Error string
	// ExplainError is a gateway error text (e.g. no access).
	ExplainError string
}

func (a *App) renderConsole(w http.ResponseWriter, r *http.Request, v *viewer, status int, dbs []gateway.DatabaseInfo, f consoleForm, res *consoleResult) {
	sel := slices.IndexFunc(dbs, func(d gateway.DatabaseInfo) bool { return d.Name == f.DB })
	if sel < 0 {
		sel = 0
	}
	db := dbs[sel]
	data := map[string]any{
		"Databases": dbs, "DB": db, "Form": f, "Result": res,
		"MaxRows": db.MaxRows, "Timeout": a.cfg.Database(db.Name).Limits.StatementTimeout.D(),
		"CanWrite": db.CanWrite, "IsAuditor": a.isAuditor(v.p),
	}
	// Schema browser (catalog only). The plain table list is part of the
	// page and is not audited; a search typed into the box is.
	if db.CanSearch {
		keyword := strings.TrimSpace(f.Search)
		sr, err := a.gw.SearchObjects(r.Context(), v.p, gateway.SearchRequest{Database: db.Name, Keyword: keyword,
			Detail: "summary", Limit: 100, Browse: keyword == ""})
		if err != nil {
			data["SchemaError"] = true
		} else {
			data["Objects"] = sr.Objects
			data["ObjectsTruncated"] = sr.Truncated
		}
	}
	if res != nil && res.Explain != nil {
		data["ExplainPill"] = decisionPill(res.Explain.Decision)
	}
	if res != nil && res.Exec != nil && res.Exec.Status == gateway.StatusPending {
		data["PendingURL"] = "/approvals/" + url.PathEscape(res.Exec.RequestID)
	}
	a.render(w, r, v, status, "console", "title.console", "console", ui.WidthFull, data)
}

// handleConsoleRun runs or explains a statement.
func (a *App) handleConsoleRun(w http.ResponseWriter, r *http.Request) {
	v, ok := a.post(w, r)
	if !ok {
		return
	}
	dbs := a.readableDatabases(v.p)
	if len(dbs) == 0 {
		a.forbidden(w, r, v, "console.no_databases")
		return
	}
	f := consoleForm{DB: r.PostFormValue("db"), SQL: r.PostFormValue("sql"), Reason: strings.TrimSpace(r.PostFormValue("reason"))}
	res := &consoleResult{}
	// Never trust the submitted database: it must be one the viewer may
	// read (the gateway checks again).
	if !slices.ContainsFunc(dbs, func(d gateway.DatabaseInfo) bool { return d.Name == f.DB }) {
		res.Error = "console.error_database"
		a.renderConsole(w, r, v, http.StatusForbidden, dbs, f, res)
		return
	}
	switch {
	case strings.TrimSpace(f.SQL) == "":
		res.Error = "console.error_sql"
	case len(f.SQL) > maxConsoleSQL || !utf8.ValidString(f.SQL):
		res.Error = "console.error_sql_long"
	}
	if res.Error != "" {
		a.renderConsole(w, r, v, http.StatusBadRequest, dbs, f, res)
		return
	}
	ctx := r.Context()
	if r.PostFormValue("action") == "explain" {
		ex, err := a.gw.ExplainPolicy(ctx, consolePrincipal(v.p), gateway.ExplainRequest{Database: f.DB, SQL: f.SQL})
		if err != nil {
			res.ExplainError = err.Error()
		} else {
			res.Explain = ex
		}
		a.renderConsole(w, r, v, http.StatusOK, dbs, f, res)
		return
	}
	if f.Reason == "" {
		res.Error = "console.error_reason"
		a.renderConsole(w, r, v, http.StatusBadRequest, dbs, f, res)
		return
	}
	resp := a.gw.ExecuteSQL(ctx, consolePrincipal(v.p), gateway.ExecuteRequest{Database: f.DB, SQL: f.SQL, Reason: f.Reason})
	res.Exec = resp
	if resp.Status == gateway.StatusOK && len(resp.Columns) > 0 {
		res.Table = newTableView(resp.Columns, resp.Rows)
	}
	resp.Reason, resp.Hint = ui.InertText(resp.Reason), ui.InertText(resp.Hint)
	a.renderConsole(w, r, v, http.StatusOK, dbs, f, res)
}
