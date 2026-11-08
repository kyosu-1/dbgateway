package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
	"github.com/kyosu-1/dbgateway/internal/web/ui"
)

// The SQL editor (/console) is how people run SQL (the same approach as
// Bytebase: there is no wire-protocol proxy for desktop clients). It is a
// plain form that works without JavaScript; /static/editor.js adds the
// CodeMirror editor, completion, tabs and sorting on top.

const (
	// maxConsoleSQL bounds the statement accepted by the editor.
	maxConsoleSQL = 32 << 10
	// maxSavedName bounds the name of a saved query (in characters).
	maxSavedName = 100
	// consoleHistoryShown is the number of history entries listed.
	consoleHistoryShown = 100
	// schemaListLimit is the number of tables listed (and offered for
	// completion) when nothing is searched.
	schemaListLimit = 200
)

// consolePrincipal is the viewer acting through the editor. It is the
// same human principal (no extra rights); the client ID marks the channel
// in the audit log and in approval requests.
func consolePrincipal(p *identity.Principal) *identity.Principal {
	c := *p
	c.ClientID, c.ClientName = ConsoleClientID, "dbgw web console"
	return &c
}

// consoleForm is the editor input.
type consoleForm struct {
	DB, SQL, Reason, Search string
	// RunSQL is the selected part of SQL to run instead of the whole.
	RunSQL string
	// Panel is the side panel shown: schema (default), history or saved.
	Panel string
	// SaveName is the name given when saving the query.
	SaveName string
}

// executed is the statement that runs: the selection when there is one.
func (f consoleForm) executed() string {
	if strings.TrimSpace(f.RunSQL) != "" {
		return f.RunSQL
	}
	return f.SQL
}

// consoleResult is what the editor shows below the input.
type consoleResult struct {
	Exec    *gateway.ExecuteResponse
	Explain *gateway.ExplainResponse
	Table   *tableView
	// SQL is the statement that produced Exec (exported again as is).
	SQL string
	// DurationText is the time the statement took ("14ms", "1.2s").
	DurationText string
	// Error is a message key for input problems.
	Error string
	// ExplainError is a gateway error text (e.g. no access).
	ExplainError string
	// Saved is set after the query was saved.
	Saved bool
}

// handleConsole shows the editor. ?history=<id> and ?saved=<id> open a
// statement from the viewer's history or saved queries.
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
	f := consoleForm{DB: q.Get("db"), Search: q.Get("q"), Panel: q.Get("panel")}
	open := consoleOpen{}
	ctx := r.Context()
	if id := q.Get("history"); id != "" {
		h, err := a.st.GetConsoleHistory(ctx, v.ws.Email, id, a.now())
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			a.serverError(w, r, v.ws.Email, err)
			return
		}
		if h != nil {
			f.DB, f.SQL, f.Reason, open.Kind = h.Database, h.SQL, h.Reason, "history"
		}
		f.Panel = "history"
	} else if id := q.Get("saved"); id != "" {
		s, err := a.st.GetSavedQuery(ctx, v.ws.Email, id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			a.serverError(w, r, v.ws.Email, err)
			return
		}
		if s != nil {
			f.DB, f.SQL, open.Kind, open.Name = s.Database, s.SQL, "saved", s.Name
		}
		f.Panel = "saved"
	}
	a.renderConsole(w, r, v, http.StatusOK, dbs, f, nil, open)
}

// consoleOpen describes a statement opened from history or saved queries
// (the editor puts it in a new tab).
type consoleOpen struct {
	Kind string // history | saved
	Name string
}

func (a *App) renderConsole(w http.ResponseWriter, r *http.Request, v *viewer, status int, dbs []gateway.DatabaseInfo, f consoleForm, res *consoleResult, open consoleOpen) {
	sel := slices.IndexFunc(dbs, func(d gateway.DatabaseInfo) bool { return d.Name == f.DB })
	if sel < 0 {
		sel = 0
	}
	db := dbs[sel]
	switch f.Panel {
	case "history", "saved":
	default:
		f.Panel = "schema"
	}
	ctx := r.Context()
	data := map[string]any{
		"Databases": dbs, "DB": db, "Form": f, "Result": res, "Open": open,
		"MaxRows": db.MaxRows, "Timeout": a.cfg.Database(db.Name).Limits.StatementTimeout.D(),
		"CanWrite": db.CanWrite, "IsAuditor": a.isAuditor(v.p),
		"HistoryEnabled": a.cfg.Console.HistoryEnabled(), "HistoryDays": int(a.cfg.Console.HistoryTTL().Hours() / 24),
		"ExportEnabled": a.cfg.Console.ExportEnabled(), "ExportMaxRows": groupDigits(a.cfg.Console.ExportRows()),
		"StorageKey": storageKey(v.ws.Email), "Posted": res != nil,
		"Text": consoleText(a, r),
	}
	// Schema browser and completion (catalog only). The plain table list
	// is part of the page and is not audited; a search typed into the box
	// is.
	if db.CanSearch {
		keyword := strings.TrimSpace(f.Search)
		limit := 100
		if keyword == "" {
			limit = schemaListLimit
		}
		sr, err := a.gw.SearchObjects(ctx, v.p, gateway.SearchRequest{Database: db.Name, Keyword: keyword,
			Detail: "summary", Limit: limit, Browse: keyword == ""})
		if err != nil {
			data["SchemaError"] = true
		} else {
			data["Objects"] = sr.Objects
			data["ObjectsTruncated"] = sr.Truncated
			data["Schema"] = completionSchema(db.Type, sr)
		}
	}
	saved, err := a.st.ListSavedQueries(ctx, v.ws.Email)
	if err != nil {
		a.log.Error("list saved queries", "err", err)
	}
	data["Saved"] = saved
	if f.Panel == "history" && a.cfg.Console.HistoryEnabled() {
		hist, err := a.st.ListConsoleHistory(ctx, v.ws.Email, consoleHistoryShown, a.now())
		if err != nil {
			a.log.Error("list console history", "err", err)
		}
		views := make([]historyView, len(hist))
		for i, h := range hist {
			views[i] = historyView{ConsoleHistory: h, Pill: historyPill(h.Status)}
		}
		data["History"] = views
	}
	if res != nil && res.Explain != nil {
		data["ExplainPill"] = decisionPill(res.Explain.Decision)
		var masked []string
		for _, o := range res.Explain.Output {
			if o.Masked || o.Withheld {
				masked = append(masked, o.Name)
			}
		}
		data["MaskedOutputs"] = masked
	}
	if res != nil && res.Exec != nil && res.Exec.Status == gateway.StatusPending {
		data["PendingURL"] = "/approvals/" + url.PathEscape(res.Exec.RequestID)
	}
	a.render(w, r, v, status, "console", "title.console", "console", ui.WidthFull, data, ui.Asset("/static/editor.js"))
}

// consoleText holds the strings the editor script shows, in the viewer's
// language.
func consoleText(a *App, r *http.Request) map[string]string {
	t := a.ui.Printer(r).T
	return map[string]string{
		"tab": t("console.tab_default"), "newTab": t("console.tab_new"), "close": t("console.tab_close"),
		"rename": t("console.tab_rename"), "masked": t("console.class_masked"), "noAI": t("console.class_no_ai"),
	}
}

// storageKey names the viewer's drafts in browser storage without putting
// the e-mail address there.
func storageKey(email string) string {
	sum := sha256.Sum256([]byte("dbgw-console:" + strings.ToLower(email)))
	return hex.EncodeToString(sum[:8])
}

// completionSchema is the schema offered for completion: the tables and
// columns the viewer may see, with their data class.
func completionSchema(dbType string, sr *gateway.SearchResponse) map[string]any {
	type col struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		Class string `json:"class,omitempty"`
	}
	tables := map[string][]col{}
	for _, o := range sr.Objects {
		name := o.Name
		if o.Schema != "" && o.Schema != "public" {
			name = o.Schema + "." + o.Name
		}
		cols := make([]col, 0, len(o.Columns))
		for _, c := range o.Columns {
			class := c.Class
			if c.Masked && class == "" {
				class = config.ClassMasked
			}
			cols = append(cols, col{Name: c.Name, Type: c.Type, Class: class})
		}
		tables[name] = cols
	}
	dialect := "postgres"
	if dbType == "mysql" {
		dialect = "mysql"
	}
	return map[string]any{"dialect": dialect, "tables": tables}
}

// handleConsoleRun runs, explains, saves or exports the statement.
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
	f := consoleForm{DB: r.PostFormValue("db"), SQL: r.PostFormValue("sql"), RunSQL: r.PostFormValue("run_sql"),
		Reason: strings.TrimSpace(r.PostFormValue("reason")), Panel: r.PostFormValue("panel"),
		SaveName: strings.TrimSpace(r.PostFormValue("save_name"))}
	action := r.PostFormValue("action")
	res := &consoleResult{}
	// Never trust the submitted database: it must be one the viewer may
	// read (the gateway checks again).
	if !slices.ContainsFunc(dbs, func(d gateway.DatabaseInfo) bool { return d.Name == f.DB }) {
		res.Error = "console.error_database"
		a.renderConsole(w, r, v, http.StatusForbidden, dbs, f, res, consoleOpen{})
		return
	}
	sqlText := f.executed()
	switch {
	case strings.TrimSpace(sqlText) == "":
		res.Error = "console.error_sql"
	case len(f.SQL) > maxConsoleSQL || len(f.RunSQL) > maxConsoleSQL || !utf8.ValidString(f.SQL) || !utf8.ValidString(f.RunSQL):
		res.Error = "console.error_sql_long"
	}
	if res.Error != "" {
		a.renderConsole(w, r, v, http.StatusBadRequest, dbs, f, res, consoleOpen{})
		return
	}
	ctx := r.Context()
	switch action {
	case "explain":
		ex, err := a.gw.ExplainPolicy(ctx, consolePrincipal(v.p), gateway.ExplainRequest{Database: f.DB, SQL: sqlText})
		if err != nil {
			res.ExplainError = err.Error()
		} else {
			res.Explain = ex
		}
		a.renderConsole(w, r, v, http.StatusOK, dbs, f, res, consoleOpen{})
		return
	case "save":
		a.consoleSave(w, r, v, dbs, f, res)
		return
	case "export":
		a.consoleExport(w, r, v, dbs, f, res)
		return
	}
	if f.Reason == "" {
		res.Error = "console.error_reason"
		a.renderConsole(w, r, v, http.StatusBadRequest, dbs, f, res, consoleOpen{})
		return
	}
	start := time.Now()
	resp := a.gw.ExecuteSQL(ctx, consolePrincipal(v.p), gateway.ExecuteRequest{Database: f.DB, SQL: sqlText, Reason: f.Reason})
	res.Exec, res.SQL, res.DurationText = resp, sqlText, shortDuration(time.Since(start))
	if resp.Status == gateway.StatusOK && len(resp.Columns) > 0 {
		res.Table = newTableView(resp.Columns, resp.Rows)
	}
	a.recordHistory(r, v, f, resp, sqlText)
	resp.Reason, resp.Hint = ui.InertText(resp.Reason), ui.InertText(resp.Hint)
	a.renderConsole(w, r, v, http.StatusOK, dbs, f, res, consoleOpen{})
}

// recordHistory keeps the statement in the viewer's history. A failure
// only loses the history entry; the statement already ran and is audited.
func (a *App) recordHistory(r *http.Request, v *viewer, f consoleForm, resp *gateway.ExecuteResponse, sqlText string) {
	if !a.cfg.Console.HistoryEnabled() {
		return
	}
	now := a.now()
	h := &store.ConsoleHistory{ID: "h_" + rand.Text(), Email: v.ws.Email, Database: f.DB, SQL: sqlText, Reason: f.Reason,
		Status: resp.Status, RequestID: resp.RequestID, CreatedAt: now, ExpiresAt: now.Add(a.cfg.Console.HistoryTTL())}
	switch {
	case resp.RowsAffected != nil:
		h.RowCount = resp.RowsAffected
	case resp.Status == gateway.StatusOK:
		n := int64(resp.RowCount)
		h.RowCount = &n
	}
	if err := a.st.AddConsoleHistory(r.Context(), h); err != nil {
		a.log.Error("record console history", "err", err, "request_id", resp.RequestID)
	}
}

// consoleSave stores the editor's statement as a saved query.
func (a *App) consoleSave(w http.ResponseWriter, r *http.Request, v *viewer, dbs []gateway.DatabaseInfo, f consoleForm, res *consoleResult) {
	switch {
	case f.SaveName == "":
		res.Error = "console.error_save_name"
	case utf8.RuneCountInString(f.SaveName) > maxSavedName || !utf8.ValidString(f.SaveName):
		res.Error = "console.error_save_name_long"
	}
	if res.Error != "" {
		a.renderConsole(w, r, v, http.StatusBadRequest, dbs, f, res, consoleOpen{})
		return
	}
	now := a.now()
	err := a.st.CreateSavedQuery(r.Context(), &store.SavedQuery{ID: "sq_" + rand.Text(), Email: v.ws.Email, Name: f.SaveName,
		Database: f.DB, SQL: f.SQL, CreatedAt: now, UpdatedAt: now})
	switch {
	case errors.Is(err, store.ErrLimit):
		res.Error = "console.error_save_limit"
		a.renderConsole(w, r, v, http.StatusConflict, dbs, f, res, consoleOpen{})
		return
	case err != nil:
		a.serverError(w, r, v.ws.Email, err)
		return
	}
	res.Saved = true
	f.Panel, f.SaveName = "saved", ""
	a.renderConsole(w, r, v, http.StatusOK, dbs, f, res, consoleOpen{})
}

// handleSavedDelete removes one of the viewer's saved queries.
func (a *App) handleSavedDelete(w http.ResponseWriter, r *http.Request) {
	v, ok := a.post(w, r)
	if !ok {
		return
	}
	err := a.st.DeleteSavedQuery(r.Context(), v.ws.Email, r.PathValue("id"))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		a.serverError(w, r, v.ws.Email, err)
		return
	}
	http.Redirect(w, r, "/console?panel=saved&db="+url.QueryEscape(r.PostFormValue("db")), http.StatusSeeOther)
}

// historyView is a history entry with its status pill.
type historyView struct {
	*store.ConsoleHistory
	Pill pill
}

func historyPill(status string) pill {
	switch status {
	case gateway.StatusOK:
		return pill{"decision.allow", "success"}
	case gateway.StatusPending:
		return pill{"status.pending", "accent"}
	case gateway.StatusDenied:
		return pill{"decision.deny", "danger"}
	}
	return pill{"decision.error", "danger"}
}

// shortDuration formats an execution time for the result header.
func shortDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// groupDigits formats n with thousands separators ("10,000").
func groupDigits(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0 && s[i-1] != '-'; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
