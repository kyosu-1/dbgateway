package web

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/auth"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/web/i18n"
	"github.com/kyosu-1/dbgateway/internal/web/ui"
)

// pill is a status label: a message key and a tone (CSS modifier).
type pill struct {
	Key  string
	Tone string // accent | success | danger | warning | "" (neutral)
}

func riskPill(risk string) pill {
	switch risk {
	case "high":
		return pill{"risk.high", "warning"}
	case "medium":
		return pill{"risk.medium", ""}
	}
	return pill{"risk.low", "success"}
}

func riskLongPill(risk string) pill {
	p := riskPill(risk)
	p.Key += "_long"
	return p
}

func statusPill(s approval.Status) pill {
	switch s {
	case approval.StatusPending:
		return pill{"status.pending", "accent"}
	case approval.StatusApproved:
		return pill{"status.approved", "accent"}
	case approval.StatusRunning:
		return pill{"status.running", "accent"}
	case approval.StatusSucceeded:
		return pill{"status.succeeded", "success"}
	case approval.StatusFailed:
		return pill{"status.failed", "danger"}
	case approval.StatusRejected:
		return pill{"status.rejected", "danger"}
	case approval.StatusExpired:
		return pill{"status.expired", ""}
	case approval.StatusCanceled:
		return pill{"status.canceled", ""}
	}
	return pill{string(s), ""}
}

func decisionPill(d string) pill {
	switch d {
	case "allow":
		return pill{"decision.allow", "success"}
	case "approve":
		return pill{"decision.approve", "accent"}
	case "deny":
		return pill{"decision.deny", "danger"}
	case "error":
		return pill{"decision.error", "danger"}
	}
	return pill{"decision.other", ""}
}

// shortTable drops the default schema ("public.users" → "users").
func shortTable(t string) string { return strings.TrimPrefix(t, "public.") }

func tableList(p *i18n.Printer, tables []string) string {
	if len(tables) == 0 {
		return p.T("req.table_unknown")
	}
	short := make([]string, len(tables))
	for i, t := range tables {
		short[i] = shortTable(t)
	}
	return strings.Join(short, p.T("list.separator"))
}

// rowsPhrase is "1行" / "3 rows"; empty when the count is unknown.
func rowsPhrase(p *i18n.Printer, rows float64) string {
	n := int64(math.Ceil(rows))
	switch {
	case n <= 0:
		return ""
	case n == 1:
		return p.T("rows.one", n)
	}
	return p.T("rows.other", n)
}

// requestTitle summarizes a write: "subscriptions の1行を更新".
func requestTitle(p *i18n.Printer, kind string, tables []string, estimate float64) string {
	switch kind {
	case "update", "delete", "insert", "merge":
	case "truncate":
		return p.T("req.title.truncate", tableList(p, tables))
	default:
		return p.T("req.title.other", tableList(p, tables))
	}
	rows := rowsPhrase(p, estimate)
	if rows == "" {
		return p.T("req.title."+kind+".nocount", tableList(p, tables))
	}
	return p.T("req.title."+kind, tableList(p, tables), rows)
}

// requesterLabel is "claude-code · taro@example.com の代理", "SQLコンソール ·
// kenji@example.com" or the e-mail.
func requesterLabel(p *i18n.Printer, req approval.Requester) string {
	switch {
	case req.Kind == identity.KindAgent:
		return p.T("req.by_agent", req.Agent, req.Human)
	case req.ClientID == ConsoleClientID:
		return p.T("req.by_console", req.Human)
	case req.ClientID == auth.CLIClientID:
		return p.T("req.by_cli", req.Human)
	}
	return req.Human
}

// sourceLabel is the requester's channel for the requester's own list:
// the agent name, "SQLコンソール", "dbgw CLI" or "".
func sourceLabel(p *i18n.Printer, req approval.Requester) string {
	switch {
	case req.Kind == identity.KindAgent:
		return req.Agent
	case req.ClientID == ConsoleClientID:
		return p.T("req.source_console")
	case req.ClientID == auth.CLIClientID:
		return p.T("req.source_cli")
	}
	return ""
}

// timeLeft is "残り 1時間36分" for a pending request.
func timeLeft(p *i18n.Printer, expires, now time.Time) string {
	d := expires.Sub(now)
	if d <= 0 {
		return p.T("approvals.overdue")
	}
	if d < time.Minute {
		d = time.Minute
	}
	return p.T("approvals.left", p.Duration(d))
}

// cell is one formatted result value.
type cell struct {
	Text   string
	Null   bool
	Masked bool
}

// tableView is a result set prepared for display.
type tableView struct {
	Columns []gateway.ResultColumn
	Rows    [][]cell
}

func newTableView(cols []gateway.ResultColumn, rows [][]any) *tableView {
	t := &tableView{Columns: cols}
	for _, row := range rows {
		cells := make([]cell, len(row))
		for i, v := range row {
			cells[i] = formatValue(v)
			cells[i].Masked = i < len(cols) && (cols[i].Masked || cols[i].Withheld)
		}
		t.Rows = append(t.Rows, cells)
	}
	return t
}

// formatValue renders a result value as inert text.
func formatValue(v any) cell {
	var s string
	switch x := v.(type) {
	case nil:
		return cell{Text: "NULL", Null: true}
	case string:
		s = x
	case []byte:
		if utf8.Valid(x) {
			s = string(x)
		} else {
			s = fmt.Sprintf("\\x%x", x)
		}
	case time.Time:
		s = x.Format("2006-01-02 15:04:05.999999Z07:00")
	case fmt.Stringer:
		s = x.String()
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		s = fmt.Sprint(x)
	default:
		b, err := json.Marshal(x)
		if err != nil {
			s = fmt.Sprint(x)
		} else {
			s = string(b)
		}
	}
	const maxCell = 2000
	if utf8.RuneCountInString(s) > maxCell {
		s = string([]rune(s)[:maxCell]) + "…"
	}
	return cell{Text: ui.InertText(s)}
}

// stepLabel describes an approval step: "approver ロールの1人".
func stepLabel(p *i18n.Printer, st approval.Step) string {
	if st.Group != "" {
		return p.T("step.group", st.Group, st.Count)
	}
	return p.T("step.role", string(st.Role), st.Count)
}

func stepUpMethodKey(m string) string {
	switch m {
	case auth.StepUpPasskey, auth.StepUpIdP, auth.StepUpDev:
		return "stepup.method." + m
	}
	return "stepup.method.other"
}
