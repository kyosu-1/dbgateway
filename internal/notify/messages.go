package notify

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/kyosu-1/dbgateway/internal/events"
)

// catalog holds the message texts. English is the default; Japanese is
// selected with notifications_language: ja. Both maps must have the same
// keys (see TestCatalogParity).
var catalog = map[string]map[string]string{
	"ja": {
		"title.approval_requested": "承認依頼",
		"title.approval_decided":   "承認の状況",
		"title.execution_finished": "実行結果",
		"title.query_denied":       "クエリを拒否しました",
		"title.break_glass_used":   "緊急昇格が使われました",
		"title.anomaly_detected":   "異常を検知しました",
		"title.config_changed":     "設定が変わりました",
		"title.other":              "dbgateway の通知",

		"field.requester":     "申請者",
		"field.database":      "接続先",
		"field.tables":        "テーブル",
		"field.estimate":      "見積もり行数",
		"field.risk":          "リスク",
		"field.reason":        "理由",
		"field.status":        "状態",
		"field.sql":           "SQL（リテラルは伏せています）",
		"field.approvers":     "承認できる人",
		"field.actor":         "操作した人",
		"field.request":       "リクエスト",
		"field.rule":          "ルール",
		"field.stage":         "段階",
		"field.rows_affected": "影響行数",
		"field.databases":     "接続先",
		"field.expires_at":    "期限",
		"field.anomaly":       "内容",
		"field.version":       "設定のバージョン",
		"field.step":          "ステップ",

		"requester.agent": "%s · %s の代理",
		"button.open":     "承認画面を開く",
		"button.reject":   "却下",
		"confirm.title":   "却下の確認",
		"confirm.text":    "このリクエストを却下しますか？",
		"confirm.yes":     "却下する",
		"confirm.no":      "キャンセル",

		"status.pending":   "承認待ち",
		"status.approved":  "承認済み（実行待ち）",
		"status.running":   "実行中",
		"status.succeeded": "実行成功",
		"status.failed":    "実行失敗",
		"status.rejected":  "却下",
		"status.expired":   "期限切れ",
		"status.canceled":  "取り下げ",
		"status.deny":      "拒否",
		"status.by":        "%s（%s）",
		"status.step":      "%s（ステップ %s を %s が承認）",

		"risk.low":    "低",
		"risk.medium": "中",
		"risk.high":   "高",

		"exec.failed":     "実行に失敗しました。詳細は承認画面で確認してください。",
		"anomaly.denials": "10分間に %d 回拒否されました（しきい値 %d 回）",
		"anomaly.rows":    "1時間に %d 行を取得しました（しきい値 %d 行）",
		"config.changed":  "%s → %s",

		"reply.not_linked":     "あなたのSlackアカウントはdbgatewayのユーザーと紐づいていません。dbgatewayのアカウント画面でコードを発行し、`/dbgw link <コード>` を実行してください。",
		"reply.rejected":       "リクエスト %s を却下しました。",
		"reply.not_eligible":   "このリクエストを却下する権限がありません。",
		"reply.self":           "自分の申請は却下できません。取り下げは承認画面から行ってください。",
		"reply.not_pending":    "このリクエストはすでに処理済みです。",
		"reply.unavailable":    "承認機能が有効になっていません。",
		"reply.error":          "処理に失敗しました。時間をおいて再度試すか、承認画面を使ってください。",
		"reply.linked":         "dbgatewayのアカウント %s と紐づけました。",
		"reply.bad_code":       "コードが正しくないか、期限が切れています。アカウント画面で新しいコードを発行してください。",
		"reply.too_many":       "試行回数が多すぎます。しばらく待ってから再度試してください。",
		"reply.unlinked":       "dbgatewayのアカウント %s との紐づけを解除しました。",
		"reply.nothing_linked": "紐づいているdbgatewayのアカウントはありません。",
		"reply.whoami":         "紐づいているdbgatewayのアカウント: %s",
		"reply.help":           "使い方: `/dbgw link <コード>`（アカウント画面で発行したコードで紐づけ）、`/dbgw unlink`（解除）、`/dbgw whoami`（確認）",
	},
	"en": {
		"title.approval_requested": "Approval requested",
		"title.approval_decided":   "Approval update",
		"title.execution_finished": "Execution finished",
		"title.query_denied":       "Query denied",
		"title.break_glass_used":   "Break-glass elevation used",
		"title.anomaly_detected":   "Anomaly detected",
		"title.config_changed":     "Configuration changed",
		"title.other":              "dbgateway notification",

		"field.requester":     "Requester",
		"field.database":      "Database",
		"field.tables":        "Tables",
		"field.estimate":      "Estimated rows",
		"field.risk":          "Risk",
		"field.reason":        "Reason",
		"field.status":        "Status",
		"field.sql":           "SQL (literals hidden)",
		"field.approvers":     "Approvers",
		"field.actor":         "By",
		"field.request":       "Request",
		"field.rule":          "Rule",
		"field.stage":         "Stage",
		"field.rows_affected": "Rows affected",
		"field.databases":     "Databases",
		"field.expires_at":    "Expires",
		"field.anomaly":       "Details",
		"field.version":       "Config version",
		"field.step":          "Step",

		"requester.agent": "%s on behalf of %s",
		"button.open":     "Open approval page",
		"button.reject":   "Reject",
		"confirm.title":   "Reject request",
		"confirm.text":    "Reject this request?",
		"confirm.yes":     "Reject",
		"confirm.no":      "Cancel",

		"status.pending":   "Pending approval",
		"status.approved":  "Approved (waiting to run)",
		"status.running":   "Running",
		"status.succeeded": "Succeeded",
		"status.failed":    "Failed",
		"status.rejected":  "Rejected",
		"status.expired":   "Expired",
		"status.canceled":  "Canceled",
		"status.deny":      "Denied",
		"status.by":        "%s (%s)",
		"status.step":      "%s (step %s approved by %s)",

		"risk.low":    "low",
		"risk.medium": "medium",
		"risk.high":   "high",

		"exec.failed":     "The execution failed. See the approval page for details.",
		"anomaly.denials": "%d denials within 10 minutes (threshold %d)",
		"anomaly.rows":    "%d rows returned within an hour (threshold %d)",
		"config.changed":  "%s → %s",

		"reply.not_linked":     "Your Slack account is not linked to a dbgateway user. Issue a code on your dbgateway account page and run `/dbgw link <code>`.",
		"reply.rejected":       "Rejected request %s.",
		"reply.not_eligible":   "You are not allowed to reject this request.",
		"reply.self":           "You cannot reject your own request. Cancel it from the approval page instead.",
		"reply.not_pending":    "This request has already been decided.",
		"reply.unavailable":    "Approvals are not enabled.",
		"reply.error":          "Something went wrong. Try again later or use the approval page.",
		"reply.linked":         "Linked to the dbgateway account %s.",
		"reply.bad_code":       "The code is wrong or has expired. Issue a new one on your account page.",
		"reply.too_many":       "Too many attempts. Wait a while and try again.",
		"reply.unlinked":       "Unlinked from the dbgateway account %s.",
		"reply.nothing_linked": "No dbgateway account is linked.",
		"reply.whoami":         "Linked dbgateway account: %s",
		"reply.help":           "Usage: `/dbgw link <code>` (link with the code from your account page), `/dbgw unlink`, `/dbgw whoami`",
	},
}

// msgs renders texts in one language.
type msgs struct{ m map[string]string }

func newMsgs(lang string) msgs {
	if m, ok := catalog[lang]; ok {
		return msgs{m}
	}
	return msgs{catalog["en"]}
}

func (m msgs) t(key string, args ...any) string {
	s, ok := m.m[key]
	if !ok {
		s = catalog["en"][key]
	}
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}

// title is the heading of an event.
func (m msgs) title(t events.Type) string {
	if s, ok := m.m["title."+string(t)]; ok {
		return s
	}
	return m.t("title.other")
}

// status is the localized status, with the actor when known.
func (m msgs) status(e events.Event) string {
	s, ok := m.m["status."+e.Status]
	if !ok {
		s = e.Status
	}
	if e.Actor == "" || e.Actor == "dbgateway" {
		return s
	}
	if e.Status == "pending" && e.Detail["step"] != "" {
		step, err := strconv.Atoi(e.Detail["step"])
		if err == nil {
			return m.t("status.step", s, strconv.Itoa(step+1), e.Actor)
		}
	}
	return m.t("status.by", s, e.Actor)
}

func (m msgs) risk(r string) string {
	if s, ok := m.m["risk."+r]; ok {
		return s
	}
	return r
}

// requester renders the requester: the human, or "agent on behalf of human".
func (m msgs) requester(p *events.Principal) string {
	if p == nil {
		return ""
	}
	if p.Agent != "" {
		return m.t("requester.agent", p.Agent, p.Human)
	}
	if p.Human != "" {
		return p.Human
	}
	return p.ClientID
}

// anomaly describes an anomaly_detected event.
func (m msgs) anomaly(e events.Event) string {
	count, _ := strconv.ParseInt(e.Detail["count"], 10, 64)
	threshold, _ := strconv.ParseInt(e.Detail["threshold"], 10, 64)
	switch e.Detail["anomaly"] {
	case AnomalyDenials:
		return m.t("anomaly.denials", count, threshold)
	case AnomalyRows:
		return m.t("anomaly.rows", count, threshold)
	}
	return e.Detail["anomaly"]
}

// summary is a one-line plain description of an event (Slack fallback
// text and the webhook "text" field). It never contains SQL.
func (m msgs) summary(e events.Event) string {
	parts := []string{m.title(e.Type)}
	if e.Database != "" {
		parts = append(parts, e.Database)
	}
	if r := m.requester(e.Principal); r != "" {
		parts = append(parts, r)
	}
	if e.Status != "" {
		parts = append(parts, m.status(e))
	}
	return strings.Join(parts, " · ")
}

// allowedDetail lists the Detail keys that may leave dbgateway. Others
// ("error", "message", ...) can carry database error texts or parser
// messages that quote literal values, so they are never sent.
var allowedDetail = map[string]bool{
	"risk": true, "approval_rule": true, "max_affected_rows": true, "step": true, "rows_affected": true,
	"stage": true, "rule": true, "databases": true, "expires_at": true,
	"anomaly": true, "count": true, "threshold": true, "window": true,
	"previous_version": true, "version": true,
}

// sanitize returns a copy of e safe to send: only allowed Detail keys
// (the status still tells that an execution failed).
func sanitize(e events.Event) events.Event {
	out := e
	out.Detail = nil
	for k, v := range e.Detail {
		if allowedDetail[k] {
			if out.Detail == nil {
				out.Detail = map[string]string{}
			}
			out.Detail[k] = v
		}
	}
	if out.Labels != nil {
		labels := make(map[string]string, len(out.Labels))
		for k, v := range out.Labels {
			labels[k] = v
		}
		out.Labels = labels
	}
	return out
}
