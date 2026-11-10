package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	dbgatewayv1 "github.com/kyosu-1/dbgateway/gen/dbgateway/v1"
	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

func executeResponse(r *gateway.ExecuteResponse) *dbgatewayv1.ExecuteSQLResponse {
	out := &dbgatewayv1.ExecuteSQLResponse{
		Status:          executeStatus(r.Status),
		RequestId:       r.RequestID,
		Columns:         resultColumns(r.Columns),
		Rows:            rows(r.Rows),
		RowCount:        int64(r.RowCount),
		TotalRows:       r.TotalRows,
		Truncated:       r.Truncated,
		Notice:          r.Notice,
		RowsAffected:    r.RowsAffected,
		BreakGlass:      r.BreakGlass,
		Backup:          backup(r.Backup),
		Stage:           r.Stage,
		Rule:            r.Rule,
		Reason:          r.Reason,
		Hint:            r.Hint,
		Code:            r.Code,
		Approvers:       r.Approvers,
		ApprovalUrl:     r.ApprovalURL,
		Risk:            r.Risk,
		ApprovalRule:    r.ApprovalRule,
		MaxAffectedRows: r.MaxAffectedRows,
	}
	if r.ExpiresAt != nil {
		out.ExpireTime = timestamppb.New(*r.ExpiresAt)
	}
	return out
}

// executeStatus maps a gateway status. Anything unknown is reported as an
// error, never as success.
func executeStatus(s string) dbgatewayv1.ExecuteStatus {
	switch s {
	case gateway.StatusOK:
		return dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_OK
	case gateway.StatusDenied:
		return dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_DENIED
	case gateway.StatusPending:
		return dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_PENDING
	}
	return dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_ERROR
}

func resultColumns(cols []gateway.ResultColumn) []*dbgatewayv1.ResultColumn {
	var out []*dbgatewayv1.ResultColumn
	for _, c := range cols {
		out = append(out, &dbgatewayv1.ResultColumn{Name: c.Name, Type: c.Type, Masked: c.Masked, Withheld: c.Withheld, Class: c.Class})
	}
	return out
}

func rows(rs [][]any) []*dbgatewayv1.Row {
	var out []*dbgatewayv1.Row
	for _, r := range rs {
		row := &dbgatewayv1.Row{Values: make([]*structpb.Value, len(r))}
		for i, v := range r {
			row.Values[i] = value(v)
		}
		out = append(out, row)
	}
	return out
}

// maxExactInt is the largest integer magnitude a double represents exactly.
const maxExactInt = 1 << 53

func intValue(n int64) *structpb.Value {
	if n > maxExactInt || n < -maxExactInt {
		return structpb.NewStringValue(strconv.FormatInt(n, 10))
	}
	return structpb.NewNumberValue(float64(n))
}

func uintValue(n uint64) *structpb.Value {
	if n > maxExactInt {
		return structpb.NewStringValue(strconv.FormatUint(n, 10))
	}
	return structpb.NewNumberValue(float64(n))
}

// value converts a result value (already JSON-friendly, see
// analysis.Result) into a protobuf Value without losing precision:
// integers beyond ±2^53 and non-finite floats become strings.
func value(v any) *structpb.Value {
	switch x := v.(type) {
	case nil:
		return structpb.NewNullValue()
	case bool:
		return structpb.NewBoolValue(x)
	case string:
		return structpb.NewStringValue(x)
	case int:
		return intValue(int64(x))
	case int8:
		return intValue(int64(x))
	case int16:
		return intValue(int64(x))
	case int32:
		return intValue(int64(x))
	case int64:
		return intValue(x)
	case uint:
		return uintValue(uint64(x))
	case uint8:
		return uintValue(uint64(x))
	case uint16:
		return uintValue(uint64(x))
	case uint32:
		return uintValue(uint64(x))
	case uint64:
		return uintValue(x)
	case float32:
		return floatValue(float64(x))
	case float64:
		return floatValue(x)
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return intValue(n)
		}
		if f, err := x.Float64(); err == nil {
			return floatValue(f)
		}
		return structpb.NewStringValue(x.String())
	case []any:
		l := &structpb.ListValue{Values: make([]*structpb.Value, len(x))}
		for i, e := range x {
			l.Values[i] = value(e)
		}
		return structpb.NewListValue(l)
	case map[string]any:
		st := &structpb.Struct{Fields: make(map[string]*structpb.Value, len(x))}
		for k, e := range x {
			st.Fields[k] = value(e)
		}
		return structpb.NewStructValue(st)
	case time.Time:
		return structpb.NewStringValue(x.Format(time.RFC3339Nano))
	}
	// Anything else: its JSON form, decoded generically (decoding yields
	// only the types above, so this recursion terminates).
	if b, err := json.Marshal(v); err == nil {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		var generic any
		if err := dec.Decode(&generic); err == nil && generic != nil {
			return value(generic)
		}
	}
	return structpb.NewStringValue(fmt.Sprint(v))
}

func floatValue(f float64) *structpb.Value {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return structpb.NewStringValue(strconv.FormatFloat(f, 'g', -1, 64))
	}
	return structpb.NewNumberValue(f)
}

func explainResponse(r *gateway.ExplainResponse) *dbgatewayv1.ExplainPolicyResponse {
	out := &dbgatewayv1.ExplainPolicyResponse{
		RequestId:              r.RequestID,
		Database:               r.Database,
		Decision:               policyDecision(r.Decision),
		Stage:                  r.Stage,
		Rule:                   r.Rule,
		Reason:                 r.Reason,
		Hint:                   r.Hint,
		ShadowDeniedBy:         r.ShadowDeniedBy,
		Risk:                   r.Risk,
		ApprovalRule:           r.ApprovalRule,
		ApprovalSteps:          approvalSteps(r.ApprovalSteps),
		ExpireAfter:            expireAfter(r.ExpireAfter),
		Approvers:              r.Approvers,
		MaxAffectedRows:        r.MaxAffectedRows,
		BreakGlass:             r.BreakGlass,
		RequiresSpecificReason: r.RequiresReason,
	}
	if r.Statement != nil {
		out.Statement = &dbgatewayv1.Statement{Kind: r.Statement.Kind, IsWrite: r.Statement.IsWrite, Tables: r.Statement.Tables}
	}
	if r.Estimate != nil {
		out.Estimate = &dbgatewayv1.Estimate{Rows: r.Estimate.Rows, Cost: r.Estimate.Cost}
	}
	for _, c := range r.Columns {
		out.Columns = append(out.Columns, &dbgatewayv1.ReferencedColumn{Name: c.Name, Class: c.Class, Usage: c.Usage})
	}
	for _, o := range r.Output {
		out.Output = append(out.Output, &dbgatewayv1.OutputColumn{Name: o.Name, Class: o.Class, Masked: o.Masked, Withheld: o.Withheld})
	}
	return out
}

// policyDecision maps a decision. Anything unknown is reported as deny.
func policyDecision(d string) dbgatewayv1.PolicyDecision {
	switch d {
	case config.ActionAllow:
		return dbgatewayv1.PolicyDecision_POLICY_DECISION_ALLOW
	case config.ActionApprove:
		return dbgatewayv1.PolicyDecision_POLICY_DECISION_APPROVE
	}
	return dbgatewayv1.PolicyDecision_POLICY_DECISION_DENY
}

func approvalSteps(steps []config.ApprovalStep) []*dbgatewayv1.ApprovalStep {
	var out []*dbgatewayv1.ApprovalStep
	for _, s := range steps {
		out = append(out, &dbgatewayv1.ApprovalStep{Role: string(s.Role), Group: s.Group, Count: int32(s.Count)})
	}
	return out
}

func approvalRequest(r *approval.Request) *dbgatewayv1.ApprovalRequest {
	out := &dbgatewayv1.ApprovalRequest{
		Id:              r.ID,
		Status:          approvalStatus(r.Status),
		Requester:       &dbgatewayv1.Requester{Kind: tokenKind(r.Requester.Kind), Human: r.Requester.Human, Agent: r.Requester.Agent, ClientId: r.Requester.ClientID},
		Database:        r.Database,
		Sql:             r.SQL,
		NormalizedSql:   r.NormalizedSQL,
		Reason:          r.Reason,
		Kind:            r.Analysis.Kind,
		Tables:          r.Analysis.Tables,
		EstimateRows:    r.EstimateRows,
		MaxAffectedRows: r.MaxAffectedRows,
		Risk:            r.Risk,
		ApprovalRule:    r.ApprovalRule,
		CurrentStep:     int32(r.CurrentStep),
		ConfigVersion:   r.ConfigVersion,
		CreateTime:      timestamppb.New(r.CreatedAt),
		ExpireTime:      timestamppb.New(r.ExpiresAt),
		DecideTime:      optTime(r.DecidedAt),
		DecidedBy:       r.DecidedBy,
		Comment:         r.Comment,
		StartTime:       optTime(r.StartedAt),
		FinishTime:      optTime(r.FinishedAt),
		Url:             r.URL,
	}
	for _, c := range r.Analysis.Columns {
		out.Columns = append(out.Columns, &dbgatewayv1.ReferencedColumn{Name: c.Name, Class: c.Class, Usage: c.Usage})
	}
	for _, s := range r.Steps {
		out.Steps = append(out.Steps, &dbgatewayv1.ApprovalStep{Role: string(s.Role), Group: s.Group, Count: int32(s.Count)})
	}
	for _, a := range r.Approvals {
		out.Approvals = append(out.Approvals, &dbgatewayv1.Approval{Step: int32(a.Step), Approver: a.Approver,
			ApproveTime: timestamppb.New(a.At), StepUpMethod: a.StepUpMethod, StepUpTime: timestamppb.New(a.StepUpAt)})
	}
	if res := r.Result; res != nil {
		out.Result = &dbgatewayv1.RequestResult{
			RowsAffected: res.RowsAffected,
			Columns:      resultColumns(res.Columns),
			Rows:         rows(res.Rows),
			RowCount:     int64(res.RowCount),
			Truncated:    res.Truncated,
			Duration:     durationpb.New(time.Duration(res.DurationMS) * time.Millisecond),
			Error:        res.Error,
			Code:         res.Code,
			Backup:       backup(res.Backup),
		}
	}
	return out
}

func backup(b *gateway.Backup) *dbgatewayv1.Backup {
	if b == nil {
		return nil
	}
	return &dbgatewayv1.Backup{Schema: b.Schema, Table: b.Table, Source: b.Source, Rows: b.Rows,
		RestoreSql: b.RestoreSQL, RestoreUnavailable: b.RestoreUnavailable}
}

func optTime(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func approvalStatus(s approval.Status) dbgatewayv1.ApprovalStatus {
	switch s {
	case approval.StatusPending:
		return dbgatewayv1.ApprovalStatus_APPROVAL_STATUS_PENDING
	case approval.StatusApproved:
		return dbgatewayv1.ApprovalStatus_APPROVAL_STATUS_APPROVED
	case approval.StatusRunning:
		return dbgatewayv1.ApprovalStatus_APPROVAL_STATUS_RUNNING
	case approval.StatusSucceeded:
		return dbgatewayv1.ApprovalStatus_APPROVAL_STATUS_SUCCEEDED
	case approval.StatusFailed:
		return dbgatewayv1.ApprovalStatus_APPROVAL_STATUS_FAILED
	case approval.StatusRejected:
		return dbgatewayv1.ApprovalStatus_APPROVAL_STATUS_REJECTED
	case approval.StatusExpired:
		return dbgatewayv1.ApprovalStatus_APPROVAL_STATUS_EXPIRED
	case approval.StatusCanceled:
		return dbgatewayv1.ApprovalStatus_APPROVAL_STATUS_CANCELED
	}
	return dbgatewayv1.ApprovalStatus_APPROVAL_STATUS_UNSPECIFIED
}

func tokenKind(k identity.Kind) dbgatewayv1.TokenKind {
	switch k {
	case identity.KindHuman:
		return dbgatewayv1.TokenKind_TOKEN_KIND_HUMAN
	case identity.KindAgent:
		return dbgatewayv1.TokenKind_TOKEN_KIND_AGENT
	}
	return dbgatewayv1.TokenKind_TOKEN_KIND_UNSPECIFIED
}
