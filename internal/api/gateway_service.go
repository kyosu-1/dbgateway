package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	dbgatewayv1 "github.com/kyosu-1/dbgateway/gen/dbgateway/v1"
	"github.com/kyosu-1/dbgateway/gen/dbgateway/v1/dbgatewayv1connect"
	"github.com/kyosu-1/dbgateway/internal/approval"
	"github.com/kyosu-1/dbgateway/internal/auth"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/gateway"
)

// maxSQLRequestBytes bounds a GatewayService request (SQL, reason).
const maxSQLRequestBytes = 1 << 20

// maxCommentRunes matches the approval service's comment limit.
const maxCommentRunes = 1000

// NewGatewayService returns the mount path and handler of GatewayService,
// the human query API used by the dbgw CLI and the web console. Every RPC
// requires a human bearer token (from `dbgw login`); agent tokens are
// refused (agents use MCP). approvals may be nil when approvals are
// disabled: writes are then denied by the gateway and the request RPCs
// fail with FAILED_PRECONDITION.
func NewGatewayService(a *auth.Server, gw *gateway.Gateway, approvals *approval.Service, cfg *config.Config) (string, http.Handler) {
	svc := &gatewayService{gw: gw, approvals: approvals, cfg: cfg}
	return dbgatewayv1connect.NewGatewayServiceHandler(svc,
		connect.WithInterceptors(humanOnly(a)),
		connect.WithReadMaxBytes(maxSQLRequestBytes),
	)
}

type gatewayService struct {
	gw *gateway.Gateway
	// approvals is nil when approvals are disabled. It is kept as the
	// concrete pointer so that the nil check cannot be fooled by a typed
	// nil in an interface.
	approvals *approval.Service
	cfg       *config.Config
}

var _ dbgatewayv1connect.GatewayServiceHandler = (*gatewayService)(nil)

func (s *gatewayService) ListDatabases(ctx context.Context, _ *connect.Request[dbgatewayv1.ListDatabasesRequest]) (*connect.Response[dbgatewayv1.ListDatabasesResponse], error) {
	caller, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	resp := &dbgatewayv1.ListDatabasesResponse{Principal: caller.Human}
	for _, d := range s.gw.ListDatabases(caller) {
		db := &dbgatewayv1.Database{Name: d.Name, Type: d.Type, Labels: d.Labels,
			CanSearch: d.CanSearch, CanRead: d.CanRead, CanWrite: d.CanWrite, MaxRows: int64(d.MaxRows), Description: d.Description}
		for _, r := range d.Roles {
			db.Roles = append(db.Roles, string(r))
		}
		resp.Databases = append(resp.Databases, db)
	}
	return connect.NewResponse(resp), nil
}

func (s *gatewayService) SearchObjects(ctx context.Context, req *connect.Request[dbgatewayv1.SearchObjectsRequest]) (*connect.Response[dbgatewayv1.SearchObjectsResponse], error) {
	caller, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	m := req.Msg
	if m.Database == "" {
		return nil, invalidArgument("database is required")
	}
	if m.Limit < 0 {
		return nil, invalidArgument("limit must not be negative")
	}
	var detail string
	switch m.Detail {
	case dbgatewayv1.ObjectDetail_OBJECT_DETAIL_UNSPECIFIED, dbgatewayv1.ObjectDetail_OBJECT_DETAIL_SUMMARY:
		detail = "summary"
	case dbgatewayv1.ObjectDetail_OBJECT_DETAIL_NAMES:
		detail = "names"
	case dbgatewayv1.ObjectDetail_OBJECT_DETAIL_FULL:
		detail = "full"
	default:
		return nil, invalidArgument("unknown detail")
	}
	res, err := s.gw.SearchObjects(ctx, caller, gateway.SearchRequest{Database: m.Database, Keyword: m.Keyword, Schema: m.Schema,
		Detail: detail, Limit: int(m.Limit), TraceID: traceID(req.Header())})
	if err != nil {
		return nil, gatewayError(err)
	}
	resp := &dbgatewayv1.SearchObjectsResponse{RequestId: res.RequestID, Database: res.Database, Truncated: res.Truncated}
	for _, o := range res.Objects {
		po := &dbgatewayv1.SchemaObject{Type: o.Type, Schema: o.Schema, Name: o.Name, Comment: o.Comment, RowEstimate: o.RowEstimate,
			Description: o.Description}
		for _, c := range o.Columns {
			po.Columns = append(po.Columns, &dbgatewayv1.ObjectColumn{Name: c.Name, Type: c.Type, Nullable: c.Nullable,
				Comment: c.Comment, Class: c.Class, Masked: c.Masked, Description: c.Description})
		}
		for _, ix := range o.Indexes {
			po.Indexes = append(po.Indexes, &dbgatewayv1.ObjectIndex{Name: ix.Name, Definition: ix.Definition})
		}
		resp.Objects = append(resp.Objects, po)
	}
	for _, ex := range res.Examples {
		resp.Examples = append(resp.Examples, &dbgatewayv1.ExampleQuery{Title: ex.Title, Description: ex.Description, Sql: ex.SQL, Tables: ex.Tables})
	}
	return connect.NewResponse(resp), nil
}

func (s *gatewayService) ExecuteSQL(ctx context.Context, req *connect.Request[dbgatewayv1.ExecuteSQLRequest]) (*connect.Response[dbgatewayv1.ExecuteSQLResponse], error) {
	caller, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	m := req.Msg
	if m.Database == "" {
		return nil, invalidArgument("database is required")
	}
	if strings.TrimSpace(m.Sql) == "" {
		return nil, invalidArgument("sql is required")
	}
	// Denials (including an empty reason) are decided and audited by the
	// gateway and reported in the response.
	res := s.gw.ExecuteSQL(ctx, caller, gateway.ExecuteRequest{Database: m.Database, SQL: m.Sql, Reason: m.Reason,
		TraceID: traceID(req.Header())})
	return connect.NewResponse(executeResponse(res)), nil
}

func (s *gatewayService) ExplainPolicy(ctx context.Context, req *connect.Request[dbgatewayv1.ExplainPolicyRequest]) (*connect.Response[dbgatewayv1.ExplainPolicyResponse], error) {
	caller, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	m := req.Msg
	if m.Database == "" {
		return nil, invalidArgument("database is required")
	}
	if strings.TrimSpace(m.Sql) == "" {
		return nil, invalidArgument("sql is required")
	}
	res, err := s.gw.ExplainPolicy(ctx, caller, gateway.ExplainRequest{Database: m.Database, SQL: m.Sql, TraceID: traceID(req.Header())})
	if err != nil {
		return nil, gatewayError(err)
	}
	return connect.NewResponse(explainResponse(res)), nil
}

func (s *gatewayService) GetRequest(ctx context.Context, req *connect.Request[dbgatewayv1.GetRequestRequest]) (*connect.Response[dbgatewayv1.GetRequestResponse], error) {
	caller, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.approvalsEnabled(); err != nil {
		return nil, err
	}
	id, err := requestID(req.Msg.Id)
	if err != nil {
		return nil, err
	}
	r, err := s.approvals.Get(ctx, caller, id)
	if err != nil {
		return nil, approvalError(err)
	}
	resp := &dbgatewayv1.GetRequestResponse{Request: approvalRequest(r)}
	if r.Result != nil {
		resp.Notice = gateway.DataNotice
	}
	return connect.NewResponse(resp), nil
}

func (s *gatewayService) ListRequests(ctx context.Context, req *connect.Request[dbgatewayv1.ListRequestsRequest]) (*connect.Response[dbgatewayv1.ListRequestsResponse], error) {
	caller, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.approvalsEnabled(); err != nil {
		return nil, err
	}
	m := req.Msg
	if m.Limit < 0 {
		return nil, invalidArgument("limit must not be negative")
	}
	var scope approval.Scope
	switch m.Scope {
	case dbgatewayv1.RequestScope_REQUEST_SCOPE_UNSPECIFIED, dbgatewayv1.RequestScope_REQUEST_SCOPE_MINE:
		scope = approval.ScopeMine
	case dbgatewayv1.RequestScope_REQUEST_SCOPE_AWAITING_ME:
		scope = approval.ScopeAwaitingMe
	case dbgatewayv1.RequestScope_REQUEST_SCOPE_DECIDED:
		scope = approval.ScopeDecided
	default:
		return nil, invalidArgument("unknown scope")
	}
	list, err := s.approvals.List(ctx, caller, approval.ListFilter{Scope: scope, Database: m.Database, Limit: int(m.Limit)})
	if err != nil {
		return nil, approvalError(err)
	}
	resp := &dbgatewayv1.ListRequestsResponse{}
	for _, r := range list {
		resp.Requests = append(resp.Requests, approvalRequest(r))
	}
	return connect.NewResponse(resp), nil
}

func (s *gatewayService) CancelRequest(ctx context.Context, req *connect.Request[dbgatewayv1.CancelRequestRequest]) (*connect.Response[dbgatewayv1.CancelRequestResponse], error) {
	caller, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.approvalsEnabled(); err != nil {
		return nil, err
	}
	id, err := requestID(req.Msg.Id)
	if err != nil {
		return nil, err
	}
	r, err := s.approvals.Cancel(ctx, caller, id)
	if err != nil {
		return nil, approvalError(err)
	}
	return connect.NewResponse(&dbgatewayv1.CancelRequestResponse{Request: approvalRequest(r)}), nil
}

func (s *gatewayService) RejectRequest(ctx context.Context, req *connect.Request[dbgatewayv1.RejectRequestRequest]) (*connect.Response[dbgatewayv1.RejectRequestResponse], error) {
	caller, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.approvalsEnabled(); err != nil {
		return nil, err
	}
	id, err := requestID(req.Msg.Id)
	if err != nil {
		return nil, err
	}
	comment := strings.TrimSpace(req.Msg.Comment)
	if utf8.RuneCountInString(comment) > maxCommentRunes {
		return nil, invalidArgument("comment is too long (at most 1000 characters)")
	}
	r, err := s.approvals.Reject(ctx, caller, id, comment)
	if err != nil {
		return nil, approvalError(err)
	}
	return connect.NewResponse(&dbgatewayv1.RejectRequestResponse{Request: approvalRequest(r)}), nil
}

func (s *gatewayService) approvalsEnabled() error {
	if s.approvals == nil {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("approvals are not enabled on this server"))
	}
	return nil
}

func requestID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", invalidArgument("id is required")
	}
	return id, nil
}

func invalidArgument(msg string) error {
	return connect.NewError(connect.CodeInvalidArgument, errors.New(msg))
}

// traceID extracts the trace ID from a W3C traceparent header so that the
// audit entries correlate with the caller's trace.
func traceID(h http.Header) string {
	parts := strings.Split(h.Get("traceparent"), "-")
	if len(parts) != 4 || len(parts[1]) != 32 || strings.Trim(parts[1], "0") == "" {
		return ""
	}
	for _, c := range parts[1] {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return ""
		}
	}
	return parts[1]
}

// errNoAccess mirrors gateway.ErrNoAccess for API clients.
var errNoAccess = errors.New("the database does not exist or you have no access to it; see ListDatabases (`dbgw dbs`)")

// gatewayError maps errors of SearchObjects and ExplainPolicy. Their
// messages (database unavailable, audit log unavailable) are written for
// clients and already sanitized.
func gatewayError(err error) error {
	if errors.Is(err, gateway.ErrNoAccess) {
		return connect.NewError(connect.CodePermissionDenied, errNoAccess)
	}
	return connect.NewError(connect.CodeUnavailable, err)
}

// errRequestNotFound is the same for nonexistent and invisible requests.
var errRequestNotFound = errors.New("the request does not exist or you cannot see it")

// approvalError maps approval service errors. ErrNotFound must look
// exactly like a nonexistent ID.
func approvalError(err error) error {
	switch {
	case errors.Is(err, approval.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, errRequestNotFound)
	case errors.Is(err, approval.ErrSelfApproval):
		return connect.NewError(connect.CodePermissionDenied, errors.New("you cannot reject your own request; cancel it instead"))
	case errors.Is(err, approval.ErrNotEligible):
		return connect.NewError(connect.CodePermissionDenied, errors.New("you are not an approver for this request"))
	case errors.Is(err, approval.ErrNotRequester):
		return connect.NewError(connect.CodePermissionDenied, errors.New("only the requester can cancel a request"))
	case errors.Is(err, approval.ErrAgent):
		return connect.NewError(connect.CodePermissionDenied, errors.New("only humans can reject requests"))
	case errors.Is(err, approval.ErrNotPending):
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("the request is no longer pending"))
	case errors.Is(err, approval.ErrExpired):
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("the request has expired"))
	case errors.Is(err, approval.ErrIntegrity):
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("the request failed its integrity check and can no longer be decided"))
	case errors.Is(err, approval.ErrUnavailable):
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("approvals are not enabled on this server"))
	case errors.Is(err, approval.ErrConflict):
		return connect.NewError(connect.CodeAborted, errors.New("the request changed concurrently; retry"))
	case errors.Is(err, approval.ErrInvalidRequest):
		return connect.NewError(connect.CodeInvalidArgument, errors.New("invalid request"))
	}
	return internal(err)
}

// expireAfter converts the rule's expiry (a time.Duration string).
func expireAfter(s string) *durationpb.Duration {
	if s == "" {
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return nil
	}
	return durationpb.New(d)
}
