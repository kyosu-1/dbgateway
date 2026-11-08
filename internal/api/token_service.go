// Package api serves the dbgateway management API (everything that is not
// MCP or OAuth) with connectRPC. Services are defined in proto/.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	dbgatewayv1 "github.com/kyosu-1/dbgateway/gen/dbgateway/v1"
	"github.com/kyosu-1/dbgateway/gen/dbgateway/v1/dbgatewayv1connect"
	"github.com/kyosu-1/dbgateway/internal/auth"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// NewTokenService returns the mount path and handler of TokenService.
// Every RPC requires a human bearer token (from `dbgw login`).
func NewTokenService(a *auth.Server, st store.Store, cfg *config.Config) (string, http.Handler) {
	svc := &tokenService{auth: a, store: st, cfg: cfg, now: time.Now}
	return dbgatewayv1connect.NewTokenServiceHandler(svc,
		connect.WithInterceptors(humanOnly(a)),
		connect.WithReadMaxBytes(64<<10),
	)
}

type tokenService struct {
	auth  *auth.Server
	store store.Store
	cfg   *config.Config
	now   func() time.Time
}

var _ dbgatewayv1connect.TokenServiceHandler = (*tokenService)(nil)

func (s *tokenService) CreateAgentToken(ctx context.Context, req *connect.Request[dbgatewayv1.CreateAgentTokenRequest]) (*connect.Response[dbgatewayv1.CreateAgentTokenResponse], error) {
	caller, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	m := req.Msg
	if m.TtlSeconds < 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("ttl_seconds must not be negative"))
	}
	// Zero means the maximum; larger values are capped (also guards
	// against overflow). MintAgentToken enforces the cap again.
	maxTTL := s.cfg.Auth.AgentTokens.MaxTTL.D()
	ttl := maxTTL
	if m.TtlSeconds > 0 && m.TtlSeconds < int64(maxTTL/time.Second) {
		ttl = time.Duration(m.TtlSeconds) * time.Second
	}
	raw, t, err := s.auth.MintAgentToken(ctx, caller, auth.AgentTokenRequest{
		AgentName: m.AgentName,
		Databases: m.Databases,
		TTL:       ttl,
		Scopes:    m.Scopes,
	})
	if err != nil {
		return nil, mintError(err)
	}
	return connect.NewResponse(&dbgatewayv1.CreateAgentTokenResponse{
		AccessToken: raw,
		ExpireTime:  timestamppb.New(t.ExpiresAt),
		Token:       toProto(t),
	}), nil
}

func (s *tokenService) ListTokens(ctx context.Context, req *connect.Request[dbgatewayv1.ListTokensRequest]) (*connect.Response[dbgatewayv1.ListTokensResponse], error) {
	caller, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	tokens, err := s.store.ListTokens(ctx, caller.Human)
	if err != nil {
		return nil, internal(err)
	}
	now := s.now()
	resp := &dbgatewayv1.ListTokensResponse{}
	for _, t := range tokens {
		if !req.Msg.IncludeInactive && !t.Active(now) {
			continue
		}
		resp.Tokens = append(resp.Tokens, toProto(t))
	}
	return connect.NewResponse(resp), nil
}

func (s *tokenService) RevokeToken(ctx context.Context, req *connect.Request[dbgatewayv1.RevokeTokenRequest]) (*connect.Response[dbgatewayv1.RevokeTokenResponse], error) {
	caller, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if req.Msg.Id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("id is required"))
	}
	t, err := s.store.GetToken(ctx, req.Msg.Id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("token not found"))
	}
	if err != nil {
		return nil, internal(err)
	}
	if t.Human != caller.Human {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("you can only revoke your own tokens"))
	}
	if _, err := s.store.RevokeToken(ctx, t.ID, s.now()); err != nil {
		return nil, internal(err)
	}
	return connect.NewResponse(&dbgatewayv1.RevokeTokenResponse{}), nil
}

func toProto(t *store.Token) *dbgatewayv1.Token {
	pt := &dbgatewayv1.Token{
		Id:         t.ID,
		Human:      t.Human,
		AgentName:  t.Agent,
		ClientId:   t.ClientID,
		ClientName: t.ClientName,
		Databases:  t.Databases,
		Scopes:     t.Scopes,
		CreateTime: timestamppb.New(t.CreatedAt),
		ExpireTime: timestamppb.New(t.ExpiresAt),
		ParentId:   t.ParentID,
	}
	switch t.Kind {
	case identity.KindHuman:
		pt.Kind = dbgatewayv1.TokenKind_TOKEN_KIND_HUMAN
	case identity.KindAgent:
		pt.Kind = dbgatewayv1.TokenKind_TOKEN_KIND_AGENT
	}
	switch t.Type {
	case store.TokenAccess:
		pt.Type = dbgatewayv1.TokenType_TOKEN_TYPE_ACCESS
	case store.TokenRefresh:
		pt.Type = dbgatewayv1.TokenType_TOKEN_TYPE_REFRESH
	}
	if t.RevokedAt != nil {
		pt.RevokeTime = timestamppb.New(*t.RevokedAt)
	}
	return pt
}

func mintError(err error) error {
	switch {
	case errors.Is(err, auth.ErrInvalidRequest):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, auth.ErrPermissionDenied):
		return connect.NewError(connect.CodePermissionDenied, err)
	}
	return internal(err)
}

// internal logs err and hides its details from the client.
func internal(err error) error {
	slog.Error("api: internal error", "err", err)
	return connect.NewError(connect.CodeInternal, errors.New("internal error"))
}
