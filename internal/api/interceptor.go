package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/kyosu-1/dbgateway/internal/auth"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

// humanOnly authenticates every unary RPC with a human bearer token and
// stores the principal in the context. Agent tokens are refused: agents can
// never manage tokens.
func humanOnly(a *auth.Server) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if req.Spec().IsClient {
				return next(ctx, req)
			}
			bearer := auth.BearerToken(req.Header().Get("Authorization"))
			if bearer == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing bearer token"))
			}
			p, err := a.Authenticate(ctx, bearer)
			if errors.Is(err, mcpauth.ErrInvalidToken) {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired token; run `dbgw login`"))
			}
			if err != nil {
				return nil, internal(err)
			}
			if p.Kind != identity.KindHuman {
				return nil, connect.NewError(connect.CodePermissionDenied, errors.New("agent tokens cannot use the token API"))
			}
			return next(identity.WithPrincipal(ctx, p), req)
		}
	}
}

// callerFrom returns the authenticated human set by the interceptor. It
// fails closed if the interceptor did not run.
func callerFrom(ctx context.Context) (*identity.Principal, error) {
	p := identity.FromContext(ctx)
	if p == nil || p.Kind != identity.KindHuman {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}
	return p, nil
}
