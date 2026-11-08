package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	dbgatewayv1 "github.com/kyosu-1/dbgateway/gen/dbgateway/v1"
	"github.com/kyosu-1/dbgateway/gen/dbgateway/v1/dbgatewayv1connect"
)

// MCPCmd is `dbgw mcp`, with the `stdio` subcommand.
func MCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "MCP client helpers",
	}
	cmd.AddCommand(mcpStdioCmd())
	return cmd
}

func mcpStdioCmd() *cobra.Command {
	var server, agent, databases string
	cmd := &cobra.Command{
		Use:   "stdio",
		Short: "Relay MCP over stdio to dbgateway, as an agent acting for you",
		Long: "Serve MCP on stdin/stdout for stdio-only MCP clients. Using the credentials\n" +
			"saved by `dbgw login`, mints a short-lived agent token (re-minted before it\n" +
			"expires) and relays to <server>/mcp over Streamable HTTP. Logs go to stderr.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Nothing but MCP JSON-RPC may go to stdout.
			cmd.SetOut(os.Stderr)
			log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
			c, err := loggedIn(server)
			if err != nil {
				return err
			}
			dbs := splitList(databases)
			if len(dbs) == 0 {
				return errors.New("--databases is required (comma-separated databases the agent may read)")
			}
			ts := &agentTokenSource{client: tokenServiceClient(c), agent: agent, databases: dbs}
			return runStdioRelay(cmd.Context(), log, c.Server+"/mcp", ts, &mcp.StdioTransport{})
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "dbgateway URL (default: the logged-in server)")
	cmd.Flags().StringVar(&agent, "agent", "mcp-stdio", "agent name recorded in audit logs")
	cmd.Flags().StringVar(&databases, "databases", "", "comma-separated databases the agent may read (required)")
	return cmd
}

// agentTokenSource mints agent tokens with the human credentials and
// re-mints them shortly before they expire.
type agentTokenSource struct {
	client    dbgatewayv1connect.TokenServiceClient
	agent     string
	databases []string

	mu       sync.Mutex
	token    string
	expires  time.Time
	lifetime time.Duration
}

// Token returns a valid agent token.
func (s *agentTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	margin := max(s.lifetime/5, 30*time.Second)
	if s.token != "" && time.Until(s.expires) > margin {
		return s.token, nil
	}
	resp, err := s.client.CreateAgentToken(ctx, connect.NewRequest(&dbgatewayv1.CreateAgentTokenRequest{
		AgentName: s.agent,
		Databases: s.databases,
	}))
	if err != nil {
		s.token = ""
		if connect.CodeOf(err) == connect.CodeUnauthenticated {
			return "", fmt.Errorf("%w (%v)", errNotLoggedIn, err)
		}
		return "", fmt.Errorf("mint agent token: %w", err)
	}
	s.token = resp.Msg.AccessToken
	s.expires = resp.Msg.ExpireTime.AsTime()
	s.lifetime = time.Until(s.expires)
	return s.token, nil
}

// invalidate drops the cached token (e.g. after a 401).
func (s *agentTokenSource) invalidate() {
	s.mu.Lock()
	s.token = ""
	s.mu.Unlock()
}

type tokenSource interface {
	Token(context.Context) (string, error)
	invalidate()
}

// relay forwards tools between a local MCP server and the upstream
// dbgateway session. It reconnects when the upstream session ends.
type relay struct {
	log      *slog.Logger
	endpoint string
	http     *http.Client
	server   *mcp.Server

	mu    sync.Mutex
	sess  *mcp.ClientSession
	tools map[string]bool
}

func runStdioRelay(ctx context.Context, log *slog.Logger, endpoint string, ts tokenSource, local mcp.Transport) error {
	if _, err := ts.Token(ctx); err != nil { // fail fast before serving
		return err
	}
	r := &relay{
		log:      log,
		endpoint: endpoint,
		http: &http.Client{Transport: &bearerTransport{
			token:          ts.Token,
			onUnauthorized: ts.invalidate,
		}},
		tools: map[string]bool{},
	}
	sess, err := r.session(ctx)
	if err != nil {
		return err
	}
	opts := &mcp.ServerOptions{Logger: log}
	if ir := sess.InitializeResult(); ir != nil {
		opts.Instructions = ir.Instructions
	}
	r.server = mcp.NewServer(&mcp.Implementation{Name: "dbgateway", Version: version()}, opts)
	if err := r.syncTools(ctx, sess); err != nil {
		return err
	}
	log.Info("dbgw: relaying MCP over stdio", "upstream", endpoint)
	err = r.server.Run(ctx, local)
	r.mu.Lock()
	if r.sess != nil {
		r.sess.Close()
	}
	r.mu.Unlock()
	return err
}

// session returns the upstream session, connecting if needed.
func (r *relay) session(ctx context.Context) (*mcp.ClientSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sess != nil {
		return r.sess, nil
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "dbgw-stdio", Version: version()}, &mcp.ClientOptions{
		Logger: r.log,
		ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {
			// Not on the session's read loop: listing would deadlock.
			go func() {
				if s, err := r.session(context.Background()); err == nil {
					if err := r.syncTools(context.Background(), s); err != nil {
						r.log.Warn("dbgw: refresh tools", "err", err)
					}
				}
			}()
		},
	})
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: r.endpoint, HTTPClient: r.http}, nil)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", r.endpoint, err)
	}
	r.sess = sess
	go func() {
		err := sess.Wait()
		r.mu.Lock()
		if r.sess == sess {
			r.sess = nil
		}
		r.mu.Unlock()
		r.log.Info("dbgw: upstream session ended; will reconnect on next call", "err", err)
	}()
	return sess, nil
}

// syncTools mirrors the upstream tool list on the local server.
func (r *relay) syncTools(ctx context.Context, sess *mcp.ClientSession) error {
	seen := map[string]bool{}
	for tool, err := range sess.Tools(ctx, nil) {
		if err != nil {
			return fmt.Errorf("list tools: %w", err)
		}
		if r.addTool(tool) {
			seen[tool.Name] = true
		}
	}
	r.mu.Lock()
	var gone []string
	for name := range r.tools {
		if !seen[name] {
			gone = append(gone, name)
		}
	}
	r.tools = seen
	r.mu.Unlock()
	if len(gone) > 0 {
		r.server.RemoveTools(gone...)
	}
	return nil
}

// addTool registers a forwarding tool; it reports false for a tool the SDK
// rejects (e.g. an invalid schema).
func (r *relay) addTool(tool *mcp.Tool) (ok bool) {
	defer func() {
		if p := recover(); p != nil {
			r.log.Warn("dbgw: skipping upstream tool", "tool", tool.Name, "err", p)
			ok = false
		}
	}()
	r.server.AddTool(tool, r.callTool)
	return true
}

// callTool forwards a tools/call upstream.
func (r *relay) callTool(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	sess, err := r.session(ctx)
	if err != nil {
		return nil, err
	}
	params := &mcp.CallToolParams{Meta: forwardMeta(req.Params.Meta), Name: req.Params.Name}
	if len(req.Params.Arguments) > 0 {
		params.Arguments = req.Params.Arguments
	}
	return sess.CallTool(ctx, params)
}

// forwardMeta copies request metadata (e.g. trace context, progress token)
// except the keys reserved by the MCP protocol itself, such as the
// per-request protocol version: those describe the local session and are
// set by the upstream session as needed.
func forwardMeta(m mcp.Meta) mcp.Meta {
	var out mcp.Meta
	for k, v := range m {
		if strings.HasPrefix(k, "io.modelcontextprotocol/") {
			continue
		}
		if out == nil {
			out = mcp.Meta{}
		}
		out[k] = v
	}
	return out
}

func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "dev"
}
