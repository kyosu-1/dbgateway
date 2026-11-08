package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	dbgatewayv1 "github.com/kyosu-1/dbgateway/gen/dbgateway/v1"
)

// TokenCmd is `dbgw token create|list|revoke|print`.
func TokenCmd() *cobra.Command {
	var server string
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage your tokens",
	}
	cmd.PersistentFlags().StringVar(&server, "server", "", "dbgateway URL (default: the logged-in server)")
	cmd.AddCommand(tokenCreateCmd(&server), tokenListCmd(&server), tokenRevokeCmd(&server), tokenPrintCmd(&server))
	return cmd
}

func tokenCreateCmd(server *string) *cobra.Command {
	var agent, databases string
	var write bool
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an agent token (printed to stdout)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := loggedIn(*server)
			if err != nil {
				return err
			}
			resp, err := tokenServiceClient(c).CreateAgentToken(cmd.Context(), connect.NewRequest(&dbgatewayv1.CreateAgentTokenRequest{
				AgentName:  agent,
				Databases:  splitList(databases),
				TtlSeconds: int64(ttl / time.Second),
				Scopes:     scopesFor(write),
			}))
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Created token %s for agent %q (expires %s).\n",
				resp.Msg.Token.GetId(), agent, resp.Msg.ExpireTime.AsTime().Local().Format(time.DateTime))
			fmt.Fprintln(cmd.OutOrStdout(), resp.Msg.AccessToken)
			return nil
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "agent name recorded in audit logs (required)")
	cmd.Flags().StringVar(&databases, "databases", "", "comma-separated databases the agent may read (required)")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "token lifetime (default and maximum: the server's max_ttl)")
	cmd.Flags().BoolVar(&write, "write", false, "also allow submitting writes for approval (db:write)")
	_ = cmd.MarkFlagRequired("agent")
	_ = cmd.MarkFlagRequired("databases")
	return cmd
}

func tokenListCmd(server *string) *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your tokens",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := loggedIn(*server)
			if err != nil {
				return err
			}
			resp, err := tokenServiceClient(c).ListTokens(cmd.Context(), connect.NewRequest(&dbgatewayv1.ListTokensRequest{IncludeInactive: all}))
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tKIND\tTYPE\tAGENT\tCLIENT\tDATABASES\tEXPIRES\tSTATUS")
			for _, t := range resp.Msg.Tokens {
				status := "active"
				switch {
				case t.RevokeTime != nil:
					status = "revoked"
				case t.ExpireTime.AsTime().Before(time.Now()):
					status = "expired"
				}
				client := t.ClientName
				if client == "" {
					client = t.ClientId
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", t.Id, kindName(t.Kind), typeName(t.Type), dash(t.AgentName),
					dash(client), dash(strings.Join(t.Databases, ",")), t.ExpireTime.AsTime().Local().Format(time.DateTime), status)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "include expired and revoked tokens")
	return cmd
}

func tokenRevokeCmd(server *string) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke ID",
		Short: "Revoke one of your tokens (and the tokens derived from it)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := loggedIn(*server)
			if err != nil {
				return err
			}
			if _, err := tokenServiceClient(c).RevokeToken(cmd.Context(), connect.NewRequest(&dbgatewayv1.RevokeTokenRequest{Id: args[0]})); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Revoked %s.\n", args[0])
			return nil
		},
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func kindName(k dbgatewayv1.TokenKind) string {
	switch k {
	case dbgatewayv1.TokenKind_TOKEN_KIND_HUMAN:
		return "human"
	case dbgatewayv1.TokenKind_TOKEN_KIND_AGENT:
		return "agent"
	}
	return "-"
}

func typeName(t dbgatewayv1.TokenType) string {
	switch t {
	case dbgatewayv1.TokenType_TOKEN_TYPE_ACCESS:
		return "access"
	case dbgatewayv1.TokenType_TOKEN_TYPE_REFRESH:
		return "refresh"
	}
	return "-"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
