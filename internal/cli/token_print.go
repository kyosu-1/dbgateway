package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// tokenPrintCmd is `dbgw token print`: it prints the access token saved by
// `dbgw login`, e.g. to call the connectRPC API from a script.
func tokenPrintCmd(server *string) *cobra.Command {
	return &cobra.Command{
		Use:   "print",
		Short: "Print your saved access token (e.g. for scripts calling the API)",
		Long: `Print the access token saved by ` + "`dbgw login`" + ` to stdout, for example to call
the connectRPC API from a script:

  curl -H "Authorization: Bearer $(dbgw token print)" -H "Content-Type: application/json" \
    -d '{}' https://dbgateway.example.com/dbgateway.v1.GatewayService/ListDatabases

The token is a secret: anyone holding it can query as you until it expires.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := loggedIn(*server)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: this is a secret bearer token for %s (expires %s). "+
				"Anyone holding it can query as you; do not share it or put it in logs or shell history.\n",
				c.Server, c.ExpiresAt.Local().Format(time.DateTime))
			fmt.Fprintln(cmd.OutOrStdout(), c.AccessToken)
			return nil
		},
	}
}
