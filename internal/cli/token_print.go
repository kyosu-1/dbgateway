package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// tokenPrintCmd is `dbgw token print`: it prints the access token saved by
// `dbgw login`, e.g. to use as the password of the PostgreSQL proxy.
func tokenPrintCmd(server *string) *cobra.Command {
	return &cobra.Command{
		Use:   "print",
		Short: "Print your saved access token (e.g. as the PostgreSQL proxy password)",
		Long: `Print the access token saved by ` + "`dbgw login`" + ` to stdout, for example to use
as the password of the PostgreSQL-compatible proxy:

  PGPASSWORD="$(dbgw token print)" psql "host=127.0.0.1 port=5433 dbname=prod-main user=me"

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
