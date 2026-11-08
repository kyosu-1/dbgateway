package web

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/kyosu-1/dbgateway/internal/auth"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// OpenStore opens the management database of a configuration for CLI
// commands. It defaults to the SQLite store at store.path; replace it when
// other store drivers are wired.
var OpenStore = func(ctx context.Context, cfg *config.Config) (store.Store, error) {
	return store.OpenSQLite(ctx, cfg.Store.Path)
}

// PasskeyCmd is `dbgw passkey`. Its `enroll` subcommand writes a one-time
// passkey enrollment link (valid 24 hours) for a person to the store and
// prints it. Run it on the server, with the server's configuration; it
// needs auth.passkeys: true.
func PasskeyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "passkey", Short: "Passkey commands"}
	enroll := &cobra.Command{
		Use:   "enroll --email ADDRESS",
		Short: "Create a one-time passkey enrollment link (valid 24h) and print it",
		Long: "Create a one-time link that lets the person register their first passkey and sign in.\n" +
			"Give the link only to that person, over a trusted channel. Requires auth.passkeys: true.",
		Args: cobra.NoArgs,
	}
	def := os.Getenv("DBGW_CONFIG")
	if def == "" {
		def = "dbgateway.yaml"
	}
	path := enroll.Flags().StringP("config", "c", def, "path to dbgateway.yaml (env DBGW_CONFIG)")
	email := enroll.Flags().String("email", "", "e-mail address of the person (required)")
	_ = enroll.MarkFlagRequired("email")
	enroll.RunE = func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load(*path)
		if err != nil {
			return err
		}
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		st, err := OpenStore(ctx, cfg)
		if err != nil {
			return fmt.Errorf("store: %w", err)
		}
		defer st.Close()
		link, expires, err := auth.CreatePasskeyEnrollment(ctx, st, cfg, *email, time.Now())
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), link)
		fmt.Fprintf(cmd.ErrOrStderr(), "One-time link for %s, valid until %s. Give it only to that person.\n",
			*email, expires.Local().Format(time.RFC3339))
		return nil
	}
	cmd.AddCommand(enroll)
	return cmd
}
