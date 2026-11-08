// Command dbgw is the dbgateway server and CLI.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/kyosu-1/dbgateway/internal/cli"
	mcpserver "github.com/kyosu-1/dbgateway/internal/mcp"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRoot().ExecuteContext(ctx); err != nil {
		var exit exitError
		if errors.As(err, &exit) {
			os.Exit(int(exit))
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// exitError ends the process with a status code without printing.
type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func newRoot() *cobra.Command {
	mcpserver.Version = version
	root := &cobra.Command{
		Use:           "dbgw",
		Short:         "dbgateway: a SQL-aware gateway that lets AI agents and people safely access production databases",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	root.AddCommand(
		serveCmd(),
		configCmd(),
		policyCmd(),
		auditCmd(),
		storeCmd(),
		cli.LoginCmd(),
		cli.LogoutCmd(),
		cli.TokenCmd(),
		cli.MCPCmd(),
	)
	return root
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
