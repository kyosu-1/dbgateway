package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/policy"
	"github.com/kyosu-1/dbgateway/internal/policytest"
	"github.com/kyosu-1/dbgateway/internal/server"
)

const defaultConfig = "dbgateway.yaml"

func configFlag(cmd *cobra.Command, required bool) *string {
	def := os.Getenv("DBGW_CONFIG")
	if def == "" && !required {
		def = defaultConfig
	}
	return cmd.Flags().StringP("config", "c", def, "path to dbgateway.yaml (env DBGW_CONFIG)")
}

// loadConfig loads the configuration and compiles the policies, printing
// warnings to stderr.
func loadConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if _, err := policy.Compile(cfg); err != nil {
		return nil, err
	}
	for _, w := range cfg.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	return cfg, nil
}

func serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the dbgateway server (MCP over Streamable HTTP, OAuth, API)",
		Args:  cobra.NoArgs,
	}
	path := configFlag(cmd, false)
	level := cmd.Flags().String("log-level", "info", "log level: debug, info, warn, error")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		logger := newLogger(*level)
		cfg, err := loadConfig(*path)
		if err != nil {
			return err
		}
		srv, err := server.New(cmd.Context(), cfg, logger)
		if err != nil {
			return err
		}
		defer srv.Close()
		return srv.Run(cmd.Context())
	}
	return cmd
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Configuration commands"}
	validate := &cobra.Command{
		Use:   "validate",
		Short: "Validate the configuration (types, CEL rules, no allow rule matching writes)",
		Args:  cobra.NoArgs,
	}
	path := configFlag(validate, false)
	validate.RunE = func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig(*path)
		if err != nil {
			return err
		}
		fmt.Printf("ok: %s (version %s, %d databases, %d policies)\n", *path, cfg.Version, len(cfg.Databases), len(cfg.Policies))
		return nil
	}
	cmd.AddCommand(validate)
	return cmd
}

func policyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Policy commands"}
	test := &cobra.Command{
		Use:   "test FILE...",
		Short: "Run policy test files (expected decisions and masking for SQL); exits 1 on failure",
		Args:  cobra.MinimumNArgs(1),
	}
	path := test.Flags().StringP("config", "c", "", "configuration to test (default: the test file's `config`)")
	verbose := test.Flags().BoolP("verbose", "v", false, "print passing cases too")
	test.RunE = func(cmd *cobra.Command, files []string) error {
		failed := 0
		total := 0
		for _, file := range files {
			f, err := policytest.Load(file)
			if err != nil {
				return err
			}
			cfgPath := f.Config
			if *path != "" {
				cfgPath = *path
			}
			if cfgPath == "" {
				return fmt.Errorf("%s: no configuration (set `config:` in the file or pass --config)", file)
			}
			cfg, err := loadConfig(cfgPath)
			if err != nil {
				return err
			}
			results, err := policytest.Run(cmd.Context(), f, cfg)
			if err != nil {
				return fmt.Errorf("%s: %w", file, err)
			}
			for _, r := range results {
				total++
				if r.Passed {
					if *verbose {
						fmt.Printf("PASS %s: %s => %s\n", file, r.Name, r.Got)
					}
					continue
				}
				failed++
				fmt.Printf("FAIL %s: %s => %s\n", file, r.Name, r.Got)
				for _, msg := range r.Failures {
					fmt.Printf("     %s\n", msg)
				}
			}
		}
		fmt.Printf("%d passed, %d failed\n", total-failed, failed)
		if failed > 0 {
			return exitError(1)
		}
		return nil
	}
	cmd.AddCommand(test)
	return cmd
}

func auditCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Audit log commands"}
	verify := &cobra.Command{
		Use:   "verify",
		Short: "Verify the hash chain of the audit log; exits 1 if it was tampered with",
		Args:  cobra.NoArgs,
	}
	dir := verify.Flags().String("dir", "", "audit directory (default: audit.dir from the configuration)")
	path := configFlag(verify, false)
	verify.RunE = func(cmd *cobra.Command, _ []string) error {
		d := *dir
		if d == "" {
			cfg, err := config.Load(*path)
			if err != nil {
				return fmt.Errorf("pass --dir or a valid --config: %w", err)
			}
			d = cfg.Audit.Dir
		}
		rep, err := audit.VerifyDir(d)
		if err != nil {
			fmt.Printf("FAILED: %v\n", err)
			if rep != nil {
				fmt.Printf("verified %d entries before the failure\n", rep.Entries)
			}
			return exitError(1)
		}
		from := "genesis"
		if rep.StartedFromCheckpoint {
			from = "a retention checkpoint"
		}
		fmt.Printf("ok: %d entries in %d files, chained from %s; last hash %s\n", rep.Entries, rep.Files, from, rep.LastHash)
		return nil
	}
	cmd.AddCommand(verify)
	return cmd
}
