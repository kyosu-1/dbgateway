package main

import (
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/kyosu-1/dbgateway/internal/audit"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/policy"
	"github.com/kyosu-1/dbgateway/internal/policytest"
	"github.com/kyosu-1/dbgateway/internal/server"
	"github.com/kyosu-1/dbgateway/internal/store"
)

const defaultConfig = "dbgateway.yaml"

func configFlag(cmd *cobra.Command, required bool) *string {
	def := os.Getenv("DBGW_CONFIG")
	if def == "" && os.Getenv("DBGW_CONFIG_YAML") != "" {
		def = config.EnvPrefix + "DBGW_CONFIG_YAML"
	}
	if def == "" && !required {
		def = defaultConfig
	}
	return cmd.Flags().StringP("config", "c", def, `path to dbgateway.yaml, or "env:NAME" to read it from an environment variable (env DBGW_CONFIG; DBGW_CONFIG_YAML holds the content)`)
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
		Long: "Verify the hash chain of the audit log: the files in --dir, or the output selected by the\n" +
			"configuration (audit.dir for audit.output: file, the audit_log table for audit.output: postgres).",
		Args: cobra.NoArgs,
	}
	dir := verify.Flags().String("dir", "", "audit directory (default: audit.dir from the configuration)")
	path := configFlag(verify, false)
	verify.RunE = func(cmd *cobra.Command, _ []string) error {
		d := *dir
		where := ""
		var rep *audit.VerifyReport
		var err error
		if d == "" {
			cfg, lerr := config.Load(*path)
			if lerr != nil {
				return fmt.Errorf("pass --dir or a valid --config: %w", lerr)
			}
			d = cfg.Audit.Dir
			if cfg.Audit.Output == config.AuditOutputPostgres {
				dsn, derr := cfg.AuditDSN()
				if derr != nil {
					return derr
				}
				where = "the PostgreSQL audit log"
				rep, err = audit.VerifyPostgres(cmd.Context(), dsn)
			}
		}
		if where == "" {
			rep, err = audit.VerifyDir(d)
			if rep != nil {
				where = fmt.Sprintf("%d files", rep.Files)
			}
		}
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
		fmt.Printf("ok: %d entries in %s, chained from %s; last hash %s\n", rep.Entries, where, from, rep.LastHash)
		return nil
	}
	cmd.AddCommand(verify)
	return cmd
}

func storeCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "store", Short: "Management database commands"}
	imp := &cobra.Command{
		Use:   "import-sqlite",
		Short: "Copy a SQLite management database into the PostgreSQL one (store.driver: postgres)",
		Long: "Copy every row of a SQLite management database (users, sessions, tokens, approval requests,\n" +
			"grants, SCIM state) into the empty PostgreSQL management database of the configuration.\n" +
			"Stop dbgateway first. The copy runs in one transaction and refuses a non-empty target.",
		Args: cobra.NoArgs,
	}
	from := imp.Flags().String("from", "", "path of the SQLite database (e.g. var/dbgateway.db)")
	path := configFlag(imp, false)
	imp.RunE = func(cmd *cobra.Command, _ []string) error {
		if *from == "" {
			return fmt.Errorf("--from is required")
		}
		if _, err := os.Stat(*from); err != nil {
			return err
		}
		cfg, err := config.Load(*path)
		if err != nil {
			return err
		}
		if cfg.Store.Driver != config.StorePostgres {
			return fmt.Errorf("the configuration must select store.driver: %s", config.StorePostgres)
		}
		dsn, err := cfg.StoreDSN()
		if err != nil {
			return err
		}
		ctx := cmd.Context()
		src, err := store.OpenSQLite(ctx, *from)
		if err != nil {
			return err
		}
		defer src.Close()
		dst, err := store.OpenPostgres(ctx, dsn)
		if err != nil {
			return err
		}
		defer dst.Close()
		counts, err := store.ImportSQLite(ctx, src, dst)
		if err != nil {
			return err
		}
		tables := slices.Sorted(maps.Keys(counts))
		for _, t := range tables {
			fmt.Printf("%-24s %d rows\n", t, counts[t])
		}
		return nil
	}
	cmd.AddCommand(imp)
	return cmd
}
