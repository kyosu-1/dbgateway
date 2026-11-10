package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kyosu-1/dbgateway/internal/lint"
)

// lintUsageExit is the exit status when files could not be checked at all
// (bad flags, configuration or paths). Error-level findings exit with 1.
const lintUsageExit = 2

func lintCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lint [flags] FILE|DIR|-...",
		Short: "Check SQL migrations for statements that are risky in production (offline); exits 1 on errors",
		Long: `Check SQL migration files for statements that can cause an outage or lose
data when applied to a production database: long locks, table rewrites,
destructive and breaking changes. Files are parsed with the database's own
parser; no database connection is needed.

Arguments are files, directories (searched for *.sql) or glob patterns; "-"
reads standard input. Exit status: 0 without error-level findings, 1 with
error-level findings, 2 when the files could not be checked.`,
	}
	dialect := cmd.Flags().String("dialect", "", "SQL dialect: postgres or mysql (default: the configuration's dialect, else postgres)")
	cfgPath := cmd.Flags().StringP("config", "c", "", "lint configuration file (YAML)")
	format := cmd.Flags().StringP("format", "o", lint.FormatText, "output format: text, json or github (GitHub Actions annotations)")
	listRules := cmd.Flags().Bool("list-rules", false, "list the rules and exit")
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return lintUsageError(c, err)
	})
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		err := runLint(cmd, args, *dialect, *cfgPath, *format, *listRules)
		var exit exitError
		if err != nil && !errors.As(err, &exit) {
			return lintUsageError(cmd, err)
		}
		return err
	}
	return cmd
}

func lintUsageError(cmd *cobra.Command, err error) error {
	fmt.Fprintln(cmd.ErrOrStderr(), "error:", err)
	return exitError(lintUsageExit)
}

func runLint(cmd *cobra.Command, args []string, dialectFlag, cfgPath, format string, listRules bool) error {
	switch format {
	case lint.FormatText, lint.FormatJSON, lint.FormatGitHub:
	default:
		return fmt.Errorf("unknown format %q (use text, json or github)", format)
	}
	var cfg *lint.Config
	if cfgPath != "" {
		var err error
		if cfg, err = lint.LoadConfig(cfgPath); err != nil {
			return err
		}
	}
	name := dialectFlag
	if name == "" && cfg != nil {
		name = cfg.Dialect
	}
	if name == "" {
		name = string(lint.Postgres)
	}
	dialect, err := lint.ParseDialect(name)
	if err != nil {
		return err
	}
	if listRules {
		return printRules(cmd.OutOrStdout(), dialect, format)
	}
	if len(args) == 0 {
		return errors.New("no files given (pass files, directories, glob patterns or - for standard input)")
	}
	files, err := lintFiles(args)
	if err != nil {
		return err
	}
	l, err := lint.New(dialect, cfg)
	if err != nil {
		return err
	}

	var findings []lint.Finding
	for _, f := range files {
		var src []byte
		name := f
		if f == "-" {
			name = "<stdin>"
			src, err = io.ReadAll(cmd.InOrStdin())
		} else {
			src, err = os.ReadFile(f)
		}
		if err != nil {
			return err
		}
		findings = append(findings, l.Lint(name, src)...)
	}
	if err := lint.Write(cmd.OutOrStdout(), format, len(files), findings); err != nil {
		return err
	}
	sum := lint.Summarize(len(files), findings)
	if format != lint.FormatJSON {
		fmt.Fprintln(cmd.ErrOrStderr(), sum)
	}
	if sum.Errors > 0 {
		return exitError(1)
	}
	return nil
}

// lintFiles expands the arguments: directories are searched for *.sql files
// and patterns the shell did not expand are globbed.
func lintFiles(args []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(f string) {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	for _, arg := range args {
		if arg == "-" {
			add(arg)
			continue
		}
		paths := []string{arg}
		if _, err := os.Stat(arg); err != nil && strings.ContainsAny(arg, "*?[") {
			matches, gerr := filepath.Glob(arg)
			if gerr != nil {
				return nil, fmt.Errorf("%s: %w", arg, gerr)
			}
			if len(matches) == 0 {
				return nil, fmt.Errorf("%s: no files match", arg)
			}
			paths = matches
		}
		for _, p := range paths {
			fi, err := os.Stat(p)
			if err != nil {
				return nil, err
			}
			if !fi.IsDir() {
				add(p)
				continue
			}
			n := len(out)
			err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".sql") {
					add(path)
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			if len(out) == n {
				return nil, fmt.Errorf("%s: no .sql files in the directory", p)
			}
		}
	}
	return out, nil
}

func printRules(w io.Writer, d lint.Dialect, format string) error {
	rules := lint.Rules(d)
	if format == lint.FormatJSON {
		type rule struct {
			ID       string        `json:"id"`
			Severity lint.Severity `json:"severity"`
			Summary  string        `json:"summary"`
			Hint     string        `json:"hint"`
		}
		out := make([]rule, 0, len(rules))
		for _, r := range rules {
			out = append(out, rule{r.ID, r.Severity, r.Summary, r.Hint})
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tSEVERITY\tSUMMARY")
	for _, r := range rules {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", r.ID, r.Severity, r.Summary)
	}
	return tw.Flush()
}
