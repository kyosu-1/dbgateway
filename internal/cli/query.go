package cli

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	dbgatewayv1 "github.com/kyosu-1/dbgateway/gen/dbgateway/v1"
	"github.com/kyosu-1/dbgateway/gen/dbgateway/v1/dbgatewayv1connect"
)

// maxSQLBytes bounds SQL read from a file or stdin (the server accepts at
// most 1 MiB per request).
const maxSQLBytes = 1 << 20

// gatewayServiceClient returns a GatewayService client authenticated with
// the human credentials. Queries may run for a while (the server enforces
// statement timeouts), so the client timeout is only a safety net.
func gatewayServiceClient(c *Credentials) dbgatewayv1connect.GatewayServiceClient {
	hc := &http.Client{Timeout: 10 * time.Minute, Transport: &bearerTransport{token: staticToken(c.AccessToken)}}
	return dbgatewayv1connect.NewGatewayServiceClient(hc, c.Server)
}

// QueryCmd is `dbgw query`.
func QueryCmd() *cobra.Command {
	var server, db, reason, format, file string
	cmd := &cobra.Command{
		Use:   "query --db NAME --reason TEXT [SQL | -f FILE]",
		Short: "Run a SQL statement through dbgateway",
		Long: `Run one SQL statement through dbgateway, as yourself (the login from
` + "`dbgw login`" + `). The SQL is taken from the arguments, from --file, or from
standard input. Reads return results at once (masked columns are marked
with * in the header); writes that need approval are submitted and run
after approval.

Exit status: 0 success, 1 error, 2 denied (the reason and a hint are printed
to stderr), 3 submitted for approval (the request ID and the approval URL
are printed to stderr).`,
		Example: `  dbgw query --db prod-main --reason "Support #1234: check the user's plan" \
    "SELECT id, plan FROM users WHERE id = 42"
  dbgw query --db prod-main --reason "Monthly report" -f report.sql --format csv > report.csv`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkFormat(format, formatTable, formatJSON, formatCSV); err != nil {
				return err
			}
			sql, err := readSQL(cmd, args, file)
			if err != nil {
				return err
			}
			c, err := loggedIn(server)
			if err != nil {
				return err
			}
			resp, err := gatewayServiceClient(c).ExecuteSQL(cmd.Context(), connect.NewRequest(&dbgatewayv1.ExecuteSQLRequest{
				Database: db, Sql: sql, Reason: reason,
			}))
			if err != nil {
				return apiError(err)
			}
			return printExecute(cmd.OutOrStdout(), cmd.ErrOrStderr(), format, resp.Msg)
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "dbgateway URL (default: the logged-in server)")
	cmd.Flags().StringVar(&db, "db", "", "database name, see `dbgw dbs` (required)")
	cmd.Flags().StringVar(&reason, "reason", "", "why you run this query, recorded in the audit log (required)")
	cmd.Flags().StringVarP(&format, "format", "o", formatTable, "output format: table, json or csv")
	cmd.Flags().StringVarP(&file, "file", "f", "", "read the SQL from a file (- for standard input)")
	_ = cmd.MarkFlagRequired("db")
	_ = cmd.MarkFlagRequired("reason")
	return cmd
}

// readSQL returns the statement from the arguments, --file or stdin.
func readSQL(cmd *cobra.Command, args []string, file string) (string, error) {
	var sql string
	switch {
	case file != "" && len(args) > 0:
		return "", errors.New("pass the SQL either as an argument or with --file, not both")
	case len(args) > 0:
		sql = strings.Join(args, " ")
	case file != "" && file != "-":
		f, err := os.Open(file)
		if err != nil {
			return "", err
		}
		defer f.Close()
		if sql, err = readLimited(f); err != nil {
			return "", fmt.Errorf("%s: %w", file, err)
		}
	default:
		in := cmd.InOrStdin()
		if f, ok := in.(*os.File); ok && file == "" {
			if fi, err := f.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
				return "", errors.New("no SQL: pass it as an argument, with --file, or on standard input")
			}
		}
		var err error
		if sql, err = readLimited(in); err != nil {
			return "", fmt.Errorf("standard input: %w", err)
		}
	}
	sql = strings.TrimSpace(sql)
	if sql == "" {
		return "", errors.New("the SQL is empty")
	}
	return sql, nil
}

func readLimited(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxSQLBytes+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxSQLBytes {
		return "", fmt.Errorf("the SQL is larger than %d bytes", maxSQLBytes)
	}
	return string(b), nil
}

// queryJSON is the --format json output of `dbgw query`.
type queryJSON struct {
	Status          string       `json:"status"`
	RequestID       string       `json:"request_id"`
	Columns         []columnJSON `json:"columns,omitzero"`
	Rows            [][]any      `json:"rows,omitzero"`
	RowCount        *int64       `json:"row_count,omitempty"`
	TotalRows       *int64       `json:"total_rows,omitempty"`
	Truncated       bool         `json:"truncated,omitzero"`
	RowsAffected    *int64       `json:"rows_affected,omitempty"`
	BreakGlass      bool         `json:"break_glass,omitzero"`
	Notice          string       `json:"notice,omitempty"`
	Stage           string       `json:"stage,omitempty"`
	Rule            string       `json:"rule,omitempty"`
	Reason          string       `json:"reason,omitempty"`
	Hint            string       `json:"hint,omitempty"`
	Code            string       `json:"code,omitempty"`
	Approvers       []string     `json:"approvers,omitzero"`
	ApprovalURL     string       `json:"approval_url,omitempty"`
	ExpireTime      *time.Time   `json:"expire_time,omitempty"`
	Risk            string       `json:"risk,omitempty"`
	ApprovalRule    string       `json:"approval_rule,omitempty"`
	MaxAffectedRows int64        `json:"max_affected_rows,omitzero"`
}

type columnJSON struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Masked   bool   `json:"masked,omitzero"`
	Withheld bool   `json:"withheld,omitzero"`
	Class    string `json:"class,omitempty"`
}

func executeStatusName(s dbgatewayv1.ExecuteStatus) string {
	switch s {
	case dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_OK:
		return "ok"
	case dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_DENIED:
		return "denied"
	case dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_PENDING:
		return "pending"
	}
	return "error"
}

func toQueryJSON(r *dbgatewayv1.ExecuteSQLResponse) *queryJSON {
	out := &queryJSON{
		Status: executeStatusName(r.Status), RequestID: r.RequestId, TotalRows: r.TotalRows, Truncated: r.Truncated,
		RowsAffected: r.RowsAffected, BreakGlass: r.BreakGlass, Notice: r.Notice, Stage: r.Stage, Rule: r.Rule, Reason: r.Reason,
		Hint: r.Hint, Code: r.Code, Approvers: r.Approvers, ApprovalURL: r.ApprovalUrl, Risk: r.Risk, ApprovalRule: r.ApprovalRule,
		MaxAffectedRows: r.MaxAffectedRows,
	}
	if r.Status == dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_OK {
		out.Columns, out.Rows = []columnJSON{}, rowValues(r.Rows)
		n := r.RowCount
		out.RowCount = &n
		for _, c := range r.Columns {
			out.Columns = append(out.Columns, columnJSON{Name: c.Name, Type: c.Type, Masked: c.Masked, Withheld: c.Withheld, Class: c.Class})
		}
	}
	if r.ExpireTime != nil {
		t := r.ExpireTime.AsTime()
		out.ExpireTime = &t
	}
	return out
}

// printExecute prints a query result and returns the exit status as an
// *ExitCodeError for anything but success. Results go to stdout; denials,
// errors, approval information and notes go to stderr, so stdout stays
// machine-readable for csv and json.
func printExecute(out, errw io.Writer, format string, r *dbgatewayv1.ExecuteSQLResponse) error {
	if format == formatJSON {
		if err := writeJSON(out, toQueryJSON(r)); err != nil {
			return err
		}
	}
	switch r.Status {
	case dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_OK:
		if err := printRows(out, errw, format, r); err != nil {
			return err
		}
		if r.BreakGlass {
			fmt.Fprintln(errw, "note: executed without approval under break-glass elevation (recorded in the audit log).")
		}
		return nil
	case dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_DENIED:
		fmt.Fprintf(errw, "denied: %s\n", sanitize(r.Reason))
		if r.Hint != "" {
			fmt.Fprintf(errw, "hint: %s\n", sanitize(r.Hint))
		}
		fmt.Fprintf(errw, "(rule: %s, stage: %s, request: %s)\n", dash(r.Rule), dash(r.Stage), r.RequestId)
		return &ExitCodeError{Code: ExitDenied}
	case dbgatewayv1.ExecuteStatus_EXECUTE_STATUS_PENDING:
		fmt.Fprintln(errw, "Submitted for approval. The write has NOT run yet; dbgateway runs it once approved.")
		w := tabwriter.NewWriter(errw, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  request:\t%s\n", r.RequestId)
		fmt.Fprintf(w, "  approve at:\t%s\n", r.ApprovalUrl)
		if len(r.Approvers) > 0 {
			fmt.Fprintf(w, "  approvers:\t%s\n", strings.Join(r.Approvers, ", "))
		}
		if r.ExpireTime != nil {
			fmt.Fprintf(w, "  expires:\t%s\n", r.ExpireTime.AsTime().Local().Format(time.DateTime))
		}
		if r.Risk != "" {
			fmt.Fprintf(w, "  risk:\t%s (approval rule %s, max affected rows %d)\n", r.Risk, dash(r.ApprovalRule), r.MaxAffectedRows)
		}
		_ = w.Flush()
		fmt.Fprintf(errw, "Check its status with `dbgw request %s`.\n", r.RequestId)
		return &ExitCodeError{Code: ExitPending}
	}
	msg := sanitize(r.Reason)
	if msg == "" {
		msg = "the statement failed"
	}
	if r.Code != "" {
		msg += " (SQLSTATE " + r.Code + ")"
	}
	fmt.Fprintf(errw, "error: %s\n(request: %s)\n", msg, r.RequestId)
	return &ExitCodeError{Code: ExitFailure}
}

func printRows(out, errw io.Writer, format string, r *dbgatewayv1.ExecuteSQLResponse) error {
	switch format {
	case formatJSON:
		return nil // already printed
	case formatCSV:
		if err := resultCSV(out, r.Columns, r.Rows); err != nil {
			return err
		}
		var masked []string
		for _, c := range r.Columns {
			if c.Masked || c.Withheld {
				masked = append(masked, sanitize(c.Name))
			}
		}
		if len(masked) > 0 {
			fmt.Fprintf(errw, "note: masked or withheld columns: %s\n", strings.Join(masked, ", "))
		}
		if r.Truncated {
			fmt.Fprintf(errw, "note: %s\n", truncationNote(r))
		}
		return nil
	}
	if len(r.Columns) > 0 {
		if err := resultTable(out, r.Columns, r.Rows, r.RowCount); err != nil {
			return err
		}
	}
	if r.RowsAffected != nil {
		fmt.Fprintf(out, "(%d rows affected)\n", *r.RowsAffected)
	}
	if r.Truncated {
		fmt.Fprintln(out, truncationNote(r))
	}
	return nil
}

func truncationNote(r *dbgatewayv1.ExecuteSQLResponse) string {
	msg := fmt.Sprintf("Result truncated: only the first %d rows are shown", r.RowCount)
	if r.TotalRows != nil {
		msg += fmt.Sprintf(" (of %d)", *r.TotalRows)
	}
	msg += ". Narrow the query or aggregate."
	return msg
}

// ExplainCmd is `dbgw explain`.
func ExplainCmd() *cobra.Command {
	var server, db, format, file string
	cmd := &cobra.Command{
		Use:   "explain --db NAME [SQL | -f FILE]",
		Short: "Show what dbgateway would do with a SQL statement, without running it",
		Long: `Evaluate a statement exactly like ` + "`dbgw query`" + ` (role, analysis, data classes,
risk, policy, approval rule) without executing it. Only the planner estimate
(EXPLAIN) may run.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkFormat(format, formatTable, formatJSON); err != nil {
				return err
			}
			sql, err := readSQL(cmd, args, file)
			if err != nil {
				return err
			}
			c, err := loggedIn(server)
			if err != nil {
				return err
			}
			resp, err := gatewayServiceClient(c).ExplainPolicy(cmd.Context(), connect.NewRequest(&dbgatewayv1.ExplainPolicyRequest{Database: db, Sql: sql}))
			if err != nil {
				return apiError(err)
			}
			if format == formatJSON {
				return writeProtoJSON(cmd.OutOrStdout(), resp.Msg)
			}
			return printExplain(cmd.OutOrStdout(), resp.Msg)
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "dbgateway URL (default: the logged-in server)")
	cmd.Flags().StringVar(&db, "db", "", "database name, see `dbgw dbs` (required)")
	cmd.Flags().StringVarP(&format, "format", "o", formatTable, "output format: table or json")
	cmd.Flags().StringVarP(&file, "file", "f", "", "read the SQL from a file (- for standard input)")
	_ = cmd.MarkFlagRequired("db")
	return cmd
}

func decisionName(d dbgatewayv1.PolicyDecision) string {
	switch d {
	case dbgatewayv1.PolicyDecision_POLICY_DECISION_ALLOW:
		return "allow"
	case dbgatewayv1.PolicyDecision_POLICY_DECISION_APPROVE:
		return "approve (runs after approval)"
	}
	return "deny"
}

func printExplain(out io.Writer, r *dbgatewayv1.ExplainPolicyResponse) error {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Decision:\t%s\n", decisionName(r.Decision))
	if r.Rule != "" {
		fmt.Fprintf(w, "Rule:\t%s (stage %s)\n", sanitize(r.Rule), dash(r.Stage))
	}
	if r.Risk != "" {
		fmt.Fprintf(w, "Risk:\t%s\n", r.Risk)
	}
	if r.Reason != "" {
		fmt.Fprintf(w, "Reason:\t%s\n", sanitize(r.Reason))
	}
	if r.Hint != "" {
		fmt.Fprintf(w, "Hint:\t%s\n", sanitize(r.Hint))
	}
	if r.ShadowDeniedBy != "" {
		fmt.Fprintf(w, "Shadow mode:\twould be denied by %s\n", sanitize(r.ShadowDeniedBy))
	}
	if r.RequiresSpecificReason {
		fmt.Fprintf(w, "Reason required:\ta specific --reason is required by the policy\n")
	}
	if st := r.Statement; st != nil {
		kind := st.Kind
		if st.IsWrite {
			kind += " (write)"
		}
		fmt.Fprintf(w, "Statement:\t%s on %s\n", kind, dash(sanitize(strings.Join(st.Tables, ", "))))
	}
	if r.Estimate != nil {
		fmt.Fprintf(w, "Estimate:\t%s rows (cost %s)\n", formatNumber(r.Estimate.Rows), formatNumber(r.Estimate.Cost))
	}
	if r.ApprovalRule != "" {
		line := r.ApprovalRule
		if r.ExpireAfter != nil {
			line += ", expires after " + r.ExpireAfter.AsDuration().String()
		}
		if r.MaxAffectedRows > 0 {
			line += fmt.Sprintf(", max affected rows %d", r.MaxAffectedRows)
		}
		fmt.Fprintf(w, "Approval rule:\t%s\n", sanitize(line))
		for i, s := range r.ApprovalSteps {
			fmt.Fprintf(w, "  step %d:\t%s\n", i+1, stepText(s))
		}
		fmt.Fprintf(w, "Approvers:\t%s\n", dash(strings.Join(r.Approvers, ", ")))
	}
	if r.BreakGlass {
		fmt.Fprintf(w, "Break-glass:\tactive; the write would run immediately without approval\n")
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if len(r.Output) > 0 {
		fmt.Fprintln(out, "Output columns:")
		w = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, o := range r.Output {
			treatment := "shown"
			switch {
			case o.Withheld:
				treatment = "withheld " + markWithheld
			case o.Masked:
				treatment = "masked " + markMasked
			}
			fmt.Fprintf(w, "  %s\t%s\t%s\n", sanitize(o.Name), dash(o.Class), treatment)
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func stepText(s *dbgatewayv1.ApprovalStep) string {
	who := "role " + s.Role
	if s.Group != "" {
		who = "group " + s.Group
	}
	if s.Count > 1 {
		who += fmt.Sprintf(" (%d approvals)", s.Count)
	}
	return sanitize(who)
}
