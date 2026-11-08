package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"

	dbgatewayv1 "github.com/kyosu-1/dbgateway/gen/dbgateway/v1"
)

// RequestsCmd is `dbgw requests`.
func RequestsCmd() *cobra.Command {
	var server, scope, db, format string
	var limit int
	cmd := &cobra.Command{
		Use:   "requests",
		Short: "List approval requests",
		Long: `List approval requests, newest first.

  --scope mine      requests by you or your agents (default)
  --scope awaiting  pending requests you can approve
  --scope decided   requests that are no longer pending`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkFormat(format, formatTable, formatJSON); err != nil {
				return err
			}
			var s dbgatewayv1.RequestScope
			switch scope {
			case "mine":
				s = dbgatewayv1.RequestScope_REQUEST_SCOPE_MINE
			case "awaiting", "awaiting_me", "awaiting-me":
				s = dbgatewayv1.RequestScope_REQUEST_SCOPE_AWAITING_ME
			case "decided":
				s = dbgatewayv1.RequestScope_REQUEST_SCOPE_DECIDED
			default:
				return fmt.Errorf("unknown --scope %q (use mine, awaiting or decided)", scope)
			}
			if limit < 0 || limit > 200 {
				return fmt.Errorf("--limit must be between 1 and 200")
			}
			c, err := loggedIn(server)
			if err != nil {
				return err
			}
			resp, err := gatewayServiceClient(c).ListRequests(cmd.Context(), connect.NewRequest(&dbgatewayv1.ListRequestsRequest{
				Scope: s, Database: db, Limit: int32(limit),
			}))
			if err != nil {
				return apiError(err)
			}
			if format == formatJSON {
				return writeProtoJSON(cmd.OutOrStdout(), resp.Msg)
			}
			if len(resp.Msg.Requests) == 0 {
				fmt.Fprintln(cmd.ErrOrStderr(), "No requests.")
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSTATUS\tDATABASE\tREQUESTER\tRISK\tCREATED\tSQL")
			for _, r := range resp.Msg.Requests {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", sanitize(r.Id), requestStatus(r), sanitize(r.Database), requesterText(r.Requester),
					dash(r.Risk), localTime(r.CreateTime), sanitize(truncateText(r.NormalizedSql, 60)))
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "dbgateway URL (default: the logged-in server)")
	cmd.Flags().StringVar(&scope, "scope", "mine", "mine, awaiting or decided")
	cmd.Flags().StringVar(&db, "db", "", "only requests on this database")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum number of requests (default 50, max 200)")
	cmd.Flags().StringVarP(&format, "format", "o", formatTable, "output format: table or json")
	return cmd
}

// RequestCmd is `dbgw request ID`, with the cancel and reject subcommands.
func RequestCmd() *cobra.Command {
	var server, format string
	cmd := &cobra.Command{
		Use:   "request ID",
		Short: "Show an approval request (or cancel / reject one)",
		Long: `Show an approval request, including its result once it has run.

Approving is only possible in the web UI, because an approval requires a
fresh passkey or IdP re-authentication.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkFormat(format, formatTable, formatJSON); err != nil {
				return err
			}
			c, err := loggedIn(server)
			if err != nil {
				return err
			}
			resp, err := gatewayServiceClient(c).GetRequest(cmd.Context(), connect.NewRequest(&dbgatewayv1.GetRequestRequest{Id: args[0]}))
			if err != nil {
				return apiError(err)
			}
			if format == formatJSON {
				return writeProtoJSON(cmd.OutOrStdout(), resp.Msg)
			}
			return printRequest(cmd.OutOrStdout(), resp.Msg.Request)
		},
	}
	cmd.PersistentFlags().StringVar(&server, "server", "", "dbgateway URL (default: the logged-in server)")
	cmd.Flags().StringVarP(&format, "format", "o", formatTable, "output format: table or json")
	cmd.AddCommand(requestCancelCmd(&server), requestRejectCmd(&server))
	return cmd
}

func requestCancelCmd(server *string) *cobra.Command {
	return &cobra.Command{
		Use:   "cancel ID",
		Short: "Withdraw one of your pending requests",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := loggedIn(*server)
			if err != nil {
				return err
			}
			resp, err := gatewayServiceClient(c).CancelRequest(cmd.Context(), connect.NewRequest(&dbgatewayv1.CancelRequestRequest{Id: args[0]}))
			if err != nil {
				return apiError(err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Canceled %s.\n", sanitize(resp.Msg.Request.GetId()))
			return nil
		},
	}
}

func requestRejectCmd(server *string) *cobra.Command {
	var comment string
	cmd := &cobra.Command{
		Use:   "reject ID",
		Short: "Reject a pending request you can approve",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := loggedIn(*server)
			if err != nil {
				return err
			}
			resp, err := gatewayServiceClient(c).RejectRequest(cmd.Context(), connect.NewRequest(&dbgatewayv1.RejectRequestRequest{Id: args[0], Comment: comment}))
			if err != nil {
				return apiError(err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Rejected %s.\n", sanitize(resp.Msg.Request.GetId()))
			return nil
		},
	}
	cmd.Flags().StringVar(&comment, "comment", "", "comment shown to the requester (why it was rejected)")
	return cmd
}

func approvalStatusName(s dbgatewayv1.ApprovalStatus) string {
	if s == dbgatewayv1.ApprovalStatus_APPROVAL_STATUS_UNSPECIFIED {
		return "unknown"
	}
	return strings.ToLower(strings.TrimPrefix(s.String(), "APPROVAL_STATUS_"))
}

func requestStatus(r *dbgatewayv1.ApprovalRequest) string {
	s := approvalStatusName(r.Status)
	if r.Status == dbgatewayv1.ApprovalStatus_APPROVAL_STATUS_PENDING && len(r.Steps) > 1 {
		s += fmt.Sprintf(" (step %d/%d)", r.CurrentStep+1, len(r.Steps))
	}
	return s
}

func requesterText(r *dbgatewayv1.Requester) string {
	if r == nil {
		return "-"
	}
	if r.Kind == dbgatewayv1.TokenKind_TOKEN_KIND_AGENT {
		return sanitize(fmt.Sprintf("%s (agent for %s)", r.Agent, r.Human))
	}
	return sanitize(r.Human)
}

func localTime(t *timestamppb.Timestamp) string {
	if t == nil {
		return "-"
	}
	return t.AsTime().Local().Format(time.DateTime)
}

func printRequest(out io.Writer, r *dbgatewayv1.ApprovalRequest) error {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "ID:\t%s\n", sanitize(r.Id))
	fmt.Fprintf(w, "Status:\t%s\n", requestStatus(r))
	fmt.Fprintf(w, "Database:\t%s\n", sanitize(r.Database))
	fmt.Fprintf(w, "Requester:\t%s\n", requesterText(r.Requester))
	fmt.Fprintf(w, "Reason:\t%s\n", sanitize(r.Reason))
	fmt.Fprintf(w, "Statement:\t%s on %s (estimate %s rows, max affected rows %d)\n", dash(r.Kind), dash(sanitize(strings.Join(r.Tables, ", "))),
		formatNumber(r.EstimateRows), r.MaxAffectedRows)
	fmt.Fprintf(w, "Risk:\t%s\n", dash(r.Risk))
	fmt.Fprintf(w, "Approval rule:\t%s\n", dash(sanitize(r.ApprovalRule)))
	for i, s := range r.Steps {
		var by []string
		for _, a := range r.Approvals {
			if int(a.Step) == i {
				by = append(by, fmt.Sprintf("%s at %s", sanitize(a.Approver), localTime(a.ApproveTime)))
			}
		}
		state := "waiting"
		switch {
		case len(by) > 0:
			state = "approved by " + strings.Join(by, ", ")
		case i > int(r.CurrentStep):
			state = "-"
		}
		fmt.Fprintf(w, "  step %d:\t%s: %s\n", i+1, stepText(s), state)
	}
	fmt.Fprintf(w, "Created:\t%s\n", localTime(r.CreateTime))
	fmt.Fprintf(w, "Expires:\t%s\n", localTime(r.ExpireTime))
	if r.DecideTime != nil {
		line := localTime(r.DecideTime)
		if r.DecidedBy != "" {
			line += " by " + sanitize(r.DecidedBy)
		}
		fmt.Fprintf(w, "Decided:\t%s\n", line)
	}
	if r.Comment != "" {
		fmt.Fprintf(w, "Comment:\t%s\n", sanitize(r.Comment))
	}
	if r.StartTime != nil {
		fmt.Fprintf(w, "Started:\t%s\n", localTime(r.StartTime))
	}
	if r.FinishTime != nil {
		fmt.Fprintf(w, "Finished:\t%s\n", localTime(r.FinishTime))
	}
	fmt.Fprintf(w, "URL:\t%s\n", sanitize(r.Url))
	if err := w.Flush(); err != nil {
		return err
	}
	sql := r.Sql
	if sql == "" {
		sql = r.NormalizedSql
	}
	fmt.Fprintln(out, "SQL:")
	for _, line := range strings.Split(sql, "\n") {
		fmt.Fprintf(out, "  %s\n", sanitize(line))
	}
	if res := r.Result; res != nil {
		fmt.Fprintf(out, "Result: %d rows affected in %s\n", res.RowsAffected, res.Duration.AsDuration())
		if res.Error != "" {
			msg := sanitize(res.Error)
			if res.Code != "" {
				msg += " (SQLSTATE " + res.Code + ")"
			}
			fmt.Fprintf(out, "Error: %s\n", msg)
		}
		if len(res.Columns) > 0 {
			if err := resultTable(out, res.Columns, res.Rows, res.RowCount); err != nil {
				return err
			}
		}
	}
	if r.Status == dbgatewayv1.ApprovalStatus_APPROVAL_STATUS_PENDING {
		fmt.Fprintln(out, "Approvers approve it in the web UI (URL above).")
	}
	return nil
}
