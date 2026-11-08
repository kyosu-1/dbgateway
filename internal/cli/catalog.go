package cli

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	dbgatewayv1 "github.com/kyosu-1/dbgateway/gen/dbgateway/v1"
)

// DatabasesCmd is `dbgw dbs`.
func DatabasesCmd() *cobra.Command {
	var server, format string
	cmd := &cobra.Command{
		Use:     "dbs",
		Aliases: []string{"databases"},
		Short:   "List the databases you can use, with your permissions",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkFormat(format, formatTable, formatJSON); err != nil {
				return err
			}
			c, err := loggedIn(server)
			if err != nil {
				return err
			}
			resp, err := gatewayServiceClient(c).ListDatabases(cmd.Context(), connect.NewRequest(&dbgatewayv1.ListDatabasesRequest{}))
			if err != nil {
				return apiError(err)
			}
			if format == formatJSON {
				return writeProtoJSON(cmd.OutOrStdout(), resp.Msg)
			}
			if len(resp.Msg.Databases) == 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "%s has no access to any database.\n", resp.Msg.Principal)
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tTYPE\tROLES\tSEARCH\tREAD\tWRITE\tMAX_ROWS\tLABELS")
			for _, d := range resp.Msg.Databases {
				maxRows := "-"
				if d.MaxRows > 0 {
					maxRows = fmt.Sprint(d.MaxRows)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", sanitize(d.Name), sanitize(d.Type), dash(strings.Join(d.Roles, ",")),
					yesNo(d.CanSearch), yesNo(d.CanRead), writeText(d.CanWrite), maxRows, dash(sanitize(labels(d.Labels))))
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "dbgateway URL (default: the logged-in server)")
	cmd.Flags().StringVarP(&format, "format", "o", formatTable, "output format: table or json")
	return cmd
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func writeText(b bool) string {
	if b {
		return "approval"
	}
	return "no"
}

func labels(m map[string]string) string {
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}

// SearchCmd is `dbgw search`.
func SearchCmd() *cobra.Command {
	var server, db, schema, detail, format string
	var limit int
	cmd := &cobra.Command{
		Use:   "search --db NAME [KEYWORD]",
		Short: "Search tables, views and columns",
		Long: `Search tables, views and columns whose schema, table or column name contains
KEYWORD (everything when omitted). Columns masked for you are marked with *.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkFormat(format, formatTable, formatJSON); err != nil {
				return err
			}
			var d dbgatewayv1.ObjectDetail
			switch detail {
			case "names":
				d = dbgatewayv1.ObjectDetail_OBJECT_DETAIL_NAMES
			case "summary":
				d = dbgatewayv1.ObjectDetail_OBJECT_DETAIL_SUMMARY
			case "full":
				d = dbgatewayv1.ObjectDetail_OBJECT_DETAIL_FULL
			default:
				return fmt.Errorf("unknown --detail %q (use names, summary or full)", detail)
			}
			if limit < 0 || limit > 200 {
				return fmt.Errorf("--limit must be between 1 and 200")
			}
			keyword := ""
			if len(args) == 1 {
				keyword = args[0]
			}
			c, err := loggedIn(server)
			if err != nil {
				return err
			}
			resp, err := gatewayServiceClient(c).SearchObjects(cmd.Context(), connect.NewRequest(&dbgatewayv1.SearchObjectsRequest{
				Database: db, Keyword: keyword, Schema: schema, Detail: d, Limit: int32(limit),
			}))
			if err != nil {
				return apiError(err)
			}
			if format == formatJSON {
				return writeProtoJSON(cmd.OutOrStdout(), resp.Msg)
			}
			if err := printObjects(cmd.OutOrStdout(), resp.Msg.Objects); err != nil {
				return err
			}
			if len(resp.Msg.Objects) == 0 {
				fmt.Fprintln(cmd.ErrOrStderr(), "No matching objects.")
			}
			if resp.Msg.Truncated {
				fmt.Fprintln(cmd.ErrOrStderr(), "note: more objects matched; use a more specific keyword or --limit.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "dbgateway URL (default: the logged-in server)")
	cmd.Flags().StringVar(&db, "db", "", "database name, see `dbgw dbs` (required)")
	cmd.Flags().StringVar(&schema, "schema", "", "only this schema (system schemas are listed only when named)")
	cmd.Flags().StringVar(&detail, "detail", "summary", "names, summary (with columns) or full (with indexes, comments, row estimates)")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum number of objects (default 50, max 200)")
	cmd.Flags().StringVarP(&format, "format", "o", formatTable, "output format: table or json")
	_ = cmd.MarkFlagRequired("db")
	return cmd
}

func printObjects(out io.Writer, objs []*dbgatewayv1.SchemaObject) error {
	anyMasked := false
	for i, o := range objs {
		if i > 0 && len(o.Columns) > 0 {
			fmt.Fprintln(out)
		}
		line := fmt.Sprintf("%s.%s (%s)", sanitize(o.Schema), sanitize(o.Name), sanitize(o.Type))
		if o.RowEstimate != nil {
			line += fmt.Sprintf(" ~%d rows", *o.RowEstimate)
		}
		if o.Comment != "" {
			line += " -- " + sanitize(o.Comment)
		}
		fmt.Fprintln(out, line)
		if len(o.Columns) > 0 {
			w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			for _, c := range o.Columns {
				name := sanitize(c.Name)
				if c.Masked {
					name += markMasked
					anyMasked = true
				}
				null := "not null"
				if c.Nullable {
					null = "null"
				}
				fmt.Fprintf(w, "  %s\t%s\t%s\t%s", name, sanitize(c.Type), null, dash(sanitize(c.Class)))
				if c.Comment != "" {
					fmt.Fprintf(w, "\t-- %s", sanitize(c.Comment))
				}
				fmt.Fprintln(w)
			}
			if err := w.Flush(); err != nil {
				return err
			}
		}
		for _, ix := range o.Indexes {
			fmt.Fprintf(out, "  index %s: %s\n", sanitize(ix.Name), sanitize(ix.Definition))
		}
	}
	if anyMasked {
		fmt.Fprintf(out, "\n%s masked for you\n", markMasked)
	}
	return nil
}
