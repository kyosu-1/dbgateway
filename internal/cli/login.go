package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

const cliClientID = "dbgw-cli"

// LoginCmd is `dbgw login`: device authorization flow, then save the human
// token locally.
func LoginCmd() *cobra.Command {
	var server string
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to a dbgateway server (device flow)",
		Long: "Log in to a dbgateway server. Opens the browser to confirm a code, then saves\n" +
			"the credentials to the user config directory (dbgw/credentials.json).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			saved, _ := loadCredentials()
			s, err := resolveServer(server, saved)
			if err != nil {
				return err
			}
			return login(cmd.Context(), cmd.ErrOrStderr(), s, !noBrowser)
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "dbgateway URL (default: $DBGW_SERVER or the saved server)")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "do not try to open a browser")
	return cmd
}

func login(ctx context.Context, out io.Writer, server string, browser bool) error {
	meta, err := discover(ctx, server)
	if err != nil {
		return err
	}
	conf := &oauth2.Config{
		ClientID: cliClientID,
		Scopes:   []string{"db:read"},
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: meta.DeviceAuthorizationEndpoint,
			TokenURL:      meta.TokenEndpoint,
			AuthStyle:     oauth2.AuthStyleInParams,
		},
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Timeout: 30 * time.Second})
	da, err := conf.DeviceAuth(ctx)
	if err != nil {
		return fmt.Errorf("start login: %w", err)
	}
	verify := da.VerificationURIComplete
	if verify == "" {
		verify = da.VerificationURI
	}
	fmt.Fprintf(out, "To log in, open this URL in your browser:\n\n  %s\n\nand confirm the code: %s\n\n", verify, da.UserCode)
	if browser && sameOrigin(server, verify) {
		openBrowser(verify)
	}
	fmt.Fprintln(out, "Waiting for confirmation...")
	tok, err := conf.DeviceAccessToken(ctx, da)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if !strings.HasPrefix(tok.AccessToken, "dbgw_at_") || tok.Expiry.IsZero() {
		return fmt.Errorf("unexpected token from server")
	}
	if err := saveCredentials(&Credentials{Server: server, AccessToken: tok.AccessToken, ExpiresAt: tok.Expiry}); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}
	fmt.Fprintf(out, "Logged in to %s (valid until %s).\n", server, tok.Expiry.Local().Format(time.DateTime))
	return nil
}

// openBrowser tries to open u; failures are ignored (the URL is printed).
func openBrowser(u string) {
	if pu, err := url.Parse(u); err != nil || (pu.Scheme != "https" && pu.Scheme != "http") {
		return
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	if err := cmd.Start(); err == nil {
		go cmd.Wait()
	}
}

// LogoutCmd is `dbgw logout`: revoke the saved token (and the agent tokens
// minted from it) and delete the credentials.
func LogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out and revoke the saved credentials",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := loadCredentials()
			if err != nil {
				return err
			}
			if c == nil {
				fmt.Fprintln(cmd.ErrOrStderr(), "Not logged in.")
				return nil
			}
			if c.Valid() {
				if err := revokeToken(cmd.Context(), c); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not revoke the token on the server: %v\n", err)
				}
			}
			if err := deleteCredentials(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Logged out of %s.\n", c.Server)
			return nil
		},
	}
}

func revokeToken(ctx context.Context, c *Credentials) error {
	meta, err := discover(ctx, c.Server)
	if err != nil {
		return err
	}
	if meta.RevocationEndpoint == "" {
		return fmt.Errorf("server has no revocation endpoint")
	}
	form := url.Values{"token": {c.AccessToken}, "client_id": {cliClientID}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.RevocationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revocation status %d", resp.StatusCode)
	}
	return nil
}
