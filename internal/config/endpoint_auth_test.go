package config

import (
	"strings"
	"testing"
)

func parseWithPrimary(t *testing.T, primary string) (*Config, error) {
	t.Helper()
	return Parse([]byte(`
auth: { dev_login: true }
databases:
  - name: main
    primary: ` + primary + `
`))
}

func TestEndpointAuth(t *testing.T) {
	tests := []struct {
		name    string
		primary string
		wantErr string // empty: valid
		warn    string
	}{
		{"password", `{ host: db, read_user: r, password_env: PW }`, "", ""},
		{"aws_iam", `{ host: db, auth: aws_iam, read_user: dbgw_iam, region: ap-northeast-1 }`, "", ""},
		{"aws_iam default region", `{ host: db, auth: aws_iam, read_user: dbgw_iam }`, "", ""},
		{"aws_iam verify-ca", `{ host: db, auth: aws_iam, read_user: dbgw_iam, sslmode: verify-ca }`, "", ""},
		{"aws_iam require warns", `{ host: db, auth: aws_iam, read_user: dbgw_iam, sslmode: require }`, "", "could be intercepted"},
		{"aws_iam disable", `{ host: db, auth: aws_iam, read_user: dbgw_iam, sslmode: disable }`, "requires TLS", ""},
		{"aws_iam prefer", `{ host: db, auth: aws_iam, read_user: dbgw_iam, sslmode: prefer }`, "requires TLS", ""},
		{"aws_iam with password", `{ host: db, auth: aws_iam, read_user: dbgw_iam, password_env: PW }`, "must not be set", ""},
		{"aws_iam with write password", `{ host: db, auth: aws_iam, read_user: dbgw_iam, write_user: w, write_password_env: PW }`, "must not be set", ""},
		{"aws_iam bad region", `{ host: db, auth: aws_iam, read_user: dbgw_iam, region: Tokyo }`, "invalid AWS region", ""},
		{"gcp_iam", `{ host: 10.0.0.5, auth: gcp_iam, read_user: dbgw-sa@proj.iam, sslmode: verify-ca, sslrootcert: ca.pem }`, "", ""},
		{"gcp_iam user email", `{ host: db, auth: gcp_iam, read_user: alice@example.com }`, "", ""},
		{"gcp_iam full sa email", `{ host: db, auth: gcp_iam, read_user: dbgw-sa@proj.iam.gserviceaccount.com }`, "without the .gserviceaccount.com suffix", ""},
		{"gcp_iam uppercase", `{ host: db, auth: gcp_iam, read_user: Alice@example.com }`, "lowercase", ""},
		{"gcp_iam region", `{ host: db, auth: gcp_iam, read_user: a@b.c, region: asia-northeast1 }`, "only used with auth: aws_iam", ""},
		{"password region", `{ host: db, read_user: r, region: ap-northeast-1 }`, "only used with auth: aws_iam", ""},
		{"unknown", `{ host: db, read_user: r, auth: kerberos }`, "must be password, aws_iam or gcp_iam", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := parseWithPrimary(t, tt.primary)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if tt.warn != "" && !strings.Contains(strings.Join(c.Warnings, "\n"), tt.warn) {
					t.Errorf("warnings %q do not contain %q", c.Warnings, tt.warn)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestEndpointRegionParsed(t *testing.T) {
	c, err := parseWithPrimary(t, `{ host: db, auth: aws_iam, read_user: dbgw_iam, region: us-east-1 }`)
	if err != nil {
		t.Fatal(err)
	}
	if ep := c.Databases[0].Primary; ep.Region != "us-east-1" || ep.Auth != AuthAWSIAM {
		t.Errorf("endpoint = %+v", ep)
	}
}
