package config

import (
	"regexp"
	"strings"
)

// Endpoint authentication methods.
const (
	AuthPassword = "password"
	AuthAWSIAM   = "aws_iam"
	AuthGCPIAM   = "gcp_iam"
)

var awsRegionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)

// validateEndpointAuth checks the auth method of one endpoint. p is the
// path for messages (e.g. "databases[0].primary").
func validateEndpointAuth(p string, ep *Endpoint, add, warn func(string, ...any)) {
	switch ep.Auth {
	case AuthPassword:
		if ep.Region != "" {
			add("%s.region: only used with auth: aws_iam", p)
		}
		return
	case AuthAWSIAM, AuthGCPIAM:
	default:
		add("%s.auth: must be password, aws_iam or gcp_iam", p)
		return
	}

	if ep.PasswordEnv != "" || ep.WritePasswordEnv != "" {
		add("%s: password_env and write_password_env must not be set with auth: %s (a token is used instead)", p, ep.Auth)
	}
	// IAM tokens are bearer credentials: they must never be sent in
	// plaintext, so modes that may fall back to an unencrypted connection
	// are refused.
	switch ep.SSLMode {
	case "verify-full", "verify-ca":
	case "require":
		warn("%s.sslmode: require does not verify the server certificate, so the %s token could be intercepted; use verify-full (or verify-ca for a Cloud SQL per-instance CA)", p, ep.Auth)
	default:
		add("%s.sslmode: auth: %s requires TLS (require, verify-ca or verify-full)", p, ep.Auth)
	}

	switch ep.Auth {
	case AuthAWSIAM:
		if ep.Region != "" && !awsRegionPattern.MatchString(ep.Region) {
			add("%s.region: invalid AWS region %q", p, ep.Region)
		}
	case AuthGCPIAM:
		if ep.Region != "" {
			add("%s.region: only used with auth: aws_iam", p)
		}
		for _, u := range []struct{ field, user string }{{"read_user", ep.ReadUser}, {"write_user", ep.WriteUser}} {
			if strings.HasSuffix(u.user, ".gserviceaccount.com") {
				add("%s.%s: for a service account, use the email without the .gserviceaccount.com suffix (%q)", p, u.field, strings.TrimSuffix(u.user, ".gserviceaccount.com"))
			}
			if u.user != strings.ToLower(u.user) {
				add("%s.%s: Cloud SQL IAM database users are lowercase", p, u.field)
			}
		}
	}
}
