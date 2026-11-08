package config

import "os"

// minSCIMTokenLen is the shortest SCIM bearer token accepted without a
// warning. The handler rejects every request when the token is empty.
const minSCIMTokenLen = 32

// SCIM configures the SCIM 2.0 provisioning endpoint (/scim/v2).
//
//	scim:
//	  enabled: true
//	  token_env: DBGW_SCIM_TOKEN
type SCIM struct {
	Enabled bool `yaml:"enabled"`
	// TokenEnv names the environment variable holding the bearer token the
	// IdP presents. The token itself is never written in the file.
	TokenEnv string `yaml:"token_env"`
}

func (s *SCIM) validate(c *Config, add func(string, ...any)) {
	if !s.Enabled {
		return
	}
	if s.TokenEnv == "" {
		add("scim.token_env: required when scim.enabled is true")
		return
	}
	switch tok := os.Getenv(s.TokenEnv); {
	case tok == "":
		c.warn("scim.token_env: %s is not set; every SCIM request will be rejected", s.TokenEnv)
	case len(tok) < minSCIMTokenLen:
		c.warn("scim.token_env: %s is shorter than %d characters; use a long random token", s.TokenEnv, minSCIMTokenLen)
	}
}
