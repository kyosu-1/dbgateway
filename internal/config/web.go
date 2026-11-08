package config

import (
	"fmt"
	"net/mail"
	"slices"
	"strings"
)

// Auditor grants read access to the audit log screen (/audit) and the user
// screens (/users) of the web UI. Exactly one of User (an e-mail address)
// or Group (a dbgateway group) is set. People with the admin role on any
// database have the same access.
//
//	auditors:
//	  - group: security
//	  - user: bob@example.com
type Auditor struct {
	User  string `yaml:"user"`
	Group string `yaml:"group"`
}

func (c *Config) validateAuditors(groupNames map[string]bool, add func(string, ...any)) {
	for i, a := range c.Auditors {
		p := fmt.Sprintf("auditors[%d]", i)
		switch {
		case (a.User == "") == (a.Group == ""):
			add("%s: exactly one of user or group is required", p)
		case a.Group != "" && !groupNames[a.Group]:
			add("%s.group: unknown group %q", p, a.Group)
		case a.User != "":
			if addr, err := mail.ParseAddress(a.User); err != nil || addr.Address != a.User {
				add("%s.user: %q is not an e-mail address", p, a.User)
			}
		}
	}
}

// IsAuditor reports whether the human with the given e-mail and dbgateway
// groups is listed in auditors (directly or through a group).
func (c *Config) IsAuditor(email string, groups []string) bool {
	if email == "" {
		return false
	}
	for _, a := range c.Auditors {
		if a.User != "" && strings.EqualFold(a.User, email) {
			return true
		}
		if a.Group != "" && slices.Contains(groups, a.Group) {
			return true
		}
	}
	return false
}
