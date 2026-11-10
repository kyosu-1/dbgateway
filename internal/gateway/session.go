package gateway

import (
	"strings"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

// Session identity settings (databases[].session_identity). They are set
// with set_config(..., true), so they last for the transaction only, and
// callers cannot change them: SET and set_config are refused by analysis.
const (
	SettingUser      = "dbgateway.user"       // the person (for agents, the person they act for)
	SettingKind      = "dbgateway.kind"       // human | agent
	SettingAgent     = "dbgateway.agent"      // agent name; empty for people
	SettingGroups    = "dbgateway.groups"     // comma-separated groups
	SettingRequestID = "dbgateway.request_id" // the request (audit log and approval ID)
)

// sessionIdentity returns the settings describing p for request id on db,
// or nil when db does not enable them.
func sessionIdentity(db *config.Database, p *identity.Principal, id string) []analysis.Setting {
	if db == nil || !db.SessionIdentity || p == nil {
		return nil
	}
	return []analysis.Setting{
		{Name: SettingUser, Value: strings.ToLower(p.Human)},
		{Name: SettingKind, Value: string(p.Kind)},
		{Name: SettingAgent, Value: p.Agent},
		{Name: SettingGroups, Value: strings.Join(p.Groups, ",")},
		{Name: SettingRequestID, Value: id},
	}
}
