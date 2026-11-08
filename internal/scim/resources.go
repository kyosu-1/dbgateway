package scim

import (
	"encoding/json"
	"net/mail"
	"strings"

	"github.com/kyosu-1/dbgateway/internal/store"
)

// boolish is a boolean that also accepts the strings "true" and "false"
// in any case (Entra ID sends "False" in PATCH values).
type boolish bool

func (b *boolish) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case bool:
		*b = boolish(x)
		return nil
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "true":
			*b = true
			return nil
		case "false":
			*b = false
			return nil
		}
	}
	return badRequest("invalidValue", "expected a boolean, got %s", data)
}

type nameAttr struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

type emailAttr struct {
	Value   string  `json:"value"`
	Type    string  `json:"type,omitempty"`
	Primary boolish `json:"primary,omitempty"`
}

type metaAttr struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
}

// refAttr is a reference to another resource (user.groups, group.members).
type refAttr struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
	Type    string `json:"type,omitempty"`
}

// userResource is the SCIM User representation. Attributes that are not
// listed here (phoneNumbers, title, enterprise extension, ...) are accepted
// and ignored.
type userResource struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	Name        *nameAttr   `json:"name,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Emails      []emailAttr `json:"emails,omitempty"`
	Active      *boolish    `json:"active,omitempty"`
	Groups      []refAttr   `json:"groups,omitempty"` // read-only
	Meta        *metaAttr   `json:"meta,omitempty"`
}

// groupResource is the SCIM Group representation. Members is nil when
// members are excluded (or, on input, not given).
type groupResource struct {
	Schemas     []string   `json:"schemas"`
	ID          string     `json:"id,omitempty"`
	ExternalID  string     `json:"externalId,omitempty"`
	DisplayName string     `json:"displayName"`
	Members     *[]refAttr `json:"members,omitempty"`
	Meta        *metaAttr  `json:"meta,omitempty"`
}

func (h *handler) userLocation(id string) string  { return h.base + "/Users/" + id }
func (h *handler) groupLocation(id string) string { return h.base + "/Groups/" + id }

func (h *handler) toUserResource(u *store.SCIMUser) userResource {
	active := boolish(u.Active)
	res := userResource{
		Schemas:     []string{schemaUser},
		ID:          u.ID,
		ExternalID:  u.ExternalID,
		UserName:    u.UserName,
		DisplayName: u.DisplayName,
		Active:      &active,
		Meta: &metaAttr{
			ResourceType: "User",
			Created:      timestamp(u.CreatedAt),
			LastModified: timestamp(u.UpdatedAt),
			Location:     h.userLocation(u.ID),
		},
	}
	if u.GivenName != "" || u.FamilyName != "" || u.FormattedName != "" {
		res.Name = &nameAttr{Formatted: u.FormattedName, FamilyName: u.FamilyName, GivenName: u.GivenName}
	}
	for _, e := range u.Emails {
		res.Emails = append(res.Emails, emailAttr{Value: e.Value, Type: e.Type, Primary: boolish(e.Primary)})
	}
	for _, g := range u.Groups {
		res.Groups = append(res.Groups, refAttr{Value: g.ID, Display: g.DisplayName, Ref: h.groupLocation(g.ID), Type: "direct"})
	}
	return res
}

func (h *handler) toGroupResource(g *store.SCIMGroup) groupResource {
	res := groupResource{
		Schemas:     []string{schemaGroup},
		ID:          g.ID,
		ExternalID:  g.ExternalID,
		DisplayName: g.DisplayName,
		Meta: &metaAttr{
			ResourceType: "Group",
			Created:      timestamp(g.CreatedAt),
			LastModified: timestamp(g.UpdatedAt),
			Location:     h.groupLocation(g.ID),
		},
	}
	if g.Members != nil {
		members := make([]refAttr, 0, len(g.Members))
		for _, m := range g.Members {
			members = append(members, refAttr{Value: m.UserID, Display: m.UserName, Ref: h.userLocation(m.UserID), Type: "User"})
		}
		res.Members = &members
	}
	return res
}

// setUserFields copies the writable attributes of a POST/PUT body into u.
// active is only changed when given, so that a PUT without it never
// reactivates a deactivated user.
func setUserFields(u *store.SCIMUser, in *userResource) error {
	if strings.TrimSpace(in.UserName) == "" {
		return badRequest("invalidValue", "userName is required")
	}
	u.UserName = strings.TrimSpace(in.UserName)
	u.ExternalID = in.ExternalID
	u.DisplayName = in.DisplayName
	u.GivenName, u.FamilyName, u.FormattedName = "", "", ""
	if in.Name != nil {
		u.GivenName, u.FamilyName, u.FormattedName = in.Name.GivenName, in.Name.FamilyName, in.Name.Formatted
	}
	u.Emails = nil
	for _, e := range in.Emails {
		u.Emails = append(u.Emails, store.SCIMEmail{Value: strings.TrimSpace(e.Value), Type: e.Type, Primary: bool(e.Primary)})
	}
	if in.Active != nil {
		u.Active = bool(*in.Active)
	}
	return setIdentity(u)
}

// setIdentity derives the dbgateway identity (email) of a SCIM user: the
// primary email, else the "work" email, else the first email, else
// userName if it is an email address.
func setIdentity(u *store.SCIMUser) error {
	var candidate string
	for _, pick := range []func(store.SCIMEmail) bool{
		func(e store.SCIMEmail) bool { return e.Primary },
		func(e store.SCIMEmail) bool { return strings.EqualFold(e.Type, "work") },
		func(store.SCIMEmail) bool { return true },
	} {
		for _, e := range u.Emails {
			if e.Value != "" && pick(e) {
				candidate = e.Value
				break
			}
		}
		if candidate != "" {
			break
		}
	}
	if candidate == "" {
		candidate = u.UserName
	}
	email, ok := normalizeEmail(candidate)
	if !ok {
		return badRequest("invalidValue", "the user needs an email address (primary email or an email userName); got %q", candidate)
	}
	u.Email = email
	return nil
}

// normalizeEmail accepts a bare addr-spec and lower-cases it, like the
// OIDC login does.
func normalizeEmail(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 254 {
		return "", false
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" {
		return "", false
	}
	return strings.ToLower(s), true
}
