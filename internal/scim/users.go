package scim

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/kyosu-1/dbgateway/internal/store"
)

// maxPatchOps bounds the operations of one PATCH request.
const maxPatchOps = 1000

type patchRequest struct {
	Schemas    []string  `json:"schemas"`
	Operations []patchOp `json:"Operations"`
}

type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

func (h *handler) users(w http.ResponseWriter, r *http.Request, id string) error {
	switch {
	case id == "" && r.Method == http.MethodGet:
		return h.listUsers(w, r)
	case id == "" && r.Method == http.MethodPost:
		return h.createUser(w, r)
	case id == "":
		return errMethod()
	}
	switch r.Method {
	case http.MethodGet:
		u, err := h.store.GetSCIMUser(r.Context(), id)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, h.toUserResource(u))
		return nil
	case http.MethodPut:
		return h.replaceUser(w, r, id)
	case http.MethodPatch:
		return h.patchUser(w, r, id)
	case http.MethodDelete:
		if err := h.store.DeleteSCIMUser(r.Context(), id, h.now()); err != nil {
			return err
		}
		h.log.Info("scim: user deleted; tokens and sessions revoked", "id", id)
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	return errMethod()
}

func (h *handler) listUsers(w http.ResponseWriter, r *http.Request) error {
	start, count, err := paging(r)
	if err != nil {
		return err
	}
	var f store.SCIMUserFilter
	empty := false
	if expr := r.URL.Query().Get("filter"); expr != "" {
		terms, err := parseFilter(expr)
		if err != nil {
			return err
		}
		for _, t := range terms {
			var dst *string
			switch t.attr {
			case "id":
				dst = &f.ID
			case "username":
				dst = &f.UserName
			case "externalid":
				dst = &f.ExternalID
			case "emails", "emails.value":
				dst = &f.Email
			default:
				return badRequest("invalidFilter", "filtering on %q is not supported (supported: id, userName, externalId, emails.value)", t.attr)
			}
			if *dst != "" && !strings.EqualFold(*dst, t.value) {
				empty = true // contradictory terms
			}
			*dst = t.value
		}
	}
	users, total := []*store.SCIMUser(nil), 0
	if !empty {
		if users, total, err = h.store.ListSCIMUsers(r.Context(), f, start-1, count); err != nil {
			return err
		}
	}
	resp := listResponse{Schemas: []string{schemaListResponse}, TotalResults: total, StartIndex: start, Resources: []any{}}
	for _, u := range users {
		resp.Resources = append(resp.Resources, h.toUserResource(u))
	}
	resp.ItemsPerPage = len(resp.Resources)
	writeJSON(w, http.StatusOK, resp)
	return nil
}

func (h *handler) createUser(w http.ResponseWriter, r *http.Request) error {
	var in userResource
	if err := decode(r, &in); err != nil {
		return err
	}
	u := &store.SCIMUser{ID: newID(), Active: true}
	if err := setUserFields(u, &in); err != nil {
		return err
	}
	if err := h.store.CreateSCIMUser(r.Context(), u, h.now()); err != nil {
		return err
	}
	h.log.Info("scim: user created", "id", u.ID, "email", u.Email, "active", u.Active)
	created, err := h.store.GetSCIMUser(r.Context(), u.ID)
	if err != nil {
		return err
	}
	w.Header().Set("Location", h.userLocation(u.ID))
	writeJSON(w, http.StatusCreated, h.toUserResource(created))
	return nil
}

func (h *handler) replaceUser(w http.ResponseWriter, r *http.Request, id string) error {
	var in userResource
	if err := decode(r, &in); err != nil {
		return err
	}
	u, err := h.store.UpdateSCIMUser(r.Context(), id, h.now(), func(u *store.SCIMUser) error {
		return setUserFields(u, &in)
	})
	if err != nil {
		return err
	}
	h.log.Info("scim: user replaced", "id", u.ID, "email", u.Email, "active", u.Active)
	writeJSON(w, http.StatusOK, h.toUserResource(u))
	return nil
}

func (h *handler) patchUser(w http.ResponseWriter, r *http.Request, id string) error {
	ops, err := decodePatch(r)
	if err != nil {
		return err
	}
	u, err := h.store.UpdateSCIMUser(r.Context(), id, h.now(), func(u *store.SCIMUser) error {
		for _, op := range ops {
			if err := h.applyUserOp(u, op); err != nil {
				return err
			}
		}
		return setIdentity(u)
	})
	if err != nil {
		return err
	}
	h.log.Info("scim: user patched", "id", u.ID, "email", u.Email, "active", u.Active)
	writeJSON(w, http.StatusOK, h.toUserResource(u))
	return nil
}

func decodePatch(r *http.Request) ([]patchOp, error) {
	var req patchRequest
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if len(req.Operations) == 0 {
		return nil, badRequest("invalidSyntax", "Operations is required")
	}
	if len(req.Operations) > maxPatchOps {
		return nil, badRequest("tooMany", "at most %d operations per request", maxPatchOps)
	}
	for i := range req.Operations {
		op := strings.ToLower(req.Operations[i].Op)
		if op != "add" && op != "replace" && op != "remove" {
			return nil, badRequest("invalidSyntax", "unsupported op %q", req.Operations[i].Op)
		}
		req.Operations[i].Op = op
	}
	return req.Operations, nil
}

// applyUserOp applies one PATCH operation. Unknown and extension attributes
// are ignored (IdPs send many attributes dbgateway does not keep).
func (h *handler) applyUserOp(u *store.SCIMUser, op patchOp) error {
	if op.Path == "" {
		if op.Op == "remove" {
			return badRequest("noTarget", "remove requires a path")
		}
		obj, err := decodeObject(op.Value)
		if err != nil {
			return err
		}
		for _, k := range sortedKeys(obj) {
			ap, err := parsePath(k)
			if err != nil {
				return err
			}
			if err := h.setUserAttr(u, op.Op, ap, obj[k]); err != nil {
				return err
			}
		}
		return nil
	}
	ap, err := parsePath(op.Path)
	if err != nil {
		return err
	}
	if op.Op == "remove" {
		return removeUserAttr(u, ap, op.Value)
	}
	return h.setUserAttr(u, op.Op, ap, op.Value)
}

func (h *handler) setUserAttr(u *store.SCIMUser, op string, ap attrPath, raw json.RawMessage) error {
	simple := ap.filter == nil && ap.sub == ""
	switch ap.attr {
	case "active":
		if !simple {
			return badRequest("invalidPath", "invalid path for active")
		}
		var b boolish
		if err := json.Unmarshal(raw, &b); err != nil {
			return badRequest("invalidValue", "active must be a boolean")
		}
		u.Active = bool(b)
	case "username":
		s, err := decodeString(raw)
		if err != nil || !simple || strings.TrimSpace(s) == "" {
			return badRequest("invalidValue", "userName must be a non-empty string")
		}
		u.UserName = strings.TrimSpace(s)
	case "externalid", "displayname":
		s, err := decodeString(raw)
		if err != nil || !simple {
			return badRequest("invalidValue", "%s must be a string", ap.attr)
		}
		if ap.attr == "externalid" {
			u.ExternalID = s
		} else {
			u.DisplayName = s
		}
	case "name":
		return setName(u, ap, raw)
	case "emails":
		return setEmails(u, op, ap, raw)
	default:
		h.log.Debug("scim: ignoring unsupported user attribute", "path", ap.attr)
	}
	return nil
}

func setName(u *store.SCIMUser, ap attrPath, raw json.RawMessage) error {
	if ap.filter != nil {
		return badRequest("invalidPath", "name is not multi-valued")
	}
	if ap.sub == "" {
		// Merge the given sub-attributes (RFC 7644 §3.5.2.3).
		obj, err := decodeObject(raw)
		if err != nil {
			return err
		}
		for k, v := range obj {
			if err := setName(u, attrPath{attr: "name", sub: strings.ToLower(k)}, v); err != nil {
				return err
			}
		}
		return nil
	}
	s, err := decodeString(raw)
	if err != nil {
		return badRequest("invalidValue", "name.%s must be a string", ap.sub)
	}
	switch ap.sub {
	case "givenname":
		u.GivenName = s
	case "familyname":
		u.FamilyName = s
	case "formatted":
		u.FormattedName = s
	}
	return nil
}

func setEmails(u *store.SCIMUser, op string, ap attrPath, raw json.RawMessage) error {
	if ap.filter == nil {
		if ap.sub != "" {
			return badRequest("invalidPath", "emails.%s needs a filter, e.g. emails[type eq \"work\"].%s", ap.sub, ap.sub)
		}
		list, err := decodeEmails(raw)
		if err != nil {
			return err
		}
		if op == "replace" {
			u.Emails = nil
		}
		var modified []int
		for _, e := range list {
			i := slices.IndexFunc(u.Emails, func(x store.SCIMEmail) bool { return strings.EqualFold(x.Value, e.Value) })
			if i >= 0 {
				u.Emails[i] = e
			} else {
				i = len(u.Emails)
				u.Emails = append(u.Emails, e)
			}
			modified = append(modified, i)
		}
		fixPrimary(u, modified)
		return nil
	}
	match, err := emailMatcher(*ap.filter)
	if err != nil {
		return err
	}
	var modified []int
	for i := range u.Emails {
		if !match(u.Emails[i]) {
			continue
		}
		modified = append(modified, i)
		if err := setEmailField(&u.Emails[i], ap.sub, raw); err != nil {
			return err
		}
	}
	if len(modified) == 0 {
		// Create the entry the filter describes, e.g.
		// emails[type eq "work"].value = "x".
		var e store.SCIMEmail
		switch ap.filter.attr {
		case "type":
			e.Type = ap.filter.value
		case "value":
			e.Value = ap.filter.value
		case "primary":
			e.Primary = ap.filter.value == "true"
		}
		if err := setEmailField(&e, ap.sub, raw); err != nil {
			return err
		}
		modified = append(modified, len(u.Emails))
		u.Emails = append(u.Emails, e)
	}
	fixPrimary(u, modified)
	return nil
}

func setEmailField(e *store.SCIMEmail, sub string, raw json.RawMessage) error {
	switch sub {
	case "":
		var in emailAttr
		if err := json.Unmarshal(raw, &in); err != nil {
			return badRequest("invalidValue", "invalid email value")
		}
		if in.Value != "" {
			e.Value = strings.TrimSpace(in.Value)
		}
		if in.Type != "" {
			e.Type = in.Type
		}
		e.Primary = e.Primary || bool(in.Primary)
	case "value":
		s, err := decodeString(raw)
		if err != nil {
			return badRequest("invalidValue", "emails.value must be a string")
		}
		e.Value = strings.TrimSpace(s)
	case "type":
		s, err := decodeString(raw)
		if err != nil {
			return badRequest("invalidValue", "emails.type must be a string")
		}
		e.Type = s
	case "primary":
		var b boolish
		if err := json.Unmarshal(raw, &b); err != nil {
			return badRequest("invalidValue", "emails.primary must be a boolean")
		}
		e.Primary = bool(b)
	default:
		return badRequest("invalidPath", "unknown email sub-attribute %q", sub)
	}
	return nil
}

func removeUserAttr(u *store.SCIMUser, ap attrPath, raw json.RawMessage) error {
	switch ap.attr {
	case "active", "username":
		return badRequest("invalidValue", "%s cannot be removed", ap.attr)
	case "externalid":
		u.ExternalID = ""
	case "displayname":
		u.DisplayName = ""
	case "name":
		switch ap.sub {
		case "":
			u.GivenName, u.FamilyName, u.FormattedName = "", "", ""
		case "givenname":
			u.GivenName = ""
		case "familyname":
			u.FamilyName = ""
		case "formatted":
			u.FormattedName = ""
		}
	case "emails":
		if ap.filter != nil {
			match, err := emailMatcher(*ap.filter)
			if err != nil {
				return err
			}
			u.Emails = slices.DeleteFunc(u.Emails, match)
			return nil
		}
		if isNull(raw) {
			u.Emails = nil
			return nil
		}
		list, err := decodeEmails(raw)
		if err != nil {
			return err
		}
		u.Emails = slices.DeleteFunc(u.Emails, func(e store.SCIMEmail) bool {
			return slices.ContainsFunc(list, func(x store.SCIMEmail) bool { return strings.EqualFold(x.Value, e.Value) })
		})
	}
	return nil
}

func emailMatcher(f filterTerm) (func(store.SCIMEmail) bool, error) {
	switch f.attr {
	case "type":
		return func(e store.SCIMEmail) bool { return strings.EqualFold(e.Type, f.value) }, nil
	case "value":
		return func(e store.SCIMEmail) bool { return strings.EqualFold(e.Value, f.value) }, nil
	case "primary":
		want := f.value == "true"
		return func(e store.SCIMEmail) bool { return e.Primary == want }, nil
	}
	return nil, badRequest("invalidFilter", "unsupported email filter attribute %q", f.attr)
}

// fixPrimary keeps at most one primary email: if one of the entries just
// modified is primary, it wins over the others.
func fixPrimary(u *store.SCIMUser, modified []int) {
	keep := -1
	for _, i := range modified {
		if u.Emails[i].Primary {
			keep = i
			break
		}
	}
	if keep < 0 {
		keep = slices.IndexFunc(u.Emails, func(e store.SCIMEmail) bool { return e.Primary })
	}
	for i := range u.Emails {
		u.Emails[i].Primary = i == keep
	}
}

func decodeEmails(raw json.RawMessage) ([]store.SCIMEmail, error) {
	var list []emailAttr
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '{' {
		var one emailAttr
		if err := json.Unmarshal(raw, &one); err != nil {
			return nil, badRequest("invalidValue", "invalid emails value")
		}
		list = []emailAttr{one}
	} else if err := json.Unmarshal(raw, &list); err != nil {
		return nil, badRequest("invalidValue", "invalid emails value")
	}
	out := make([]store.SCIMEmail, 0, len(list))
	for _, e := range list {
		out = append(out, store.SCIMEmail{Value: strings.TrimSpace(e.Value), Type: e.Type, Primary: bool(e.Primary)})
	}
	return out, nil
}

func decodeObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, badRequest("invalidValue", "value must be an object when no path is given")
	}
	return obj, nil
}

// decodeString decodes a JSON string; null is "". Entra ID sometimes wraps
// single values in a one-element array of {"value": ...}; that is accepted.
func decodeString(raw json.RawMessage) (string, error) {
	if isNull(raw) {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var wrapped []struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil && len(wrapped) == 1 {
		return wrapped[0].Value, nil
	}
	return "", badRequest("invalidValue", "expected a string")
}

func isNull(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) == 0 || bytes.Equal(raw, []byte("null"))
}

func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
