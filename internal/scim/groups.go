package scim

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/kyosu-1/dbgateway/internal/store"
)

func (h *handler) groups(w http.ResponseWriter, r *http.Request, id string) error {
	switch {
	case id == "" && r.Method == http.MethodGet:
		return h.listGroups(w, r)
	case id == "" && r.Method == http.MethodPost:
		return h.createGroup(w, r)
	case id == "":
		return errMethod()
	}
	switch r.Method {
	case http.MethodGet:
		g, err := h.store.GetSCIMGroup(r.Context(), id, !excludesMembers(r))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, h.toGroupResource(g))
		return nil
	case http.MethodPut:
		return h.replaceGroup(w, r, id)
	case http.MethodPatch:
		return h.patchGroup(w, r, id)
	case http.MethodDelete:
		if err := h.store.DeleteSCIMGroup(r.Context(), id, h.now()); err != nil {
			return err
		}
		h.log.Info("scim: group deleted", "id", id)
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	return errMethod()
}

func (h *handler) listGroups(w http.ResponseWriter, r *http.Request) error {
	start, count, err := paging(r)
	if err != nil {
		return err
	}
	var f store.SCIMGroupFilter
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
			case "displayname":
				dst = &f.DisplayName
			case "externalid":
				dst = &f.ExternalID
			case "members", "members.value":
				dst = &f.MemberID
			default:
				return badRequest("invalidFilter", "filtering on %q is not supported (supported: id, displayName, externalId, members.value)", t.attr)
			}
			if *dst != "" && !strings.EqualFold(*dst, t.value) {
				empty = true
			}
			*dst = t.value
		}
	}
	groups, total := []*store.SCIMGroup(nil), 0
	if !empty {
		if groups, total, err = h.store.ListSCIMGroups(r.Context(), f, start-1, count, !excludesMembers(r)); err != nil {
			return err
		}
	}
	resp := listResponse{Schemas: []string{schemaListResponse}, TotalResults: total, StartIndex: start, Resources: []any{}}
	for _, g := range groups {
		resp.Resources = append(resp.Resources, h.toGroupResource(g))
	}
	resp.ItemsPerPage = len(resp.Resources)
	writeJSON(w, http.StatusOK, resp)
	return nil
}

func (h *handler) createGroup(w http.ResponseWriter, r *http.Request) error {
	var in groupResource
	if err := decode(r, &in); err != nil {
		return err
	}
	name := strings.TrimSpace(in.DisplayName)
	if name == "" {
		return badRequest("invalidValue", "displayName is required")
	}
	g := &store.SCIMGroup{ID: newID(), DisplayName: name, ExternalID: in.ExternalID}
	if in.Members != nil {
		var err error
		if g.Members, err = toMembers(*in.Members); err != nil {
			return err
		}
	}
	if err := h.store.CreateSCIMGroup(r.Context(), g, h.now()); err != nil {
		return err
	}
	h.log.Info("scim: group created", "id", g.ID, "displayName", g.DisplayName, "members", len(g.Members))
	created, err := h.store.GetSCIMGroup(r.Context(), g.ID, true)
	if err != nil {
		return err
	}
	w.Header().Set("Location", h.groupLocation(g.ID))
	writeJSON(w, http.StatusCreated, h.toGroupResource(created))
	return nil
}

// replaceGroup handles PUT. Members are replaced when the body has a
// members attribute and kept otherwise (Okta renames groups with a PUT
// that may omit members).
func (h *handler) replaceGroup(w http.ResponseWriter, r *http.Request, id string) error {
	var in groupResource
	if err := decode(r, &in); err != nil {
		return err
	}
	name := strings.TrimSpace(in.DisplayName)
	if name == "" {
		return badRequest("invalidValue", "displayName is required")
	}
	var members []store.SCIMMember
	if in.Members != nil {
		var err error
		if members, err = toMembers(*in.Members); err != nil {
			return err
		}
	}
	g, err := h.store.UpdateSCIMGroup(r.Context(), id, h.now(), func(g *store.SCIMGroup) error {
		g.DisplayName, g.ExternalID = name, in.ExternalID
		if in.Members != nil {
			g.Members = members
		}
		return nil
	})
	if err != nil {
		return err
	}
	h.log.Info("scim: group replaced", "id", g.ID, "displayName", g.DisplayName, "members", len(g.Members))
	if excludesMembers(r) {
		g.Members = nil
	}
	writeJSON(w, http.StatusOK, h.toGroupResource(g))
	return nil
}

// patchGroup applies PATCH operations and answers 204 No Content (RFC 7644
// §3.5.2 allows it; returning large member lists is wasteful).
func (h *handler) patchGroup(w http.ResponseWriter, r *http.Request, id string) error {
	ops, err := decodePatch(r)
	if err != nil {
		return err
	}
	g, err := h.store.UpdateSCIMGroup(r.Context(), id, h.now(), func(g *store.SCIMGroup) error {
		for _, op := range ops {
			if err := h.applyGroupOp(g, op); err != nil {
				return err
			}
		}
		if strings.TrimSpace(g.DisplayName) == "" {
			return badRequest("invalidValue", "displayName cannot be empty")
		}
		return nil
	})
	if err != nil {
		return err
	}
	h.log.Info("scim: group patched", "id", g.ID, "displayName", g.DisplayName, "members", len(g.Members))
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *handler) applyGroupOp(g *store.SCIMGroup, op patchOp) error {
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
			if err := h.setGroupAttr(g, op.Op, ap, obj[k]); err != nil {
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
		return removeGroupAttr(g, ap, op.Value)
	}
	return h.setGroupAttr(g, op.Op, ap, op.Value)
}

func (h *handler) setGroupAttr(g *store.SCIMGroup, op string, ap attrPath, raw json.RawMessage) error {
	simple := ap.filter == nil && ap.sub == ""
	switch ap.attr {
	case "displayname":
		s, err := decodeString(raw)
		if err != nil || !simple || strings.TrimSpace(s) == "" {
			return badRequest("invalidValue", "displayName must be a non-empty string")
		}
		g.DisplayName = strings.TrimSpace(s)
	case "externalid":
		s, err := decodeString(raw)
		if err != nil || !simple {
			return badRequest("invalidValue", "externalId must be a string")
		}
		g.ExternalID = s
	case "members":
		if !simple {
			return badRequest("invalidPath", "members filters are only supported with remove")
		}
		list, err := decodeMembers(raw)
		if err != nil {
			return err
		}
		if op == "replace" {
			g.Members = list
			return nil
		}
		for _, m := range list {
			if !slices.ContainsFunc(g.Members, func(x store.SCIMMember) bool { return x.UserID == m.UserID }) {
				g.Members = append(g.Members, m)
			}
		}
	case "id":
		// Okta repeats the id in path-less replace operations.
	default:
		h.log.Debug("scim: ignoring unsupported group attribute", "path", ap.attr)
	}
	return nil
}

func removeGroupAttr(g *store.SCIMGroup, ap attrPath, raw json.RawMessage) error {
	switch ap.attr {
	case "displayname":
		return badRequest("invalidValue", "displayName cannot be removed")
	case "externalid":
		g.ExternalID = ""
	case "members":
		switch {
		case ap.filter != nil:
			if ap.filter.attr != "value" || ap.sub != "" {
				return badRequest("invalidFilter", `only members[value eq "id"] is supported`)
			}
			g.Members = slices.DeleteFunc(g.Members, func(m store.SCIMMember) bool { return m.UserID == ap.filter.value })
		case isNull(raw):
			g.Members = nil // remove all members
		default:
			list, err := decodeMembers(raw)
			if err != nil {
				return err
			}
			g.Members = slices.DeleteFunc(g.Members, func(m store.SCIMMember) bool {
				return slices.ContainsFunc(list, func(x store.SCIMMember) bool { return x.UserID == m.UserID })
			})
		}
	}
	return nil
}

func decodeMembers(raw json.RawMessage) ([]store.SCIMMember, error) {
	var list []refAttr
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '{' {
		var one refAttr
		if err := json.Unmarshal(raw, &one); err != nil {
			return nil, badRequest("invalidValue", "invalid members value")
		}
		list = []refAttr{one}
	} else if err := json.Unmarshal(raw, &list); err != nil {
		return nil, badRequest("invalidValue", "invalid members value")
	}
	return toMembers(list)
}

func toMembers(list []refAttr) ([]store.SCIMMember, error) {
	out := make([]store.SCIMMember, 0, len(list))
	for _, m := range list {
		if m.Value == "" {
			return nil, badRequest("invalidValue", "member without value")
		}
		if m.Type != "" && !strings.EqualFold(m.Type, "User") {
			return nil, badRequest("invalidValue", "only users can be group members (nested groups are not supported)")
		}
		out = append(out, store.SCIMMember{UserID: m.Value})
	}
	return out, nil
}
