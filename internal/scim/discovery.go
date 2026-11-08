package scim

import "net/http"

// Discovery endpoints (RFC 7644 §4). They describe only what this server
// implements.

func (h *handler) serviceProviderConfig(w http.ResponseWriter, id string) error {
	if id != "" {
		return errNotFound("unknown endpoint")
	}
	supported := func(b bool) map[string]any { return map[string]any{"supported": b} }
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas":        []string{schemaSPConfig},
		"patch":          supported(true),
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": maxCount},
		"changePassword": supported(false),
		"sort":           supported(false),
		"etag":           supported(false),
		"authenticationSchemes": []map[string]any{{
			"type":        "oauthbearertoken",
			"name":        "Bearer token",
			"description": "A static bearer token configured with scim.token_env",
			"primary":     true,
		}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": h.base + "/ServiceProviderConfig"},
	})
	return nil
}

func (h *handler) resourceTypeList() []map[string]any {
	rt := func(name, endpoint, schema string) map[string]any {
		return map[string]any{
			"schemas":     []string{schemaResourceType},
			"id":          name,
			"name":        name,
			"endpoint":    endpoint,
			"description": name,
			"schema":      schema,
			"meta":        map[string]any{"resourceType": "ResourceType", "location": h.base + "/ResourceTypes/" + name},
		}
	}
	return []map[string]any{rt("User", "/Users", schemaUser), rt("Group", "/Groups", schemaGroup)}
}

func (h *handler) resourceTypes(w http.ResponseWriter, id string) error {
	return h.writeDiscoveryList(w, id, h.resourceTypeList())
}

func (h *handler) schemas(w http.ResponseWriter, id string) error {
	return h.writeDiscoveryList(w, id, h.schemaList())
}

// writeDiscoveryList writes the whole list, or the item whose id matches.
func (h *handler) writeDiscoveryList(w http.ResponseWriter, id string, items []map[string]any) error {
	if id != "" {
		for _, it := range items {
			if it["id"] == id {
				writeJSON(w, http.StatusOK, it)
				return nil
			}
		}
		return errNotFound("unknown resource")
	}
	resp := listResponse{Schemas: []string{schemaListResponse}, TotalResults: len(items), StartIndex: 1, ItemsPerPage: len(items)}
	for _, it := range items {
		resp.Resources = append(resp.Resources, it)
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

type attrDef struct {
	name, typ, mutability, uniqueness string
	required, multi, caseExact        bool
	sub                               []attrDef
}

func (a attrDef) render() map[string]any {
	m := map[string]any{
		"name":        a.name,
		"type":        a.typ,
		"multiValued": a.multi,
		"required":    a.required,
		"caseExact":   a.caseExact,
		"mutability":  a.mutability,
		"returned":    "default",
		"uniqueness":  a.uniqueness,
	}
	if m["mutability"] == "" {
		m["mutability"] = "readWrite"
	}
	if m["uniqueness"] == "" {
		m["uniqueness"] = "none"
	}
	if len(a.sub) > 0 {
		subs := make([]map[string]any, 0, len(a.sub))
		for _, s := range a.sub {
			subs = append(subs, s.render())
		}
		m["subAttributes"] = subs
	}
	return m
}

func (h *handler) schemaList() []map[string]any {
	schema := func(id, name string, attrs []attrDef) map[string]any {
		list := make([]map[string]any, 0, len(attrs))
		for _, a := range attrs {
			list = append(list, a.render())
		}
		return map[string]any{
			"schemas":    []string{schemaSchema},
			"id":         id,
			"name":       name,
			"attributes": list,
			"meta":       map[string]any{"resourceType": "Schema", "location": h.base + "/Schemas/" + id},
		}
	}
	str := func(name string) attrDef { return attrDef{name: name, typ: "string"} }
	user := []attrDef{
		{name: "userName", typ: "string", required: true, uniqueness: "server"},
		str("externalId"),
		str("displayName"),
		{name: "name", typ: "complex", sub: []attrDef{str("formatted"), str("familyName"), str("givenName")}},
		{name: "emails", typ: "complex", multi: true, sub: []attrDef{str("value"), str("type"), {name: "primary", typ: "boolean"}}},
		{name: "active", typ: "boolean"},
		{name: "groups", typ: "complex", multi: true, mutability: "readOnly", sub: []attrDef{
			{name: "value", typ: "string", mutability: "readOnly"}, {name: "display", typ: "string", mutability: "readOnly"},
		}},
	}
	group := []attrDef{
		{name: "displayName", typ: "string", required: true, uniqueness: "server"},
		str("externalId"),
		{name: "members", typ: "complex", multi: true, sub: []attrDef{
			{name: "value", typ: "string", mutability: "immutable"}, {name: "display", typ: "string", mutability: "readOnly"},
		}},
	}
	return []map[string]any{schema(schemaUser, "User", user), schema(schemaGroup, "Group", group)}
}
