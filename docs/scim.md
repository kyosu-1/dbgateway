# Syncing users and groups with SCIM

dbgateway exposes SCIM 2.0 (RFC 7643 / RFC 7644) endpoints, so users and groups can be synced from Okta or Microsoft Entra ID. Synced groups are mapped to dbgateway groups through `groups[].oidc_group`, just like OIDC groups, and deactivating a user in the IdP immediately revokes their dbgateway sessions and tokens.

## Enabling

```yaml
scim:
  enabled: true
  token_env: DBGW_SCIM_TOKEN   # name of the environment variable holding the bearer token
```

- Use a long random token (for example `openssl rand -base64 48`). A token shorter than 32 characters produces a warning when the configuration is loaded
- If the environment variable is empty, every SCIM request is rejected with 401 (fail closed)
- With `enabled: false` (the default), everything under `/scim/v2/` returns 404
- Register the token only in the IdP's admin console and do not reuse it for anything else. It is compared in constant time

The endpoint base URL is `<server.public_url>/scim/v2` (for example `https://dbgw.example.com/scim/v2`).

## Supported scope

Support is limited to what Okta and Entra ID provisioning actually use.

| Resource | Operations |
| --- | --- |
| `/Users` | POST (create), GET (list; `filter` with `eq` and `and` on `userName`, `externalId`, `id`, `emails.value`, e.g. `filter=userName eq "..."`; `startIndex` / `count`), GET `/Users/{id}`, PUT (replace), PATCH (`add` / `replace` / `remove`), DELETE |
| `/Groups` | POST, GET (list; filter by `displayName`, `externalId`, `id`, `members[value eq "..."]`; `excludedAttributes=members`), GET `/Groups/{id}`, PUT, PATCH (add, remove and replace members; rename), DELETE |
| `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | GET (minimal content describing only the scope above) |

- Responses use the Content-Type `application/scim+json`; errors use the SCIM error format (`status`, `scimType`, `detail`)
- Not supported: Bulk, sorting, ETags, `/Me`, password changes, nested groups, `or`, and operators such as `co` / `sw`
- dbgateway stores only the user attributes `userName`, `externalId`, `name`, `displayName`, `emails` and `active`. Other attributes (`title`, `phoneNumbers`, the enterprise extension, etc.) are accepted and ignored
- Group PATCH returns 204 No Content. User PATCH returns the updated user
- The maximum `count` for lists is 200

## Mapping users

SCIM users are mapped to dbgateway users by **email address**. dbgateway uses the first of the following that exists (lowercased):

1. The `emails` entry with `primary: true`
2. The `emails` entry with `type: "work"`
3. The first `emails` entry
4. `userName` (if it looks like an email address)

This address must match the `email` claim of OIDC sign-in. In Okta they match by default. In Entra ID, `userName` is the UPN and `emails[type eq "work"].value` is the `mail` attribute, so the same value as the ID token's `email` claim (`mail`) is used.

If the email address changes, tokens and sessions of the old address are revoked and the old user's groups become empty.

## Mapping groups

The `displayName` of a SCIM group is treated as the IdP group name.

```yaml
groups:
  - name: analysts
    oidc_group: dbgw-analysts   # SCIM group name (treated the same as an OIDC group name)
```

Whenever a user's groups change (a group is created, deleted or renamed, members are added or removed, the user is activated or deactivated), the user's list of IdP groups (the one recorded at sign-in) is replaced with the set of `displayName`s of the SCIM groups they belong to. Permissions are computed from this list each time a token is verified, so changes take effect from the next request.

### Precedence over OIDC groups

- When SCIM is enabled and the user is synced through SCIM, **SCIM groups replace the groups from the ID token at sign-in**. The ID token's `groups` claim is not used, even on sign-in
- Users not synced through SCIM (for example, users who existed before SCIM was enabled) keep using the `groups` claim at sign-in
- When a user is created through SCIM, their IdP groups are empty until groups are synced. In Okta, configure both user assignment and group push
- Static `members` in the configuration apply independently of SCIM

## Deactivation and deletion

- For a user set to `active: false` (by PATCH, PUT or at creation) or deleted with DELETE, dbgateway does the following in a single transaction:
  - revokes all of the user's tokens (including agent tokens and refresh tokens issued from them)
  - deletes all browser sessions
  - clears the IdP groups
- Deactivated and deleted users cannot sign in, and their tokens cannot be used. A deleted user is no longer visible through SCIM, but the record is kept and stays locked. If the IdP creates the same user again, it becomes usable as a new user (revoked tokens are not restored)
- Disabling SCIM later does not unlock deactivated or deleted users

## IdP configuration

### Okta

1. In the application's "Provisioning", enable "SCIM"
2. SCIM connector base URL: `https://dbgw.example.com/scim/v2`
3. Unique identifier field for users: `userName` (or `email`)
4. Supported provisioning actions: "Push New Users", "Push Profile Updates", "Push Groups"
5. Authentication Mode: "HTTP Header", with the value of `DBGW_SCIM_TOKEN` as Authorization (Okta adds `Bearer`)
6. Under "To App", enable "Create Users", "Update User Attributes" and "Deactivate Users"
7. Under "Push Groups", push the groups named in `groups[].oidc_group`

### Microsoft Entra ID

1. In the enterprise application's "Provisioning", set the mode to "Automatic"
2. Tenant URL: `https://dbgw.example.com/scim/v2`
3. Secret token: the value of `DBGW_SCIM_TOKEN`
4. Check with "Test Connection"
5. The default attribute mappings work (`userName` ← `userPrincipalName`, `emails[type eq "work"].value` ← `mail`, `active` ← `Switch([IsSoftDeleted], ...)`). Removing mappings for attributes dbgateway does not store avoids a diff on every sync
6. Under "Users and groups", assign the groups to sync. Make sure group names match `groups[].oidc_group`

## Checks on the authentication side (implementation notes)

To stop users deactivated through SCIM, authentication does the following:

- At sign-in (OIDC or passkey): calls `Store.RecordLogin(ctx, email, idTokenGroups, now, cfg.SCIM.Enabled)` and refuses the sign-in if it returns `store.ErrUserInactive`
- When verifying a token and when using a session: refuses if `Store.UserActive(ctx, email)` returns false (also refuses on error)

Both the SQLite and PostgreSQL management databases implement these methods.
