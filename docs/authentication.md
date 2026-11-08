# Authentication

dbgateway always knows which person is behind a request. People sign in through the browser; the CLI gets a person's token through the device flow; AI agents get short-lived tokens that a person authorized and that never exceed that person's permissions. There are no passwords and no database credentials for users to hold.

dbgateway is its own OAuth authorization server. Upstream identity comes from an OIDC provider, passkeys, or both.

## People

### Signing in

| Method | Configuration | Use |
| --- | --- | --- |
| OIDC (SSO) | `auth.oidc` | The default for teams. Authorization code flow with PKCE and nonce. The email comes from the ID token (an `email_verified: false` claim is refused); groups come from `groups_claim` (default `groups`), or from the userinfo endpoint if the ID token lacks them |
| Passkeys | `auth.passkeys: true` | Sign-in with a passkey, so dbgateway can run without an IdP |
| Dev login | `auth.dev_login: true` | Any email, no password. Local development only; refused unless dbgateway listens on loopback |

IdP groups are mapped to dbgateway groups with `groups[].oidc_group`; without an IdP, list `members` on a group. The person's IdP groups are stored at login, and roles are resolved from them and the current configuration on every request.

### Passkeys

Passkeys (WebAuthn, user verification required) serve two purposes: sign-in (with `auth.passkeys`) and step-up authentication (always available when the public URL has a usable host name).

- **First passkey without an IdP.** An administrator runs `dbgw passkey enroll --email person@example.com` on the server. It prints a one-time enrollment link, valid for 24 hours, which signs the person in once they register a passkey.
- **More passkeys.** People add and remove passkeys on the account page (`/account`). Adding one requires a fresh step-up.

### Sessions

The browser session is an `HttpOnly`, `SameSite=Lax` cookie (`Secure` over HTTPS) that lasts `auth.session_ttl` (default 1 hour). Only a hash of the session ID is stored. Forms carry a CSRF token derived from the session.

### Step-up authentication

Approving a write, taking a break-glass elevation and adding a passkey require re-verifying the person right before the action:

- a passkey, or
- an IdP re-authentication (`prompt=login`, `max_age=0`; the ID token's `auth_time` must be recent), or
- with dev login only, a confirmation button.

The time and method are recorded on the session and in the approval. Approvals accept a step-up no older than `approvals.step_up_max_age` (default 5 minutes).

### The account page

`/account` lists the agents the person has authorized (with a revoke button), their passkeys, and Slack account linking (see [Notifications](./notifications)).

## Agents

### OAuth for MCP clients

MCP clients follow the standard MCP authorization flow:

1. A call to `/mcp` without a token returns `401` with the protected resource metadata URL (`/.well-known/oauth-protected-resource/mcp`), which points to the authorization server metadata (`/.well-known/oauth-authorization-server`).
2. The client identifies itself, either with a **Client ID Metadata Document** (its `client_id` is an HTTPS URL; preferred) or through **dynamic client registration** (`/register`, kept as a fallback). Metadata documents are fetched with SSRF protection: HTTPS only, no redirects, bounded time and size, and no private or loopback addresses. The consent page marks verified metadata, and labels a registered client's name as self-reported. All clients are public; PKCE with `S256` is required, and the `resource` parameter, if sent, must be `<public_url>/mcp`.
3. The person signs in and sees the consent page. They give the agent a name, which is recorded in the audit log, select the databases it may use (only ones they can read), and optionally tick "Request writes to the selected databases" to grant `db:write`. That option appears only when approvals are enabled and the person holds `writer` on a selected database.
4. The client exchanges the code for an agent token. Authorization codes last 60 seconds and are single-use; a replayed code revokes the tokens it issued.

The agent's identity is the token: the name given at consent and the OAuth client ID. The name the client reports about itself is recorded but never used for decisions.

### Agent tokens

| Property | Value |
| --- | --- |
| Audience | `<public_url>/mcp` only. Agent tokens are rejected elsewhere, and human tokens are rejected at `/mcp` |
| Scopes | `db:read` (schema and reads); `db:write` (submit writes for approval) |
| Databases | The explicit list chosen at consent or creation |
| Lifetime | `auth.agent_tokens.max_ttl` (default 1 hour, at most 24 hours) |
| Refresh | Only with `auth.agent_tokens.refresh`. Refresh tokens rotate on use; reusing an old one revokes the whole family. A family lasts at most 7 days |

On every request the agent's principal is rebuilt from the token and the current configuration: the person's current roles, narrowed by the token's scopes and databases, and never `approver` or `admin`. Role changes and revocations therefore apply immediately. Agents cannot approve requests, including their own person's.

Tokens are opaque random values with a recognizable prefix (`dbgw_at_`, `dbgw_rt_`) so secret scanners can find them; only their SHA-256 is stored.

## CLI

```sh
dbgw login --server https://dbgw.example.com
```

`dbgw login` uses the OAuth device authorization grant: it prints a code and opens `/device`, where the signed-in person checks that the codes match and allows the sign-in. The resulting human token lasts `auth.cli_token_ttl` (default 12 hours) and is saved in the user config directory (`dbgw/credentials.json`, mode `0600`). Commands refuse to send it to a server other than the one it was issued by. `dbgw logout` revokes it on the server, together with agent tokens minted from it.

The human token works with the connectRPC API (`dbgw query`, `dbgw requests`, ...; see [CLI](./cli)) but not with `/mcp`, so an AI client can never act with a person's unrestricted identity. For agents, the CLI mints agent tokens from it:

```sh
dbgw token create --agent ci-report --databases dev-main --ttl 1h [--write]
dbgw token list [--all]
dbgw token revoke <id>
dbgw mcp stdio --databases prod-main --agent my-agent [--write]   # mints and renews automatically
```

Minted agent tokens are capped at `auth.agent_tokens.max_ttl` and at the remaining lifetime of the person's CLI token, and have no refresh token. Revoking a token also revokes every token derived from it. Only people can mint, list or revoke tokens.

## Deactivating people

With SCIM, deactivating or deleting a user in the IdP revokes all their tokens (including agent and refresh tokens derived from them), deletes their browser sessions and locks the account; every token check also refuses deactivated users. See [SCIM](./scim).

Without SCIM, removing someone from the IdP stops new sign-ins, but tokens already issued stay valid until they expire (agent tokens within `max_ttl`, CLI tokens within `cli_token_ttl`, refresh-token families up to 7 days) unless they are revoked.
