# Quickstart

Run dbgateway on your machine against a sample PostgreSQL database, then query it from an AI agent and from the SQL editor.

## Prerequisites

- Docker, for the sample database
- Linux (amd64 or arm64) or macOS (Apple silicon) for the release binary; on other platforms, Go 1.27 or later with cgo (a C compiler) to build it

## 1. Start dbgateway

Get the repository (for the sample database and configuration) and the `dbgw` binary from the [latest release](https://github.com/kyosu-1/dbgateway/releases):

```sh
git clone --depth 1 https://github.com/kyosu-1/dbgateway.git
cd dbgateway
make download         # bin/dbgw from the latest release, checksum verified
make serve-dev
```

`make serve-dev` starts PostgreSQL 17 with sample data on `127.0.0.1:55432` and serves dbgateway on <http://127.0.0.1:8443> with [examples/dev/dbgateway.yaml](../examples/dev/dbgateway.yaml). With Go and cgo installed you can skip the download: `make run-dev` builds `bin/dbgw` from source and then does the same.

The development configuration enables **dev login**: you sign in with any e-mail address and no password. It only works while dbgateway listens on a loopback address — never use it elsewhere.

The sample configuration defines:

| User | Group | Can do |
| --- | --- | --- |
| `alice@example.com` | developers | read, request writes |
| `bob@example.com` | approvers | approve writes |

## 2. Connect an AI agent

For an MCP client with OAuth support, such as Claude Code:

```sh
claude mcp add --transport http dbgateway http://127.0.0.1:8443/mcp
```

On the first tool call a browser opens. Sign in as `alice@example.com`, choose the databases the agent may use, and (optionally) allow it to request writes.

For clients that only speak stdio, sign in with the CLI and let it relay:

```sh
bin/dbgw login --server http://127.0.0.1:8443
bin/dbgw mcp stdio --agent my-agent
```

Now ask the agent something like *"How many users are on each plan in dev-main?"*. It will call `search_objects` and `execute_sql`; `email` comes back masked.

## 3. Use the SQL editor

Open <http://127.0.0.1:8443/console>, sign in as `alice@example.com`, and run:

```sql
SELECT id, name, email, plan FROM users WHERE id < 5
```

with a reason such as `ticket #1234 investigation`. Try **Explain** (check the decision without running), the history panel, and export.

## 4. Request and approve a write

As `alice@example.com`, run:

```sql
UPDATE subscriptions SET plan = 'pro' WHERE user_id = 3
```

The write is not executed; it becomes an approval request. Sign in as `bob@example.com` in another browser profile, open **Approvals**, review the request and approve it. In dev mode the step-up check is a confirmation page; in production it is a passkey or IdP re-authentication.

## 5. Look at the audit log

Open **Audit log** as `bob@example.com` (listed under `auditors` in the sample configuration) to see every request, including denials. Verify the hash chain from the command line:

```sh
bin/dbgw audit verify --config examples/dev/dbgateway.yaml
```

## Next steps

- Write your own configuration: [Configuration](./configuration) and [Policies and roles](./policies)
- Roll out safely with shadow mode and policy tests: [Policies and roles](./policies)
- Run it for a team: [Deploying dbgateway](./deploy)
