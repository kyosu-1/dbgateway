# Security Policy

dbgateway is a gatekeeper in front of production databases, so we take
vulnerabilities seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through
[GitHub Security Advisories](https://github.com/kyosu-1/dbgateway/security/advisories/new).

Include, if you can:

- the affected version or commit,
- a description of the issue and its impact (for example a SQL statement that
  bypasses the parse-stage checks, a masking bypass, or an authorization flaw),
- steps to reproduce.

We aim to acknowledge reports within 3 business days and to agree on a
disclosure timeline with you.

## Scope

What dbgateway does and does not protect against is described in the
threat model section of [docs/security.md](docs/security.md). In short:

- In scope: anything that lets a statement reach the database without the
  configured checks (parser bypasses, multi-statement tricks, side-effect
  functions), masked or `no_ai` data reaching a client, privilege escalation
  between humans and agents, audit log tampering that `dbgw audit verify`
  does not detect, OAuth/token flaws.
- Out of scope: data an agent exfiltrates through other tools after it was
  legitimately returned, functions executed inside views or triggers (the
  database's own GRANTs are the last line of defense), and malicious
  dbgateway administrators (detectable through the audit hash chain, not
  preventable).

## Hardening reminders

- Give dbgateway a database user with `SELECT` only; never a superuser.
- Use `sslmode: verify-full` for production databases.
- Terminate TLS in front of dbgateway and do not expose it to the internet.
- Never enable `auth.dev_login` outside a developer machine.
