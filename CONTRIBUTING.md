# Contributing to dbgateway

Thanks for your interest! Bug reports, documentation fixes and pull requests are welcome.

## Before you start

- **Security issues:** do not open a public issue; see [SECURITY.md](SECURITY.md).
- **Larger changes** (new features, new database adapters, behavior changes in analysis or policy): please open an issue first so we can agree on the approach.
- Read [Design decisions](docs/design-decisions.md) and the [security model](docs/security.md). Changes must keep the safety properties described there — for example, never auto-allow writes and refuse what cannot be fully analyzed.

## Development setup

Requirements: Go (see `go.mod`) with cgo, Docker, and [buf](https://buf.build) for protobuf changes.

```sh
make build             # bin/dbgw
make test              # unit tests
make test-integration  # starts PostgreSQL in Docker and runs integration tests
make lint              # go vet, gofmt, buf lint
make run-dev           # run locally with examples/dev/dbgateway.yaml
```

MySQL integration tests use `examples/dev/mysql/compose.yaml`.

Other parts of the repository:

| Path | What | Commands |
| --- | --- | --- |
| `proto/` | connectRPC API | `make generate` (commit the generated `gen/`) |
| `web/editor/` | SQL editor bundle | `npm ci && npm run build` (commit `internal/web/ui/static/editor.js`) |
| `docs/` | documentation site (VitePress) | `npm ci && npm run dev` |
| `internal/web/i18n/messages/` | UI strings | add every key to both `en.json` and `ja.json` |

## Pull requests

- Keep changes focused and include tests. Analysis and policy changes need test cases for both the allowed and the refused side; bypass attempts belong in the adapters' bypass test suites.
- Run `make lint test` (and `make test-integration` when you touch adapters, the store or the audit log) before pushing.
- Update the docs when behavior or configuration changes, and add an entry to [CHANGELOG.md](CHANGELOG.md) under *Unreleased*.
- Write commit messages in the imperative mood ("Add …", "Fix …") with a short summary line.

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
