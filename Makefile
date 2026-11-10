# dbgateway development tasks.
GO        ?= go
BIN       ?= bin/dbgw
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)
DEV_CFG   := examples/dev/dbgateway.yaml
COMPOSE   := docker compose -f examples/dev/compose.yaml

.PHONY: all build download serve-dev test test-race test-integration lint generate policy-test helm-check dev-db dev-db-down run-dev

all: lint test build

build: ## Build the dbgw binary (cgo is required by the PostgreSQL parser)
	CGO_ENABLED=1 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/dbgw

download: ## Download bin/dbgw from the newest release instead of building it
	sh scripts/download.sh

bin/dbgw:
	$(MAKE) build

test: ## Unit tests
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

test-integration: dev-db ## Integration tests against PostgreSQL in Docker
	$(GO) test -tags integration -count=1 ./...

lint: ## Static checks
	$(GO) vet ./...
	@test -z "$$(gofmt -l . | grep -v '^gen/')" || (gofmt -l . | grep -v '^gen/'; echo 'gofmt needed'; exit 1)
	buf lint

generate: ## Regenerate protobuf / connectRPC code
	buf generate

policy-test: build ## Run the repository's policy tests
	$(BIN) policy test testdata/policy/*.yaml

helm-check: build ## Lint and render the Helm chart, validate manifests (kubeconform) and the rendered configuration
	sh deploy/helm/check.sh

dev-db: ## Start the local PostgreSQL
	$(COMPOSE) up -d --wait

dev-db-down: ## Stop the local PostgreSQL and delete its data
	$(COMPOSE) down -v

run-dev: build serve-dev ## Build, then run dbgateway locally with the dev configuration

serve-dev: bin/dbgw dev-db ## Run the existing bin/dbgw (e.g. from `make download`) with the dev configuration
	DBGW_DEV_READER_PASSWORD=reader DBGW_DEV_WRITER_PASSWORD=writer $(BIN) serve --config $(DEV_CFG) --log-level debug
