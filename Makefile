GO      ?= go
SQLC    ?= $(shell command -v sqlc 2>/dev/null || echo $(HOME)/go/bin/sqlc)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
PKG     := github.com/ncecere/open-mcp-portal
LDFLAGS := -s -w -X $(PKG)/internal/buildinfo.Version=$(VERSION) -X $(PKG)/internal/buildinfo.Commit=$(COMMIT)

# Integration tests create one database per test on this server (a role
# allowed to create databases); they skip when it is unreachable.
export OMP_TEST_DATABASE_URL ?= postgres://omp:omp-dev-only@127.0.0.1:55442/postgres?sslmode=disable

# Kubernetes tooling, installed on first use into bin/k8s-tools/<version>/.
KUSTOMIZE_VERSION   ?= v5.8.1
KUBECONFORM_VERSION ?= v0.8.0
K8S_TOOLS   := $(CURDIR)/bin/k8s-tools
KUSTOMIZE   := $(K8S_TOOLS)/kustomize-$(KUSTOMIZE_VERSION)/kustomize
KUBECONFORM := $(K8S_TOOLS)/kubeconform-$(KUBECONFORM_VERSION)/kubeconform

.PHONY: build-omp docker-omp shellcheck smoke-selftest dev-seed help deps-up deps-down generate check-generated build run migrate fake-mcp fake-oauth example-mail example-mail-fake example-mail-smoke test test-action test-integration test-ci lint actionlint fmt web web-test web-dev docker demo demo-down k8s-validate k8s-smoke prom-check

help: ## Show targets
	@grep -E '^[a-z0-9-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'

deps-up: ## Start local Postgres (127.0.0.1:55442); it restarts with Docker
	docker compose up -d --wait

deps-down: ## Stop local Postgres (keeps data)
	docker compose down

generate: ## Regenerate sqlc queries, OpenAPI types and the public client pkg/ompclient (Go, and TypeScript when web/ exists)
	$(SQLC) generate
	$(GO) generate ./...
	@if [ -f web/package.json ]; then cd web && npm run gen; else echo "web/package.json not found; skipping TypeScript generation"; fi

check-generated: generate ## Fail if generated code is stale
	@git diff --exit-code -- internal/store/dbgen internal/httpapi/apitypes pkg/ompclient web/src/api/schema.gen.ts || \
		(echo "generated code is stale: run 'make generate' and commit" && exit 1)
	@test -z "$$(git ls-files --others --exclude-standard -- internal/store/dbgen internal/httpapi/apitypes pkg/ompclient web/src/api)" || \
		(echo "untracked generated files: run 'make generate' and commit" && exit 1)

build: ## Build bin/open-mcp-portal (run `make web` first to include the UI)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/open-mcp-portal ./cmd/open-mcp-portal

build-omp: ## Build bin/omp, the command line (docs/cli.md)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/omp ./cmd/omp

run: ## Run `serve` locally on 127.0.0.1:8088 using .env (created from .env.example)
	@test -f .env || cp .env.example .env
	set -a && . ./.env && set +a && $(GO) run ./cmd/open-mcp-portal serve

migrate: ## Apply migrations using .env
	@test -f .env || cp .env.example .env
	set -a && . ./.env && set +a && $(GO) run ./cmd/open-mcp-portal migrate

dev-seed: ## Seed a local install (make run + make fake-mcp): team demo, a published server and two gateways
	python3 scripts/dev-seed.py

fake-mcp: ## Run a fake MCP server on http://127.0.0.1:8091/mcp (FAKEMCP_DESCRIBE='tool=text' changes a description)
	$(GO) run ./cmd/fakemcp -jwks http://localhost:8088/.well-known/jwks.json

fake-oauth: ## Run a fake OAuth provider on http://127.0.0.1:8092 for delegated credentials (client fake-client)
	$(GO) run ./cmd/fakeoauth

# The Gmail MCP example (examples/mail-mcp): MAIL_PROVIDER is the auth
# provider's slug in the portal, MAIL_AUDIENCE the server's URL as registered.
MAIL_PROVIDER ?= google
MAIL_AUDIENCE ?= http://127.0.0.1:8093/mcp

example-mail: ## Run the Gmail MCP example on http://127.0.0.1:8093/mcp against real Gmail (MAIL_PROVIDER=google)
	$(GO) run ./examples/mail-mcp -gateway http://localhost:8088 -provider $(MAIL_PROVIDER) -audience $(MAIL_AUDIENCE)

example-mail-fake: ## Run the Gmail MCP example with an in-process fake Gmail, for make fake-oauth (provider google-dev)
	$(GO) run ./examples/mail-mcp -gateway http://localhost:8088 -provider google-dev -audience $(MAIL_AUDIENCE) -fake-gmail

example-mail-smoke: ## Set up provider google-dev, server and gateway "mail" in team demo, and smoke-test the example
	python3 examples/mail-mcp/smoke.py

test: ## All Go tests; integration tests skip when Postgres is unreachable
	# The complete HTTP integration package needs CI's bounded budget in normal mode too.
	$(GO) test -count=1 -timeout=20m ./...

test-action: ## Test the GitHub Action adapter and signed-installer contract with a scratch CLI
	@set -eu; tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
		$(GO) build -o "$$tmp/omp" ./cmd/omp; \
		OMP_ACTION_TEST_CLI="$$tmp/omp" python3 -m unittest discover -s integrations/github-action/tests -p 'test_*.py' -v

test-integration: deps-up test-ci ## All Go tests with Postgres required (fails instead of skipping)

test-ci: ## test-integration without deps-up (CI's Postgres service; OMP_TEST_DATABASE_URL)
	# The expanded HTTP integration package can exceed Go's default 10m under -race.
	OMP_TEST_REQUIRE_DB=1 $(GO) test -race -count=1 -timeout=20m ./...

lint: ## go vet and gofmt check
	$(GO) vet ./...
	@test -z "$$(gofmt -l cmd internal pkg examples migrations web/embed.go)" || (gofmt -l cmd internal pkg examples migrations web/embed.go && echo "run 'make fmt'" && exit 1)

ACTIONLINT_VERSION ?= v1.7.12

actionlint: ## Check the GitHub Actions workflows
	$(GO) run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

fmt: ## Format Go code
	gofmt -w cmd internal pkg examples migrations web/embed.go

web: ## Build the web UI into web/dist (embedded by `make build`)
	cd web && npm ci --ignore-scripts && npm run build

web-test: ## Type-check and test the web UI
	cd web && npm run typecheck && npm test

web-dev: ## Run the Vite dev server on :5175 (proxies the API to `make run` on :8088)
	cd web && npm run dev

docker: ## Build the container image open-mcp-portal:<git describe>
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t open-mcp-portal:$(VERSION) .

docker-omp: ## Build the container image omp-cli:<git describe> (the Dockerfile's omp target)
	docker build --target omp --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t omp-cli:$(VERSION) .

demo: ## Try it in Docker: portal + Postgres + fake MCP server on http://localhost:8090 (OMP_DEMO_PORT; dev sign-in)
	docker compose -f compose.demo.yaml up --build

demo-down: ## Stop the demo and delete its data
	docker compose -f compose.demo.yaml down -v

$(KUSTOMIZE):
	GOBIN=$(dir $@) $(GO) install sigs.k8s.io/kustomize/kustomize/v5@$(KUSTOMIZE_VERSION)

$(KUBECONFORM):
	GOBIN=$(dir $@) $(GO) install github.com/yannh/kubeconform/cmd/kubeconform@$(KUBECONFORM_VERSION)

k8s-validate: $(KUSTOMIZE) $(KUBECONFORM) ## Render the Kubernetes base and overlays; validate with kubeconform
	KUSTOMIZE=$(KUSTOMIZE) KUBECONFORM=$(KUBECONFORM) deploy/kubernetes/scripts/validate.sh

# promtool, from the PATH or the pinned Prometheus image (docker; the container is removed).
PROMTOOL_IMAGE ?= prom/prometheus:v3.15.0

prom-check: ## promtool check rules and test rules on deploy/prometheus (local promtool, else docker)
	@if command -v promtool >/dev/null 2>&1; then \
		cd deploy/prometheus && promtool check rules omp-alerts.yaml && promtool test rules omp-alerts.test.yaml; \
	else \
		docker run --rm --entrypoint sh -v "$(CURDIR)/deploy/prometheus:/rules:ro" -w /rules $(PROMTOOL_IMAGE) \
			-c 'promtool check rules omp-alerts.yaml && promtool test rules omp-alerts.test.yaml'; \
	fi

k8s-smoke: ## Apply the Kubernetes base to a throwaway kind cluster and check it (docker, kind, kubectl, jq; SMOKE_CNI=calico enforces NetworkPolicy; SMOKE_SCENARIO=upgrade|ingress|restore|load)
	scripts/k8s-smoke.sh

SHELLCHECK_FILES := scripts/*.sh scripts/smoke/*.sh deploy/kubernetes/scripts/validate.sh integrations/github-action/tests/real-portal.sh

# Always the pinned, checksum-verified release: a runner's preinstalled
# ShellCheck is another version with other findings.
SHELLCHECK_VERSION := $(shell sed -n 's/^SHELLCHECK_VERSION="\(.*\)"$$/\1/p' scripts/install-smoke-tools.sh)
SHELLCHECK_BIN := $(K8S_TOOLS)/shellcheck-$(SHELLCHECK_VERSION)/shellcheck

shellcheck: ## ShellCheck the deployment and smoke scripts with the pinned release (installed into bin/k8s-tools on first use)
	@test -n "$(SHELLCHECK_VERSION)" || (echo "no SHELLCHECK_VERSION in scripts/install-smoke-tools.sh" && exit 1)
	@test -x $(SHELLCHECK_BIN) || scripts/install-smoke-tools.sh $(dir $(SHELLCHECK_BIN)) shellcheck >/dev/null
	@$(SHELLCHECK_BIN) --version | grep -q "^version: $(patsubst v%,%,$(SHELLCHECK_VERSION))$$" || (echo "$(SHELLCHECK_BIN) is not ShellCheck $(SHELLCHECK_VERSION)" && exit 1)
	$(SHELLCHECK_BIN) $(SHELLCHECK_FILES)

smoke-selftest: ## The smoke scripts' assertion helpers against stubs, and the script tests in scripts/tests (no cluster, no Docker)
	SMOKE_SELFTEST=1 scripts/k8s-smoke.sh
	python3 -m unittest discover -s scripts/tests -p 'test_*.py'
