# sp-portal top-level Makefile.

SHELL := /bin/bash
.DEFAULT_GOAL := help

# This repo sits inside the serverperch workspace but is not in go.work;
# keep every go command in module mode.
GOWORK ?= off
export GOWORK

COMPOSE := docker compose -f deploy/compose/docker-compose.yml

SP_PORTAL_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
SP_PORTAL_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
SP_PORTAL_BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION_PKG := github.com/technofish-au/sp-portal/internal/version
LDFLAGS := -s -w -X $(VERSION_PKG).Version=$(SP_PORTAL_VERSION) -X $(VERSION_PKG).Commit=$(SP_PORTAL_COMMIT) -X $(VERSION_PKG).Date=$(SP_PORTAL_BUILD_DATE)

STATICCHECK ?= staticcheck

# Our packages, excluding vendored node modules (they contain stray Go).
PKGS := $(shell GOWORK=off go list ./... | grep -v node_modules)

.PHONY: help gen lint go-lint web-lint test build go-build web-build dev-up dev-down migrate acceptance image clean

help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_.-]+:.*## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

gen: ## Generate code (sqlc -> internal/db/dbq) and the web route tree
	./scripts/ensure-web-dist.sh
	cd internal/db && sqlc generate
	cd web && npx vite build --mode development >/dev/null 2>&1 || true
	@test -z "$$(gofmt -l internal/db/dbq 2>/dev/null)" || gofmt -w internal/db/dbq

lint: go-lint web-lint ## Lint Go (gofmt + vet + staticcheck) and web code

go-lint: ## Lint Go code
	@./scripts/ensure-web-dist.sh
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }
	go vet $(PKGS)
	$(STATICCHECK) $(PKGS)

web-lint: ## Lint web code (eslint) when dependencies are installed
	@if [ -d web/node_modules ]; then cd web && npm run lint; \
	 else echo "web-lint: skipped (run 'cd web && npm install' first)"; fi

test: ## Run Go tests (integration tests use a throwaway mariadb container)
	@./scripts/ensure-web-dist.sh
	go test $(PKGS)

build: web-build go-build ## Build the web UI, then the Go binary

go-build: ## Build bin/sp-portal
	@./scripts/ensure-web-dist.sh
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/sp-portal ./cmd/sp-portal

web-build: ## Build the web UI into internal/webui/dist
	cd web && npm run build

dev-up: ## Start compose: mariadb -> migrate -> app + worker
	$(COMPOSE) up -d --wait mariadb
	$(COMPOSE) run --rm app migrate
	$(COMPOSE) up -d --wait app worker

dev-down: ## Stop the dev compose stack (add -v to also drop volumes)
	$(COMPOSE) down $(if $(VOLUMES),-v,)

migrate: ## Apply schema migrations against the compose MariaDB
	$(COMPOSE) run --rm app migrate

acceptance: ## Run the 2-replica/1000-job worker acceptance test (throwaway mariadb container)
	go test ./internal/jobs -run 'TestWorker' -v -count=1

image: ## Build the sp-portal container image
	docker build -f deploy/docker/Dockerfile \
		--build-arg SP_PORTAL_VERSION=$(SP_PORTAL_VERSION) \
		--build-arg SP_PORTAL_COMMIT=$(SP_PORTAL_COMMIT) \
		--build-arg SP_PORTAL_BUILD_DATE=$(SP_PORTAL_BUILD_DATE) \
		-t sp-portal:$(SP_PORTAL_VERSION) -t sp-portal:dev .

clean: ## Remove build outputs
	rm -rf bin internal/webui/dist
