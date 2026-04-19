# VIM — Vulnerability Inheritance Map
# Developer makefile

.PHONY: help build test lint fmt clean dev-up dev-down docker-build docs

# Default target
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

## --- Go ---

build: ## Build all Go binaries
	go build -o bin/vim-server ./cmd/vim-server
	go build -o bin/vim-cli ./cmd/vim-cli
	go build -o bin/vim-ingestor ./cmd/vim-ingestor
	go build -o bin/vim-certifier ./cmd/vim-certifier

test: ## Run Go tests with coverage
	go test -race -coverprofile=coverage.out -covermode=atomic ./...

test-integration: ## Run integration tests (requires dev-up)
	go test -tags=integration ./test/integration/...

fmt: ## Format Go code
	gofmt -s -w .
	goimports -w .

lint: ## Run linters
	golangci-lint run ./...

vet: ## Run go vet
	go vet ./...

## --- Rust ---

rust-build: ## Build Rust components
	cd rust/webgraph-analytics && cargo build --release

rust-test: ## Run Rust tests
	cd rust/webgraph-analytics && cargo test

rust-lint: ## Run Rust linters
	cd rust/webgraph-analytics && cargo clippy --all-targets -- -D warnings

## --- Python ---

py-test: ## Run Python tests
	cd python && python -m pytest

py-lint: ## Run Python linters
	cd python && ruff check . && mypy --strict .

py-fmt: ## Format Python code
	cd python && black . && ruff check --fix .

## --- Infrastructure ---

dev-up: ## Start local development infrastructure
	docker compose -f deploy/docker/docker-compose.yml up -d

dev-down: ## Stop local development infrastructure
	docker compose -f deploy/docker/docker-compose.yml down

dev-logs: ## Tail logs from dev infrastructure
	docker compose -f deploy/docker/docker-compose.yml logs -f

dev-reset: ## Reset dev infrastructure (destroys data)
	docker compose -f deploy/docker/docker-compose.yml down -v

## --- Quality ---

security-scan: ## Run security scans
	osv-scanner --lockfile=go.sum
	trivy fs --security-checks vuln,config,secret .
	gitleaks detect --source . --verbose

check: fmt vet lint test ## Run all pre-commit checks

## --- Release ---

clean: ## Clean build artifacts
	rm -rf bin/ coverage.out
	cd rust/webgraph-analytics && cargo clean

docs: ## Serve docs locally
	@echo "Docs site: TBD (Hugo or MkDocs setup planned)"
