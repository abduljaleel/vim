# Contributing to VIM

Thank you for your interest in contributing to the Vulnerability Inheritance Map! This document provides guidelines and information for contributors.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Developer Certificate of Origin (DCO)

All contributions must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/) (DCO). This certifies that you wrote (or have the right to submit) the contribution under the project's open source license.

Sign off your commits by adding `-s` to your `git commit` command:

```bash
git commit -s -m "Add fork detection for GitLab repositories"
```

This adds a `Signed-off-by` line to your commit message. All commits in a PR must be signed off, or the DCO check will fail.

## How to Contribute

### Reporting Issues

- Use [GitHub Issues](https://github.com/abduljaleel/vim/issues) to report bugs or suggest features
- Search existing issues before creating a new one
- Use the provided issue templates
- Include reproduction steps for bugs

### Development Workflow

1. **Fork** the repository
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/my-feature main
   ```
3. **Make your changes** with tests
4. **Run the test suite** locally:
   ```bash
   make test
   make lint
   ```
5. **Commit** with DCO sign-off:
   ```bash
   git commit -s -m "Descriptive commit message"
   ```
6. **Push** to your fork and open a **Pull Request**

### Pull Request Requirements

- All PRs require review by at least 2 maintainers
- All CI checks must pass (tests, linting, DCO)
- New features must include tests (minimum 80% coverage for new code)
- Public APIs must include documentation with examples
- Breaking changes require an Architecture Decision Record (ADR)

## Development Setup

### Prerequisites

- Go 1.22+
- Rust 1.77+ (for webgraph-analytics)
- Python 3.12+ (for analysis tools)
- Docker and Docker Compose (for local infrastructure)
- Make

### Quick Start

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/vim.git
cd vim

# Install Go dependencies
go mod download

# Start local infrastructure (JanusGraph, Cassandra, PostgreSQL)
make dev-up

# Run tests
make test

# Run linters
make lint
```

## Code Standards

### Go
- Follow [Effective Go](https://golang.org/doc/effective_go)
- Use `golangci-lint` (config in `.golangci.yml`)
- All exported types and functions must have doc comments

### Rust
- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines)
- Use `clippy` with pedantic lints
- Use `rustfmt` for formatting

### Python
- PEP 8 + Black formatter
- Type hints are mandatory
- Use mypy in strict mode

## Issue Labels

- `good-first-issue` — Great for newcomers
- `help-wanted` — We'd love your help
- `security` — Security-related issues (see SECURITY.md for vulnerabilities)
- `guac-integration` — Related to GUAC interop
- `graph-engine` — JanusGraph/WebGraph core
- `identity-layer` — pURL/SWHID/TLSH resolution
- `documentation` — Docs improvements

## Architecture Decision Records

Significant technical decisions are documented as ADRs in `docs/architecture/`. If your change involves a significant design choice, please include an ADR with your PR. Use the template at `docs/architecture/adr-template.md`.

## Community

- **OpenSSF Slack:** [slack.openssf.org](https://slack.openssf.org) — `#vim` channel (pending)
- **Community calls:** TBD (target: bi-weekly after sandbox acceptance)
- **Mailing list:** TBD

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
