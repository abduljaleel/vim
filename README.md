# VIM — Vulnerability Inheritance Map

**Mapping vulnerability lineage across the software supply chain**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/XXXX/badge)](https://www.bestpractices.dev/projects/XXXX)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/abduljaleel/vim/badge)](https://securityscorecards.dev/viewer/?uri=github.com/abduljaleel/vim)

VIM is an open-source graph database that maps how vulnerabilities propagate across forks, vendored dependencies, and compiled binaries. When a vulnerability is discovered in one codebase, VIM identifies every downstream system carrying the same code.

## The Problem

AI-driven vulnerability discovery (e.g., [Claude Mythos Preview](https://anthropic.com/glasswing)) has made finding bugs cheap. The bottleneck is now **tracking where vulnerable code actually lives**.

No existing tool answers: *"Given a vulnerability in project X, which forks, vendored copies, and compiled binaries are also affected?"*

- **CVE/NVD** treats each fork as a separate product with no inheritance
- **Package-level SCA** (Snyk, Black Duck, etc.) misses vendored and copied code
- **59.3%** of vulnerable copied files propagate through manual copying invisible to package managers
- **17%** of components enter codebases outside package managers

## What VIM Does

```
Discovery (Mythos, OSS-Fuzz, CodeQL)
    | finds vulnerability in upstream code
VIM (Vulnerability Inheritance Map)
    | traces all downstream forks, copies, binaries
GUAC + OSV + deps.dev
    | maps affected artifacts and versions
```

VIM is the **lineage layer** between discovery and remediation:

- **Fork genealogy** — tracks how code propagates across repository boundaries
- **Vendored code tracking** — identifies manually copied files invisible to package managers
- **Binary provenance** — connects compiled artifacts back to source origins
- **Patch propagation monitoring** — tracks which downstream forks have/haven't applied fixes

## Architecture

VIM uses a **trilateral identity resolution** system:

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Extrinsic identity | pURL (ECMA-427) | Package-level identification |
| Intrinsic identity | SWHID | Content-addressable file identity |
| Fuzzy identity | TLSH | Similarity matching for modified code |

Built on:
- **JanusGraph + Cassandra** — mutable transactional graph (100B+ vertices)
- **WebGraph (Rust)** — compressed immutable bulk analytics (SWH-scale)
- **PostgreSQL + Ent ORM** — GUAC-compatible metadata layer

Data sources include Software Heritage (50B nodes), World of Code (173M repos), OSV.dev, deps.dev, GUAC, and CISA KEV.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/abduljaleel/vim.git
cd vim

# Start local development environment
docker compose -f deploy/docker/docker-compose.yml up -d

# Run the CLI
go run ./cmd/vim-cli --help
```

## Project Status

VIM is in **pre-launch / RFC stage** (April 2026). We are:

- [ ] Assembling initial maintainers from multiple organizations
- [ ] Applying for OpenSSF Sandbox
- [ ] Building core graph infrastructure
- [ ] Shipping Phase 1 GUAC integration

See the [Roadmap](docs/guides/ROADMAP.md) for details.

## Ecosystem Position

VIM **complements** existing tools — it does not replace them:

| Tool | What it does | How VIM extends it |
|------|-------------|-------------------|
| **GUAC** | Artifact composition | VIM adds fork lineage and code-level provenance |
| **OSV** | Vuln-to-version mapping | VIM traces vulns across forks and copies |
| **deps.dev** | Dependency resolution | VIM tracks vendored code outside dep trees |
| **Scorecard** | Security posture | VIM monitors patch propagation across forks |
| **SLSA/Sigstore** | Build integrity | VIM connects binary provenance to source lineage |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

All contributions require DCO sign-off (`git commit -s`).

## Security

To report a security vulnerability, see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Governance

VIM targets [OpenSSF](https://openssf.org/) as its governance home (Sandbox -> Incubation -> Graduation). See [GOVERNANCE.md](GOVERNANCE.md).

## Links

- [Architecture Documentation](docs/architecture/)
- [API Reference](docs/api/)
- [RFCs](docs/rfcs/)
- [OpenSSF Slack](https://slack.openssf.org) — `#vim` channel (coming soon)
