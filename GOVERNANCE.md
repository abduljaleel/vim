# VIM Governance

This document describes how the Vulnerability Inheritance Map (VIM) project is governed. It is intended to evolve as the project matures through OpenSSF Sandbox, Incubation, and Graduation stages.

## Guiding Principles

1. **Open by default** — Decisions are made in public issues, PRs, and community calls. Private channels are used only for security-sensitive matters.
2. **Multi-organization** — No single company controls the project. Maintainer representation must come from at least two organizations at all times.
3. **Meritocracy** — Contributors earn trust through sustained, high-quality contributions.
4. **Complement, not compete** — VIM is designed to extend the OpenSSF ecosystem (GUAC, OSV, SLSA, Scorecard). Roadmap decisions prioritize interoperability.

## Roles

### Contributors
Anyone who contributes code, documentation, design input, bug reports, or community support. All contributors are listed in `CONTRIBUTORS.md` (auto-generated).

### Reviewers
Contributors with a demonstrated track record in a specific subsystem (e.g., `pkg/identity/`, `pkg/graph/`). Reviewers are recognized in the relevant `CODEOWNERS` entry. They can approve PRs within their subsystem but cannot merge.

**Becoming a Reviewer:** Nominated by an existing Maintainer based on at least 5 meaningful merged PRs to a subsystem. Confirmed by lazy consensus among Maintainers (72 hours, no objection).

### Maintainers
Trusted contributors with commit rights. Maintainers can merge PRs, cut releases, and vote on project decisions.

**Current Maintainers:** See `MAINTAINERS.md` (seed list will be established at project launch).

**Becoming a Maintainer:** Nominated by an existing Maintainer based on (a) sustained contribution as a Reviewer, typically 3+ months, and (b) demonstrated judgment on cross-subsystem tradeoffs. Confirmed by supermajority vote (≥2/3 of active Maintainers).

**Stepping Down / Emeritus:** A Maintainer who has not been active (no PRs, reviews, or meeting participation) for 6 consecutive months is moved to Emeritus status by the remaining Maintainers. Emeritus Maintainers retain credit but not commit rights; they can return to active status by request plus a lazy-consensus confirmation.

### Organizational Diversity Requirement
At any given time, no single organization may employ more than **50%** of active Maintainers. If the ratio is exceeded (e.g., through hiring or departures), the Maintainers must publicly document the imbalance within 30 days and actively recruit from other organizations to restore balance.

## Decision-Making

VIM uses **lazy consensus with supermajority fallback**:

1. **Lazy consensus (default):** Any Maintainer may propose a change via PR or GitHub issue. If no other Maintainer objects within 72 hours, the proposal passes.
2. **Supermajority vote (fallback):** If any Maintainer objects, the proposal requires a ≥2/3 supermajority of active Maintainers to pass. Votes are recorded publicly in the PR or issue.

### What Requires a Vote

Lazy consensus is sufficient for:
- Routine code changes (PRs)
- Documentation updates
- Dependency bumps
- Bug fixes

Supermajority vote is required for:
- Adding or removing Maintainers
- Architectural changes documented as ADRs
- Breaking API changes
- Governance changes (amendments to this document)
- Selection of a TAC sponsor
- License or dependency license policy changes
- Establishment of sub-projects or formal working groups

### Pull Request Approval

All PRs require:
- **2 Maintainer approvals** for merge (from different organizations when possible)
- Passing CI (tests, linting, DCO sign-off, security scans)
- No unresolved review comments from any Reviewer or Maintainer

Emergency security fixes may be merged with 1 Maintainer approval, with a mandatory post-merge review within 24 hours.

## Maintainer Activities

Maintainers are expected to:
- Review PRs in their subsystem(s) within 5 business days
- Attend at least 50% of community calls (when established)
- Respond to security reports via the process in `SECURITY.md`
- Vote on proposals requiring supermajority
- Mentor new contributors

## Community Calls

Once the project reaches initial sandbox acceptance, VIM will hold:
- **Maintainer meetings:** Bi-weekly, agenda posted 48 hours in advance
- **Community calls:** Monthly, open to all, recorded and published

Meeting notes are posted to the `docs/meetings/` directory in the repository.

## Code of Conduct

All community interactions are governed by the project [Code of Conduct](CODE_OF_CONDUCT.md). Enforcement is handled by the Code of Conduct Committee (initially the Maintainers; may be delegated as the project grows).

## Security Policy

Security vulnerabilities are handled according to [SECURITY.md](SECURITY.md). A rotating Security Response Team is drawn from active Maintainers.

## Relationship to Acelera Intelligence

VIM was founded by Acelera Intelligence Pty Ltd (Melbourne, Australia) and launched under the Apache License 2.0 with the explicit intention of transferring governance to a neutral foundation home.

**Founding Commitment:** Acelera Intelligence commits to:
1. Holding no more than 50% Maintainer representation once the project has ≥4 Maintainers
2. Transferring the trademark, domain names, and repository ownership to OpenSSF (or another neutral home accepted by the Maintainers) upon Incubation acceptance
3. Not placing any contractual, licensing, or commercial restrictions on downstream use of VIM

Acelera Intelligence may offer commercial services built on VIM (managed feeds, enterprise support, compliance reporting). These are separate products and cannot restrict the open-source project.

## Target Foundation Home

VIM targets **OpenSSF** (Linux Foundation) as its governance home, progressing through the stages defined by the [OpenSSF TAC Project Lifecycle](https://github.com/ossf/tac):

1. **Sandbox** — Initial acceptance, early-stage projects. *Target: Q3 2026.*
2. **Incubation** — Growing community, stable core. *Target: 2027.*
3. **Graduation** — Mature, widely adopted. *Target: 2028+.*

## Amendments

This governance document may be amended by a ≥2/3 supermajority vote of active Maintainers, with a minimum 14-day public comment period before the vote. Amendment proposals are filed as PRs to this file.

---

*Last updated: 2026-04-17. Initial version — ratified on project launch.*
