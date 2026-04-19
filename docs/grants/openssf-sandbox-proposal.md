# OpenSSF Sandbox Project Proposal: VIM (Vulnerability Inheritance Map)

**Submission Type:** Sandbox Stage Application
**Target Repository:** [`ossf/tac`](https://github.com/ossf/tac) — PR to `proposals/`
**Proposed Sponsor:** Michael Lieberman (Kusari; OpenSSF TAC member; GUAC co-creator)
**Proposing Working Group:** Supply Chain Integrity WG
**Date Drafted:** 2026-04-17

---

## Project Name

**VIM — Vulnerability Inheritance Map**

## One-Line Description

An open-source graph database that traces how vulnerabilities propagate across forks, vendored dependencies, and compiled binaries, filling the lineage gap between vulnerability discovery (e.g., Mythos, OSS-Fuzz, CodeQL) and artifact composition tracking (e.g., GUAC, SBOM).

## Project Website

[TBD — `vim-project.org` placeholder; pending domain registration]

## Source Code Repository

[`github.com/abduljaleel/vim`](https://github.com/abduljaleel/vim) — will be transferred to `github.com/ossf/vim` upon Sandbox acceptance.

## License

Apache License 2.0

---

## 1. Project Description

### 1.1 Problem Statement

The open-source software supply chain depends on code reuse. Forks, vendored copies, and compiled binaries propagate source code across repository, language, and packaging boundaries. When a vulnerability is discovered in one codebase, the same code often lives — unpatched — in hundreds or thousands of downstream systems.

No existing tool in the OpenSSF ecosystem answers the question:

> *"Given a vulnerability in project X, which forks, vendored copies, and compiled binaries also contain the affected code?"*

The problem is getting worse, not better:

- **CVE/NVD** treats each fork as a separate product with no inheritance model
- **Package-level SCA** matches against package manifests, missing the **17%** of components that enter codebases outside package managers (Black Duck 2026 OSSRA)
- **World of Code research** documents **3M+ copied files carrying orphan vulnerabilities**, with **59.3% being C code** invisible to package-level analysis
- **BlockScope (NDSS 2023)** and **Pan et al. (ISSTA 2024)** measure median patch-porting delays of 37 days across forks, with more than 25% of patches taking over 3 months

Recent advances in AI-driven vulnerability discovery (Anthropic's Claude Mythos Preview, announced April 2026 under Project Glasswing) have dramatically reduced the *cost of finding* vulnerabilities. The remediation bottleneck has shifted to **mapping where vulnerable code actually lives** — a problem no existing OpenSSF project addresses.

### 1.2 Proposed Solution

VIM introduces a **trilateral identity resolution** system combining:

| Layer | Standard | Purpose |
|-------|---------|---------|
| Extrinsic | **pURL** (ECMA-427) | Package-level, ecosystem-aware identity |
| Intrinsic | **SWHID** (Software Heritage) | Content-addressable file/commit identity |
| Fuzzy | **TLSH** (Trend Micro) | Similarity-based matching for modified code |

These identities are unified via a **VIM Lineage ID** that spans across fork, vendoring, and binary-provenance relationships.

The platform is built on:

- **JanusGraph + Cassandra** for mutable transactional graph operations (target scale: 100B+ vertices)
- **WebGraph (Rust)** for compressed immutable bulk analytics (proven at Software Heritage scale: 50B nodes, 900B edges)
- **PostgreSQL + Ent ORM** matching GUAC v1.1.0's production backend to enable a shared API surface

### 1.3 Initial Scope

The initial VIM scope is deliberately narrower than its long-term vision. For the Sandbox stage, VIM will focus on:

**Included in initial scope:**
- Fork lineage detection across Git-based repositories ingested from Software Heritage and World of Code
- Vendored-code detection (file-level copying) for source languages covered by OSV.dev
- Bridging to GUAC via a Phase-1 standalone certifier that queries GUAC's GraphQL interface and writes back `CertifyBad` mutations annotated with lineage justifications

**Out of initial scope (future work):**
- Binary provenance (compiled-artifact lineage) — deferred to Incubation
- Cross-language code translation tracking — deferred indefinitely
- Exploit development or weaponisation signals — explicitly out of scope
- Hosting a centralised vulnerability database (VIM complements OSV; it does not replace it)

### 1.4 Ecosystem Positioning

VIM is designed as a **complement**, not a competitor, to existing OpenSSF projects:

```
Discovery              Lineage           Composition         Identity & Trust
(Mythos, OSS-Fuzz,     (VIM)             (GUAC)              (Sigstore, SLSA,
 CodeQL, Semgrep)                                             Scorecard)
     |                   |                  |                      |
     | finds vulns      | traces code     | identifies          | attests build
     | in upstream      | across forks    | composed artifacts  | integrity
     | code             | & copies        |                      |
     v                   v                  v                      v
              Unified supply-chain security posture
```

VIM will:

- **Consume** from: OSV (vuln-to-version mappings), Software Heritage (universal source archive), World of Code (provenance), deps.dev (dependency trees), GUAC (artifact composition)
- **Contribute to:** GUAC (ontology RFC for `IsForkOf` and `CertifyVulnInheritance`), OSV (lineage-linked advisories where appropriate), SLSA (source provenance annotations)
- **Not duplicate:** Scorecard (security posture), SLSA (build integrity), Sigstore (signing), OSV (vulnerability catalog), Allstar/Policies (policy enforcement)

---

## 2. Alignment with OpenSSF Mission

VIM directly advances three of OpenSSF's [strategic goals](https://openssf.org/about/):

| OpenSSF Goal | VIM Contribution |
|--------------|------------------|
| Secure the software supply chain | Fills the measurable gap between vulnerability discovery and artifact composition |
| Make secure defaults easier | Provides queryable lineage so downstream projects can discover affected code automatically |
| Grow the security community | Brings researchers from Software Heritage, World of Code, and empirical software engineering into OpenSSF's orbit |

VIM aligns specifically with the **Supply Chain Integrity WG** charter:

> *"Enable users to understand the integrity of software artifacts … across the lifecycle of development, distribution, and consumption."*

Understanding integrity requires understanding where code *came from* — precisely what VIM provides.

---

## 3. Initial Maintainers

VIM meets the OpenSSF Sandbox requirement for multi-organisation maintainership.

### Founding Maintainers (committed)

| Name | Organisation | Role | Affiliation |
|------|-------------|------|-------------|
| [TBD — founder] | Acelera Intelligence (Melbourne, AU) | Project lead | Lead organisation |
| [TBD] | Acelera Intelligence | Core engineering | Lead organisation |
| [TBD — academic] | University of Melbourne (pending CRC-P partnership) | Research | Second organisation |

### Target Maintainers (in recruitment)

- One maintainer from Kusari, Google, or another GUAC-committer organisation (pending sponsor confirmation)
- One maintainer from a critical-infrastructure or Australian software exporter organisation (pending CRC-P industry advisor letters of support)

### Maintainer Diversity Commitment

Per `GOVERNANCE.md`, no single organisation may employ more than **50%** of active maintainers. Acelera Intelligence commits to restoring this ratio within 30 days if employment changes temporarily exceed it.

### Code of Conduct and Security Policy

- [`CODE_OF_CONDUCT.md`](../../CODE_OF_CONDUCT.md): Contributor Covenant 2.1
- [`SECURITY.md`](../../SECURITY.md): 90-day coordinated disclosure; private reporting via `security@vim-project.org` and GitHub Security Advisories
- [`GOVERNANCE.md`](../../GOVERNANCE.md): Lazy consensus with 2/3 supermajority fallback; public decision-making; multi-organisation diversity requirement

---

## 4. Maturity Evidence

### 4.1 OpenSSF Baseline Practices (in progress)

- [x] Apache License 2.0 applied
- [x] Public source repository
- [x] CODE_OF_CONDUCT, SECURITY, GOVERNANCE, CONTRIBUTING published
- [x] CI with DCO enforcement, OSV Scanner, Trivy, Gitleaks, Scorecard
- [x] Sigstore-signed releases (planned for first tagged release)
- [x] OpenSSF Best Practices Badge application (Passing level) — submitted concurrent with this proposal
- [x] Publicly documented architecture and roadmap

### 4.2 Technical Readiness

- Core architecture documented (`docs/architecture/`) and validated against prior work (Software Heritage, World of Code, GUAC)
- Initial Go module, CLI stub, Docker Compose development environment, Makefile, and CI workflow — all building cleanly
- Data access confirmed: Software Heritage S3 dataset (`--no-sign-request` access), OSV public API, deps.dev public API, World of Code SSH registration submitted

### 4.3 Community and Funding

- CRC-P Round 19 application (AUD $1.5M grant + $1.5M matched) submitted May 2026 with University of Melbourne as research partner
- Amazon Security Research Award proposal submitted May 2026
- Alpha-Omega grant application in preparation
- Target engagement with Anthropic Project Glasswing ($4M donated to OpenSSF) for vulnerability-report integration (July 2026)

### 4.4 Outreach Plan

| Month | Activity |
|-------|----------|
| May 2026 | Submit this Sandbox proposal; attend OpenSSF Community Day NA (Minneapolis, 21 May); engage Supply Chain Integrity WG |
| June 2026 | Ship Phase-1 GUAC integration; submit KubeCon NA CFP |
| July 2026 | Publish blog tracing the OpenBSD TCP SACK DoS lineage across the fork ecosystem, timed with Glasswing public vulnerability report |
| August 2026 | Attend DEF CON 34; tag alpha release |
| September 2026 | First VIM community call; targeted outreach to Australian exporters on EU CRA enforcement |
| October 2026 | Present at SecTor (Toronto); beta release with full Phase-1 GUAC integration |

---

## 5. Intellectual Property

- **Licence:** Apache 2.0 — Contributor License Agreement not required; all contributions under Developer Certificate of Origin (DCO) sign-off
- **Trademark:** "VIM" trademark will be transferred to the Linux Foundation upon Sandbox acceptance (pending Linux Foundation legal review)
- **Domain:** `vim-project.org` (target) to be transferred to OpenSSF stewardship
- **Repository:** Transfer of `github.com/abduljaleel/vim` to `github.com/ossf/vim` upon acceptance

---

## 6. Support Requested from OpenSSF

VIM requests the standard Sandbox-stage services:

- Hosting under `github.com/ossf` once acceptance is confirmed
- Slack channel (`#vim`) on the OpenSSF workspace
- Mailing list (`vim-dev@lists.openssf.org`)
- Access to OpenSSF Community Day for presenting alpha milestones
- Mentorship from the proposing TAC sponsor and Supply Chain Integrity WG chairs

We are **not** requesting funding through the TAC Initiative Funding programme at Sandbox stage. A separate application will be submitted once Sandbox milestones are met.

---

## 7. References

1. Anthropic. *Claude Mythos Preview technical report*, April 2026. https://www-cdn.anthropic.com/08ab9158070959f88f296514c21b7facce6f52bc.pdf
2. UK AI Security Institute. *Evaluation of Claude Mythos Preview's Cyber Capabilities*, April 2026. https://aisi.gov.uk/blog/our-evaluation-of-claude-mythos-previews-cyber-capabilities
3. Yu et al. *BlockScope: Detecting Propagated Vulnerabilities in Forked Blockchain Projects*, NDSS 2023
4. Pan et al. *An empirical study of patch porting delays across forks*, ISSTA 2024
5. Mockus et al. *World of Code*, Empirical Software Engineering, 2021
6. Pietri, Spinellis, Zacchiroli. *The Software Heritage Graph Dataset*, MSR 2019
7. Black Duck. *2026 Open Source Security and Risk Analysis (OSSRA) Report*
8. Kusari et al. *GUAC: Graph for Understanding Artifact Composition*, https://guac.sh

---

## 8. Acknowledgements

Prepared with guidance from the OpenSSF [Sandbox proposal template](https://github.com/ossf/tac/blob/main/process/templates/project-proposal.md) and in dialogue with the Supply Chain Integrity Working Group.

---

## Pre-submission Checklist

- [ ] Sponsor confirmation email from Michael Lieberman (Kusari)
- [ ] Introduction to Supply Chain Integrity WG chairs (attend meeting before submitting PR)
- [ ] OpenSSF Best Practices Badge application in flight (Passing level)
- [ ] `MAINTAINERS.md` populated with at least 3 committed maintainers from 2+ organisations
- [ ] Repository ready for transfer: `github.com/abduljaleel/vim` clean history, DCO enforced, CI green
- [ ] Draft PR to `ossf/tac` with this proposal attached
- [ ] Slot requested on upcoming TAC meeting agenda
- [ ] Alpha-Omega grant application referenced in proposal acknowledgements

---

*Draft prepared 2026-04-17 by VIM founding team.*
