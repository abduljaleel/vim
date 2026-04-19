# Amazon Security Research Award 2026 — Proposal

**Project:** Vulnerability Inheritance Map (VIM): Measuring and Mitigating Invisible Code Lineage in the Open-Source Supply Chain

**Principal Investigator:** [TBD — Acelera Intelligence, Melbourne, Australia]

**Co-Investigators:** [TBD — target: Prof. Audris Mockus (University of Tennessee, World of Code), Dr. Stefano Zacchiroli (Inria / Software Heritage)]

**Requested Amount:** Unrestricted research grant (Amazon Security Research Award)

**Duration:** 12 months (May 2026 – May 2027)

**Submission Date:** [On or before May 6, 2026]

---

## 1. Research Question

> **How prevalent is undetected vulnerable-code inheritance across the open-source software supply chain, and what fraction of it is invisible to current software composition analysis (SCA) tools?**

The open-source ecosystem is held together by code reuse: forks, vendored copies, and compiled binaries propagate source code across repository and language boundaries. When a vulnerability is found in one codebase, the same code often lives — unpatched — in hundreds or thousands of downstream systems. No existing dataset or tool measures how much of this inheritance exists, or how long patched vulnerabilities remain exploitable in downstream copies.

This research will answer that question empirically, at internet scale, by constructing the first comprehensive measurement of code-level vulnerability lineage across forks, vendored dependencies, and compiled binaries. The measurement platform — **VIM (Vulnerability Inheritance Map)** — will be released under Apache 2.0 to support reproducibility and follow-on research.

## 2. Motivation and Timeliness

### 2.1 The emerging remediation gap

Recent advances in AI-driven vulnerability discovery have dramatically reduced the *cost of finding* vulnerabilities in complex software. In April 2026, Anthropic's Claude Mythos Preview — evaluated independently by the UK AI Security Institute — demonstrated a 73% success rate on expert-level CTF tasks and autonomously produced working exploits for decades-old vulnerabilities, including a 27-year-old OpenBSD TCP SACK denial-of-service and a 17-year-old FreeBSD NFS stack overflow (CVE-2026-4747). Project Glasswing, Anthropic's launch partner program with AWS, Google, Microsoft, and 49 other organizations, will publish the full vulnerability report in July 2026.

The consequence is a structural shift: the bottleneck in software security is no longer *finding* bugs — it is *mapping where vulnerable code lives* so that patches actually reach affected systems. Over 99% of vulnerabilities found in the Mythos Preview remained unpatched at announcement because no tool can efficiently identify downstream copies of affected code across repository and packaging boundaries.

### 2.2 What existing tools miss

Current software supply chain infrastructure does not model code-level inheritance:

- **CVE / NVD** treats each fork as a separate product with no inheritance model. A vulnerability in upstream `libfoo` does not automatically generate advisories for forks, vendored copies, or relabeled distributions.
- **Package-level SCA** (Snyk, Sonatype, Black Duck, Socket) matches against package manifests. It cannot track code that enters a codebase outside a package manager — the 2026 Black Duck OSSRA reports this accounts for **17%** of open-source components in enterprise codebases.
- **GUAC** (OpenSSF) tracks artifact composition: which packages are in which products. It does not model fork relationships or detect manually copied code.
- **Software Heritage** archives universal source code (50B nodes, 900B edges) but does not link its content-addressed graph to the vulnerability graph.
- **Deps.dev** resolves dependency trees but does not follow vendored code.

### 2.3 What the academic literature suggests

Three prior studies hint at the scale of the problem:

1. **Pan et al. (ISSTA 2024)** observed a median 37-day patch-porting delay for security patches across hard forks, with more than 25% taking over three months.
2. **BlockScope (NDSS 2023)** identified 101 vulnerabilities across 13 forked blockchain projects, with patch delays exceeding 200 days.
3. **Mockus et al. (World of Code)** found **3M+ copied files with orphan vulnerabilities**; **59.3%** of vulnerable copied files are C code — precisely the language least visible to package-level SCA.

None of these studies measured the global population. Each examined a narrow slice. VIM will generalize these measurements across the full archived corpus.

## 3. Proposed Research

### 3.1 Approach

We will construct the first end-to-end measurement of vulnerability inheritance in the open-source ecosystem by building a hybrid graph database that integrates three canonical identity layers:

| Identity layer | Purpose | Technology |
|----------------|---------|-----------|
| **Extrinsic** | Package-level identity (ecosystem-aware) | pURL (ECMA-427) |
| **Intrinsic** | Content-addressable identity at file/directory/commit granularity | SWHID (Software Heritage ID) |
| **Fuzzy** | Similarity-based matching for modified code | TLSH (Trend Micro locality-sensitive hash) |

A **VIM Lineage ID** will map across the three layers, enabling queries such as *"which downstream repositories inherit a vulnerability first identified in upstream commit X?"*

### 3.2 Research activities

**RA1. Construct the global inheritance graph.** Ingest the Software Heritage compressed graph (50B nodes, 900B edges), World of Code provenance maps (173M repositories, 3.1B commits), OSV vulnerability-to-version mappings, and deps.dev dependency graphs. Build a hybrid storage architecture combining JanusGraph + Cassandra (mutable transactional) with WebGraph (Rust-based compressed analytics) to support both targeted queries and full-graph traversal.

**RA2. Measure inheritance at scale.** Systematically quantify, for a representative corpus of ~100 high-profile vulnerabilities:
  - Number of downstream repositories, packages, and compiled binaries carrying affected code
  - Time to patch propagation across forks
  - Fraction invisible to package-level SCA
  - Distribution across ecosystems, languages, and project maturity
  - Concentration in critical infrastructure (operating systems, cryptographic libraries, kernel components)

**RA3. Release reproducible infrastructure.** Publish the VIM platform under Apache 2.0, with reproducibility packages allowing independent research groups to replicate the measurement on demand. Target submission of the platform to OpenSSF Sandbox (Q3 2026).

**RA4. Publish findings.** Submit a peer-reviewed paper to USENIX Security, IEEE S&P, or NDSS (FY27), and present preliminary results at academic and community venues (OpenSSF Community Day, DEF CON, SecTor).

### 3.3 Evaluation plan

We will evaluate VIM against three criteria:

1. **Completeness:** Fraction of known upstream-to-downstream relationships successfully recovered from a curated ground-truth set of manually annotated fork/vendoring relationships.
2. **Precision:** Rate of false-positive lineage inferences, evaluated against a sample labeled by security researchers.
3. **Impact:** Number of previously undocumented downstream vulnerability exposures surfaced for at least ten critical-infrastructure vulnerabilities.

### 3.4 Relationship to existing Amazon priorities

This research aligns with AWS's sustained investment in open-source supply chain security:
- Amazon is a launch partner in Project Glasswing, receiving Mythos Preview access
- Amazon contributed to the AWS Security Research Award program specifically for research with practical security outcomes
- The Linux Foundation and OpenSSF have received Anthropic's $4M donation as part of Glasswing, with AWS participation
- AWS Open Source Security Team leads on SLSA, Sigstore, and artifact signing — complementary to VIM's lineage layer

VIM does not duplicate any of these efforts; it fills the gap between upstream discovery and downstream remediation.

## 4. Deliverables (12 months)

| Month | Deliverable |
|-------|------------|
| M3 | Identity resolution layer (pURL ↔ SWHID ↔ TLSH) with benchmark harness |
| M4 | Initial ingestion pipeline against Software Heritage and OSV |
| M6 | Alpha release: queryable graph for top-100 CVEs of 2025 |
| M6 | Application to OpenSSF Sandbox |
| M9 | Beta release: integration with GUAC (Phase 1 certifier) |
| M10 | Preliminary measurement paper (arXiv preprint) |
| M12 | Peer-reviewed paper submission; v1.0 public release |

All code, datasets (where licensing allows), analysis notebooks, and reproducibility packages will be published openly.

## 5. Team

- **[TBD — PI]**, Acelera Intelligence: responsible for architecture, community governance, and overall project direction
- **Collaborating researcher (target):** Prof. Audris Mockus, University of Tennessee. Creator of World of Code; has published extensively on cross-project code provenance and orphan vulnerabilities
- **Collaborating researcher (target):** Dr. Stefano Zacchiroli, Inria / Software Heritage. Co-creator of SWHID; leads the Software Heritage graph dataset
- **Community sponsor (target):** Michael Lieberman (Kusari), OpenSSF TAC member, GUAC co-creator. Sponsorship relationship for OpenSSF Sandbox acceptance

Ancillary engineering support is provided by Acelera Intelligence under a separate commitment; ASR funds are requested exclusively for research activities.

## 6. Budget Justification

The Amazon Security Research Award is an unrestricted grant. Funds will be applied to:

| Category | Purpose |
|----------|---------|
| Graduate student / researcher stipend | One full-time researcher for 12 months to lead measurement and paper preparation |
| Compute | Large-scale graph analytics (target: sustained AWS EC2 `r6a.48xlarge` or equivalent for bulk WebGraph traversal; S3 for dataset storage) |
| Travel | Attending OpenSSF Community Day NA (May 2026), DEF CON 34 (Aug 2026), USENIX Security 2027 |
| Publication | Open-access publication fees |
| Community | Sponsorship of OpenSSF working group participation; community call infrastructure |

Acelera Intelligence commits to matching the ASR grant with in-kind engineering time equivalent to at least 1 FTE for the duration of the project.

## 7. Broader Impact

**Reproducibility.** VIM will be the first open, reproducible measurement platform for software supply chain code lineage. All analyses will be replicable by independent groups.

**Regulatory relevance.** The EU Cyber Resilience Act takes effect September 2026 (reporting) and December 2027 (full conformity), with penalties up to €15M or 2.5% of global turnover for non-compliance. VIM provides the lineage evidence needed to answer CRA questions such as "which of our products are affected by vulnerability X?"

**Ecosystem contribution.** VIM is designed as a complement to the OpenSSF ecosystem — not a replacement. It will contribute an `IsForkOf` and `CertifyVulnInheritance` ontology proposal to GUAC, strengthening the shared infrastructure rather than fragmenting it.

**AI safety link.** VIM makes AI-driven vulnerability discovery socially beneficial rather than destabilizing. Finding exploitable bugs at low cost is only valuable if patches reach affected systems; VIM provides the mapping that closes the loop.

## 8. Prior Work and Preliminary Results

The principal investigator has completed preliminary architectural work establishing VIM's viability:

- A complete technical architecture combining JanusGraph, WebGraph, TLSH, and pURL (documented in the project repository)
- Initial repository scaffolding under Apache 2.0 with OpenSSF-aligned governance (GOVERNANCE.md, SECURITY.md, DCO, Sigstore signing)
- Ongoing dialogue with OpenSSF TAC members (target sponsor: Michael Lieberman)
- Identification of anchor data sources with confirmed access paths (Software Heritage S3 dataset, World of Code SSH access, OSV/deps.dev public APIs)

## 9. References

1. Anthropic. *Claude Mythos Preview: AI-Driven Vulnerability Discovery.* Technical report, April 2026. https://www-cdn.anthropic.com/08ab9158070959f88f296514c21b7facce6f52bc.pdf
2. UK AI Security Institute. *Evaluation of Claude Mythos Preview's Cyber Capabilities.* April 2026. https://aisi.gov.uk/blog/our-evaluation-of-claude-mythos-previews-cyber-capabilities
3. Yu et al. *BlockScope: Detecting and Investigating Propagated Vulnerabilities in Forked Blockchain Projects.* NDSS 2023.
4. Pan et al. *An empirical study of patch porting delays across forks.* ISSTA 2024.
5. Mockus et al. *World of Code: Enabling a Research Workflow for Mining and Analyzing the Universe of Open Source VCS Data.* Empirical Software Engineering, 2021.
6. Pietri, Spinellis, Zacchiroli. *The Software Heritage Graph Dataset: Public Software Development Under One Roof.* MSR 2019.
7. Oliveira et al. *TLSH — A Locality Sensitive Hash.* 2013.
8. Black Duck. *2026 Open Source Security and Risk Analysis (OSSRA) Report.*
9. Kusari et al. *GUAC: Graph for Understanding Artifact Composition.* https://guac.sh
10. ECMA-427. *Package URL (pURL) Specification.* 2026.

---

*Submission target: security-research-awards@amazon.com (or Amazon Science submission portal, to be verified).*

*Contact: [TBD]*
