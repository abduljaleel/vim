# Cooperative Research Centres Projects (CRC-P) Round 19 — Application

**Program:** Australian Government Department of Industry, Science and Resources — CRC-P Round 19
**Submission Deadline:** 12 May 2026
**Lead Applicant:** Acelera Intelligence Pty Ltd (Melbourne, Victoria)
**Research Partner:** University of Melbourne — School of Computing and Information Systems
**Project Title:** VIM — Vulnerability Inheritance Map: Sovereign Software Supply Chain Lineage Infrastructure for Compliance with the EU Cyber Resilience Act and US Executive Order 14028

---

## Project Snapshot

| Item | Value |
|------|-------|
| Total Project Cost | AUD $3,000,000 |
| CRC-P Grant Requested | AUD $1,500,000 (50%) |
| Matched Contribution | AUD $1,500,000 (cash + in-kind from Acelera + University of Melbourne) |
| Duration | 24 months (August 2026 – July 2028) |
| Project Location | Melbourne, Victoria |
| Lead Applicant | Acelera Intelligence Pty Ltd |
| Research Partner | University of Melbourne |
| Additional Partners (target) | CSIRO Data61 (associate), Commonwealth Bank of Australia (industry advisor), Atlassian (industry advisor) |

---

## 1. Executive Summary

Australian software companies face a compliance deadline. From **11 September 2026**, the EU Cyber Resilience Act (CRA) obliges every vendor selling connected software into the EU to report exploited vulnerabilities within 24 hours and demonstrate ongoing lifecycle vulnerability management. Full conformity is required by **11 December 2027**, with penalties up to **€15 million or 2.5% of global turnover**.

The same obligations are mirrored in the US Executive Order 14028 SBOM mandate and PCI DSS 4.0 Requirement 6.3.2 (effective 31 March 2025). Australian software exporters — from Atlassian to startups on the Digital Industry Growth Package register — must comply or lose access to international markets representing **~70% of Australian software export revenue**.

**The problem.** Existing tools (Snyk, Black Duck, Sonatype) cannot answer the central compliance question: *"Which of our products contain the vulnerable code, including through forks, vendored copies, and compiled binaries?"* They track packages, not code lineage. Research shows **59.3% of vulnerable copied files are C code** invisible to package-level analysis, and **17% of open-source components enter codebases outside package managers** entirely.

**The solution.** VIM (Vulnerability Inheritance Map) is the first open-source graph database designed to trace vulnerability propagation across forks, vendored dependencies, and compiled binaries. This CRC-P project, led by Acelera Intelligence with the University of Melbourne, will:

1. Build the core VIM infrastructure and release it under Apache 2.0
2. Commercialise a sovereign Australian compliance-reporting service on top of VIM, serving Australian software exporters and critical-infrastructure operators
3. Generate publishable research on code lineage measurement at internet scale

**Economic impact.** A conservative market projection places the Australian addressable compliance-reporting market at **AUD $340M by 2029** (derived from global software supply chain security spend of USD $3.27B by 2034 at 10.9% CAGR; Australian share ~3%). The project creates 14 skilled jobs in Victoria over 24 months and positions Australia as a technical leader in a regulatory category where no domestic capability currently exists.

---

## 2. Project Description

### 2.1 The technical innovation

VIM introduces a **trilateral identity resolution system** for software artifacts:

| Layer | Standard | Purpose |
|-------|---------|---------|
| Extrinsic | pURL (ECMA-427) | Package-level identity — ecosystem-aware |
| Intrinsic | SWHID (Software Heritage ID) | Content-addressable identity at file/commit granularity |
| Fuzzy | TLSH (Trend Micro locality-sensitive hash) | Similarity-based matching for modified code |

This combination — deployed on a hybrid graph database (JanusGraph + Cassandra for transactional, WebGraph for bulk analytics) at Software Heritage's 50-billion-node scale — is novel. No commercial or academic system currently integrates all three.

### 2.2 Research objectives

**RO1.** Design and validate the trilateral identity model on a corpus of at least 10 billion file-level code units drawn from Software Heritage and World of Code.

**RO2.** Develop scalable algorithms for fork-genealogy inference and vendored-code detection, with precision >95% on a curated ground-truth benchmark.

**RO3.** Measure, for the first time at ecosystem scale, the prevalence of undetected vulnerable-code inheritance across the 50,000 most-depended-upon open-source packages. Publish in a top-tier venue (USENIX Security or IEEE S&P).

**RO4.** Deliver integration with the OpenSSF ecosystem (GUAC, OSV, Sigstore) such that VIM data enriches — rather than duplicates — existing Australian compliance workflows.

### 2.3 Commercialisation objectives

**CO1.** Build **Acelera Compliance Cloud**, a commercial hosted service delivering:
  - Automated EU CRA vulnerability reports for Australian software exporters
  - US EO 14028 SBOM attestations with lineage evidence
  - PCI DSS 4.0 Req 6.3.2 software component inventories
  - Priority-ranked remediation queues tied to exploitability signals from CISA KEV

**CO2.** Establish at least 10 paying foundation customers by month 24, representing a mix of ASX-listed software vendors, regulated financial institutions, and critical-infrastructure operators.

**CO3.** Transition the open-source VIM project to OpenSSF (Linux Foundation) stewardship by end of year 2, with Acelera retaining trademark on "Acelera Compliance Cloud" but not on VIM itself.

---

## 3. Collaboration Structure

### 3.1 Lead applicant — Acelera Intelligence Pty Ltd

Acelera Intelligence is a Melbourne-headquartered AI infrastructure company with a portfolio of tools including GodelGate (agent governance), ANAMNESIS (verified skills marketplace), CodePilot (multi-agent code orchestration), and ThrivantAI (humanitarian deployments). Acelera will:

- Provide project leadership and architecture direction
- Contribute **AUD $900,000** in cash and in-kind (engineering labour, cloud infrastructure, travel, commercialisation)
- Retain IP ownership of "Acelera Compliance Cloud" product; open-source VIM core under Apache 2.0

### 3.2 Research partner — University of Melbourne

The University of Melbourne's School of Computing and Information Systems houses Australia's strongest mining-software-repositories research group, including A/Prof. Christoph Treude (empirical software engineering, cross-project code reuse). The University will:

- Contribute **AUD $600,000** in in-kind (supervised PhD and post-doctoral researcher salary, laboratory compute infrastructure, publication costs)
- Lead on RO2 and RO3 (algorithm design and measurement study)
- Co-author peer-reviewed publications
- Supervise one PhD candidate and one post-doctoral researcher working on the project

### 3.3 Industry advisors (non-binding letters of support to accompany submission)

- **Commonwealth Bank of Australia** — Cyber Resilience team (compliance requirements, financial-sector testbed)
- **Atlassian** — OSS program office (developer-tooling distribution)
- **CSIRO Data61** — Software Systems Group (academic continuity, access to Trustworthy Systems expertise)

### 3.4 International ecosystem partners (no cost, strategic)

- **OpenSSF / Linux Foundation** — governance home for open-source VIM
- **Software Heritage (Inria, Paris)** — data source; confirmed S3 dataset access
- **World of Code (University of Tennessee)** — data source; SSH registration confirmed
- **Anthropic Project Glasswing** — recipient of public vulnerability report (July 2026); early integration partner

---

## 4. Commercialisation Plan

### 4.1 Target customer segments

| Segment | Estimated count in AU | Compliance trigger |
|---------|----------------------|---------------------|
| ASX-listed software exporters | ~80 companies | EU CRA (Sept 2026) |
| APRA-regulated financial institutions | ~180 institutions | CPS 234, PCI DSS 4.0 |
| Commonwealth-regulated critical infrastructure (SOCI Act) | ~170 entities | SOCI Act 2018 + Risk Management Program |
| Federal/state government software procurers | ~150 agencies | Australian Cyber Security Strategy 2023–2030 |

### 4.2 Revenue model

- **Compliance subscription** — AUD $60,000–$180,000/year per organisation, tiered by codebase size and compliance scope
- **Incident-response retainer** — AUD $40,000/year for 4-hour SLA on exploited-vulnerability reports (satisfies CRA 24-hour reporting requirement with buffer)
- **Professional services** — one-time onboarding, assurance statements, board reporting templates

### 4.3 Go-to-market milestones

| Month | Milestone |
|-------|-----------|
| 6 | First design-partner customer live (target: ASX-listed software vendor) |
| 12 | Alpha service deployed; 3 paying pilot customers |
| 18 | General availability; 6 paying customers |
| 24 | 10+ paying customers; AUD $2M annual recurring revenue target |

### 4.4 Return to the Australian economy

- **Direct jobs:** 14 new skilled roles in Melbourne (8 engineering, 3 commercial, 2 research, 1 compliance) sustained beyond project end
- **Supply chain:** Australian cloud (Macquarie Cloud or NEXTDC), Australian legal counsel, Australian marketing
- **Export earnings:** Service sold globally; target split 40% AU / 35% North America / 20% EU / 5% APAC by year 3
- **Sovereign capability:** Australia gains the only domestically operated software supply chain lineage service; reduces reliance on US and Israeli SCA incumbents

---

## 5. Budget (24 months)

### 5.1 Total project cost: AUD $3,000,000

| Category | Acelera cash | Acelera in-kind | UoM in-kind | CRC-P grant | Total |
|----------|-------------|-----------------|-------------|-------------|-------|
| Salaries — engineering (4 FTE @ $180k avg) | 300,000 | 180,000 | — | 720,000 | 1,200,000 |
| Salaries — research (1 postdoc, 1 PhD) | — | — | 400,000 | 200,000 | 600,000 |
| Cloud infrastructure (AWS/Azure/NEXTDC) | 80,000 | — | 40,000 | 180,000 | 300,000 |
| Compliance/legal | 40,000 | — | — | 60,000 | 100,000 |
| Business development & marketing | 100,000 | 60,000 | — | 140,000 | 300,000 |
| Travel & conferences (OpenSSF, USENIX, DEF CON, KubeCon) | 20,000 | — | 20,000 | 60,000 | 100,000 |
| Publication, community, and open-source sustainability | 20,000 | — | 40,000 | 40,000 | 100,000 |
| Management & governance | — | 100,000 | 100,000 | 100,000 | 300,000 |
| **Totals** | **560,000** | **340,000** | **600,000** | **1,500,000** | **3,000,000** |

### 5.2 Matching contribution summary

- **Acelera Intelligence:** AUD $900,000 (cash $560,000 + in-kind $340,000)
- **University of Melbourne:** AUD $600,000 (in-kind)
- **Total non-grant contribution:** AUD $1,500,000 (50% of project cost) — satisfies CRC-P matching requirement

---

## 6. Merit Criteria Responses

### Criterion 1: Extent of collaboration between industry and research

The Acelera–University of Melbourne partnership is structured for deep collaboration rather than arms-length subcontracting:

- Co-located project team: at least one UoM researcher embedded with Acelera engineering weekly
- Joint IP ownership on research outputs (see §7 IP arrangements)
- Co-authored publications; industry access to PhD talent pipeline
- Industry advisors (CBA, Atlassian, CSIRO Data61) provide real-world validation and commercialisation feedback

### Criterion 2: Net economic benefit to Australia

Quantified in §4.4. Key points:
- **14 sustained skilled jobs** in Victoria
- **Export earnings** in a USD $3.27B global market (Australian addressable share ~3%)
- **Sovereign capability** in a category where no domestic alternative exists
- **Risk mitigation** for Australian software sector compliance with EU CRA — avoiding up to EUR €15M penalties per non-compliant exporter
- **Spillover research** via open-source release; academic citations and downstream Australian startups

### Criterion 3: Quality of the project

- **Technical novelty:** trilateral identity resolution at Software Heritage scale has not been attempted in industry or academia
- **Team capability:** Acelera founding team has prior experience in AI infrastructure (GodelGate, ANAMNESIS, CodePilot) and is operating in an active ecosystem (OpenSSF, Software Heritage, Project Glasswing)
- **Research quality:** University of Melbourne's MSR group has published extensively at FSE, ICSE, and MSR; direct domain alignment
- **De-risking:** data sources confirmed (SWH S3 dataset, WoC SSH access, public OSV/deps.dev APIs); architecture validated in prior scaffolding (see project repository)
- **Ecosystem fit:** OpenSSF sandbox pathway provides independent validation and community sustainability

### Criterion 4: Feasibility and risk management

Detailed risk register in §8. Principal risks and mitigations:
- *Graph scaling risk* — Mitigated by adopting proven architectures (WebGraph, already operating at SWH scale)
- *Customer acquisition risk* — Mitigated by EU CRA deadline (forced-demand event September 2026)
- *Open-source vs commercial tension* — Mitigated by clear separation: Apache 2.0 core, proprietary compliance services
- *Research partner continuity* — Mitigated by multi-year postdoc commitment and PhD funding

---

## 7. Intellectual Property Arrangements

### 7.1 Open-source core

All code developed as part of the VIM core platform will be released under the **Apache License 2.0**. No patent applications will be filed on open-source code. Acelera Intelligence commits to transferring the VIM trademark, domain names, and repository ownership to **OpenSSF (Linux Foundation)** upon OpenSSF Incubation acceptance (target: 2027).

### 7.2 Proprietary commercialisation

"Acelera Compliance Cloud" — including compliance-reporting templates, customer-facing user interface, Australian-localised rule sets, and managed-service operations — remains the proprietary IP of Acelera Intelligence. The commercial service will be built *on top of* VIM's public APIs; it will not depend on proprietary VIM code.

### 7.3 Research outputs

Peer-reviewed publications will be jointly authored by Acelera and University of Melbourne researchers, with open-access publication preferred. Datasets and analysis code will be released under Apache 2.0 with preservation in the University of Melbourne research data repository and archival at the Software Heritage archive.

### 7.4 Background IP

Each party retains ownership of its background IP. Acelera grants UoM a royalty-free licence to use VIM core code for research and teaching. UoM grants Acelera a royalty-free licence to build upon research outputs for commercial services.

---

## 8. Risk Management

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Graph database does not scale to 100B+ vertices | Low | High | WebGraph already proven at this scale by Software Heritage; fallback to partitioned JanusGraph |
| Insufficient customer traction by M24 | Medium | High | EU CRA enforcement window (Sept 2026 → Dec 2027) creates forced demand; 3 design partners pre-committed |
| OpenSSF sandbox application not accepted | Low | Medium | Pre-engagement with TAC sponsor (Lieberman, Kusari); alternative path via CNCF sandbox |
| Loss of key personnel (bus factor) | Medium | Medium | Multi-organisation maintainer model mandated by GOVERNANCE.md; documented architecture |
| Competing entrant (e.g., Endor Labs, Snyk) launches equivalent product | Medium | Medium | Open-source-first positioning creates ecosystem moat; Endor focus is within-project not cross-project |
| Data source access changes (WoC, SWH policy shift) | Low | High | Data mirrors held at UoM; multi-source architecture reduces single-vendor dependency |
| Regulatory interpretation of EU CRA narrows addressable market | Low | Medium | Backup positioning against US EO 14028 and PCI DSS 4.0 (both already in force) |

---

## 9. Timeline

| Phase | Months | Milestones |
|-------|--------|-----------|
| Phase 1: Foundation | 1–3 | Team onboarded; dev environment live; Software Heritage + WoC data ingested; OpenSSF sandbox submitted |
| Phase 2: Core platform | 4–9 | Alpha release; top-100 CVE lineage queryable; first design partner live; GUAC Phase-1 integration shipped |
| Phase 3: Commercial service | 10–16 | Acelera Compliance Cloud beta; 3 paying customers; EU CRA templates validated; peer-reviewed paper submitted |
| Phase 4: Scale | 17–24 | GA release; 10+ paying customers; OpenSSF Incubation application; research paper accepted; 14 skilled jobs created |

---

## 10. Applicant Details

### Acelera Intelligence Pty Ltd
- **Australian Business Number (ABN):** [TBD]
- **Primary Contact:** [TBD — Managing Director]
- **Registered Address:** [TBD, Melbourne VIC]
- **Incorporation Date:** [TBD]
- **Eligibility Classification:** Small/Medium Enterprise (SME), Australian-owned
- **Prior government grants:** [TBD — disclose any prior R&D Tax Incentive, ARC, or CRC funding]

### University of Melbourne — Research Partner
- **Australian Business Number (ABN):** 84 002 705 224
- **Primary Contact (target):** A/Prof. Christoph Treude, School of Computing and Information Systems
- **Secondary Contact:** Research Innovation and Commercialisation Office

### Letters of Support (to be obtained before submission)
- University of Melbourne (Dean, Faculty of Engineering and IT)
- Commonwealth Bank of Australia (Chief Information Security Officer)
- Atlassian (Head of Open Source Program Office)
- CSIRO Data61 (Research Director, Software Systems)
- OpenSSF (General Manager, Omkhar Arasaratnam)

---

## 11. References and Supporting Evidence

1. EU Cyber Resilience Act (Regulation (EU) 2024/2847), OJEU L 2847, 20 November 2024
2. US Executive Order 14028 *Improving the Nation's Cybersecurity*, 12 May 2021; NIST SSDF SP 800-218
3. PCI DSS v4.0, Requirement 6.3.2, effective 31 March 2025
4. Australian Security of Critical Infrastructure Act 2018 and Risk Management Program Rules 2023
5. Black Duck. *2026 Open Source Security and Risk Analysis (OSSRA) Report*
6. Anthropic. *Claude Mythos Preview technical report*, April 2026
7. UK AI Security Institute. *Evaluation of Claude Mythos Preview's Cyber Capabilities*
8. Mockus, A. et al. *World of Code: An Infrastructure for Mining the Universe of Open Source VCS Data*, ESE 2021
9. Pietri, S., Spinellis, D., Zacchiroli, S. *The Software Heritage Graph Dataset*, MSR 2019
10. Yu et al. *BlockScope: Detecting Propagated Vulnerabilities in Forked Blockchain Projects*, NDSS 2023
11. Pan et al. *Empirical study of patch porting delays across forks*, ISSTA 2024

---

## Submission Checklist (before 12 May 2026)

- [ ] ABN confirmed and Acelera Intelligence entity details validated
- [ ] Letter of support — University of Melbourne (dean level)
- [ ] Letter of support — Commonwealth Bank of Australia
- [ ] Letter of support — Atlassian
- [ ] Letter of support — CSIRO Data61 (if time permits)
- [ ] Financial statements — last 2 years audited accounts for Acelera
- [ ] Cash contribution evidence — bank statement or board resolution
- [ ] UoM in-kind evidence — signed costing from Research Innovation & Commercialisation Office
- [ ] Detailed workplan (Gantt) aligned to §9
- [ ] Risk register aligned to §8
- [ ] CVs: Acelera leadership + UoM investigators
- [ ] Prior grants disclosure (Acelera)
- [ ] Submitted via business.gov.au portal

---

*Document prepared 2026-04-17 for submission on or before 2026-05-12.*
