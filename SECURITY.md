# Security Policy

## Reporting a Vulnerability

The VIM project takes security seriously. If you discover a security issue in VIM itself (not in data VIM is tracking about other projects), please report it privately so we can address it before public disclosure.

### How to Report

Please report security vulnerabilities in VIM by emailing:

**security@vim-project.org**

(During pre-launch, reports can be sent directly to the founding maintainers — contact details in `MAINTAINERS.md`.)

You may also use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) feature on the VIM repository.

### What to Include

A good report includes:
- A description of the issue and the component affected
- Steps to reproduce
- The impact you believe the issue has
- Any suggested mitigations
- Your name and affiliation (if you wish to be credited)

Please do **not** open a public GitHub issue for security matters.

## Response Timeline

We aim to meet the following response targets:

| Stage | Target |
|-------|--------|
| Acknowledge receipt | Within 2 business days |
| Initial assessment | Within 5 business days |
| Fix or mitigation plan | Within 30 days of confirmed vulnerability |
| Coordinated disclosure | Typically 90 days from report, subject to complexity |

If a fix will take longer than 30 days, we will communicate the reason and a revised timeline to the reporter.

## Disclosure Policy

VIM follows a **coordinated disclosure** model:
1. The reporter and maintainers agree on a disclosure date
2. A fix is developed and tested in a private branch
3. A GitHub Security Advisory (GHSA) is drafted
4. On the disclosure date: advisory published, CVE assigned (if applicable), patched release cut, reporter credited (unless they prefer anonymity)

Where a vulnerability is being actively exploited, the timeline may be shortened.

## Safe Harbor

We consider security research conducted in good faith under this policy to be:
- Authorized, with respect to any applicable anti-hacking laws
- Exempt from our Terms of Service restrictions that would prohibit the research
- Lawful and not a violation of the Computer Fraud and Abuse Act (or equivalent legislation in other jurisdictions)

We will not pursue legal action for good-faith research that:
- Stays within the scope of this policy
- Does not access, modify, or destroy data belonging to others
- Reports findings promptly and does not exploit them beyond what is necessary to demonstrate the issue

## Scope

This policy applies to vulnerabilities in:
- The VIM codebase (this repository)
- Official VIM container images
- Official VIM infrastructure (api.vim-project.org, etc., once deployed)

This policy does **not** cover:
- Vulnerabilities in upstream projects (Software Heritage, OSV, GUAC, etc.) — please report those to the respective projects
- Data about third-party vulnerabilities that VIM tracks — VIM surfaces public information from upstream sources
- Self-hosted VIM deployments where the issue is in deployment configuration rather than VIM itself

## Security Practices

VIM follows OpenSSF security baseline practices:
- All releases are signed with Sigstore (Cosign + Rekor)
- Target SLSA Level 3 build provenance
- Dependencies are pinned and scanned in CI (OSV-Scanner, Trivy, Semgrep, Gitleaks)
- OpenSSF Best Practices Badge (Passing level, target)
- Annual third-party security review once the project reaches Incubation

## Hall of Fame

Reporters who responsibly disclose vulnerabilities in VIM will be acknowledged in our `SECURITY_ACKNOWLEDGMENTS.md` file (unless they request anonymity).

---

*Policy last updated: 2026-04-17*
