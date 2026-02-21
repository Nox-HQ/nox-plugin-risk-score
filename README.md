# nox-plugin-risk-score

**Enrich vulnerability findings with EPSS scores and CISA KEV status for evidence-based prioritization.**

<!-- badges -->
![Track: Intelligence](https://img.shields.io/badge/track-Intelligence-purple)
![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8)

---

## Overview

`nox-plugin-risk-score` enriches vulnerability findings with real-world exploitation data from two authoritative sources: FIRST.org's Exploit Prediction Scoring System (EPSS) and CISA's Known Exploited Vulnerabilities (KEV) catalog. Instead of prioritizing vulnerabilities solely by CVSS severity, this plugin adds probability-of-exploitation context that helps teams focus remediation on the vulnerabilities most likely to be exploited in the wild.

CVSS scores tell you how bad a vulnerability *could* be. EPSS scores tell you how likely it *will* be exploited in the next 30 days. The KEV catalog tells you it *is* being exploited right now. Combining these signals with nox's static findings produces a risk-prioritized view that dramatically reduces alert fatigue -- most organizations find that fewer than 5% of their vulnerabilities account for the majority of actual risk.

The plugin belongs to the **Intelligence** track and operates with a passive risk class. It requires network access to `api.first.org` (EPSS API) and `www.cisa.gov` (KEV catalog) for enrichment lookups.

## Use Cases

### Prioritizing a Large Vulnerability Backlog

A team inherits a codebase with 200+ known CVEs in its dependency tree. Rather than working through them by CVSS score (which would prioritize many theoretical risks), they run the risk-score plugin to enrich each CVE with EPSS data. The result: 12 CVEs have EPSS scores above 0.4 (high probability of exploitation), and 3 are in the KEV catalog (actively exploited). The team fixes those 15 first, reducing actual risk by over 80% before touching the remaining 185.

### CI/CD Risk Gate

Integrate the plugin into your CI pipeline to gate deployments based on real-world risk. A policy like "block deployment if any dependency CVE has EPSS >= 0.7 or is in KEV" catches actively exploited vulnerabilities while allowing theoretical risks to be tracked and addressed in normal sprint work.

### Security Dashboard Enrichment

Feed enriched findings into your security dashboard or SIEM. Each finding includes the EPSS score, percentile, KEV status, and a computed risk priority (critical/high/medium/low), giving security analysts the context they need to make informed triage decisions without manually looking up each CVE.

## Tools

| Tool | Description | Context-Aware |
|------|-------------|---------------|
| `enrich_findings` | Enrich VULN findings with EPSS scores and KEV status | Yes (reads scan findings) |
| `get_epss` | Get EPSS score for a specific CVE | No |
| `get_kev_status` | Check if a CVE is in the CISA KEV catalog | No |

## Risk Priority Classification

The plugin classifies each enriched finding into a risk priority based on EPSS score and KEV status:

| Priority | Criteria | Action |
|----------|----------|--------|
| Critical | In KEV catalog OR EPSS >= 0.7 | Remediate immediately |
| High | EPSS >= 0.4 | Remediate this sprint |
| Medium | EPSS >= 0.1 | Schedule remediation |
| Low | EPSS < 0.1 | Track and monitor |

## Enriched Finding Schema

Each enriched finding includes:

```json
{
  "rule_id": "VULN-001",
  "cve": "CVE-2024-1234",
  "epss_score": 0.45,
  "epss_percentile": 0.92,
  "in_kev": true,
  "kev_detail": {
    "cveID": "CVE-2024-1234",
    "vendorProject": "example",
    "product": "library",
    "dateAdded": "2024-03-15",
    "requiredAction": "Apply updates per vendor instructions",
    "dueDate": "2024-04-05"
  },
  "risk_priority": "critical",
  "enriched_at": "2025-01-15T10:30:00Z"
}
```

## Data Sources

| Source | URL | Update Frequency |
|--------|-----|-----------------|
| EPSS | `https://api.first.org/data/v1/epss` | Daily |
| KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | As vulnerabilities are confirmed |

## Configuration

This plugin requires no configuration. Network access to `api.first.org` and `www.cisa.gov` is required for enrichment lookups.

## Installation

### Via Nox (recommended)

```bash
nox plugin install nox-hq/nox-plugin-risk-score
```

### From source

```bash
git clone https://github.com/nox-hq/nox-plugin-risk-score.git
cd nox-plugin-risk-score
make build
```

## Development

```bash
# Build the plugin binary
make build

# Run all tests
make test

# Run linter
make lint

# Clean build artifacts
make clean
```

## Architecture

The plugin is built on the Nox plugin SDK and communicates via the Nox plugin protocol over stdio. It registers three tools under the `risk-score` capability:

1. **enrich_findings** -- A context-aware tool that receives the current scan's findings via `req.Findings()`. For each finding with a CVE in its metadata, it queries the EPSS API and KEV catalog, computes a risk priority, and emits an enrichment attached to the finding's fingerprint.

2. **get_epss** -- A standalone tool that takes a `cve_id` input parameter and returns the EPSS score and percentile for that CVE.

3. **get_kev_status** -- A standalone tool that takes a `cve_id` input parameter and checks the locally cached KEV catalog for that CVE.

The plugin declares network access to `api.first.org` and `www.cisa.gov` in its safety manifest, allowing the host to enforce network policies.

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/nox-hq/nox-plugin-risk-score).

## License

Apache-2.0
