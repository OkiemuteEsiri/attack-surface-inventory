# Attack Surface Inventory

A recruiter-facing defensive security engineering project for building a normalized, explainable inventory of enterprise attack-surface exposure. The project demonstrates how asset context, vulnerability intelligence, business criticality, lifecycle risk, control coverage, ownership, and inventory freshness can be converted into prioritized remediation decisions without relying on opaque scoring.

> **Safety:** This repository is designed for authorized defensive analysis. It contains synthetic data only, performs no network scanning or exploitation, and includes no production targets, credentials, employer/client data, or offensive payloads.

## Problem statement

Security teams often have multiple partial views of the same environment: CMDB records, vulnerability findings, EDR coverage, cloud inventory, internet-exposure data, application ownership, and lifecycle status. The difficult engineering problem is not simply collecting records; it is producing a trustworthy, reviewable inventory that answers:

- Which assets create the highest exposure?
- Why are they high priority?
- Are ownership and business context known?
- Is the underlying inventory current enough to trust?
- What remediation would measurably reduce risk?
- How can closure be revalidated rather than assumed?

This lab implements that workflow in a deterministic Python pipeline.

## Architecture

```text
Synthetic / approved asset inventory
            |
            v
  schema + quality validation
            |
            v
     canonical Asset model
            |
            v
 exposure scoring + rationale
            |
            +----> data-quality flags
            |
            v
 fleet metrics + prioritized report
            |
            v
 remediation / evidence / revalidation
```

Key modules:

- `src/models.py` — immutable asset and exposure-finding models
- `src/inventory.py` — schema validation, normalization, duplicate detection, stale-record logic
- `src/scoring.py` — explainable 0–100 exposure scoring and P0–P3 prioritization
- `src/reporting.py` — fleet metrics and Markdown reporting
- `src/cli.py` — deterministic batch execution
- `data/synthetic_assets.json` — realistic, clearly synthetic inventory
- `tests/` — normalization, scoring, ordering, validation, and reporting tests
- `docs/` — architecture and methodology
- `reports/example-assessment.md` — example recruiter-facing assessment output
- `.github/workflows/ci.yml` — least-privilege test and smoke-assessment workflow

## Risk model

The example scoring model combines:

| Signal | Maximum contribution |
|---|---:|
| Business criticality | 40 |
| Internet exposure | 22 |
| Known-exploited vulnerability correlation | 20 |
| Critical vulnerability findings | 15 |
| End-of-life technology | 10 |
| Endpoint protection absent | 8 |
| Stale inventory record | 6 |

Scores are capped at 100. Unknown ownership, unknown control state, and missing service mapping are retained as **data-quality/governance flags** rather than silently treated as confirmed exploitability.

Priority bands:

- **P0 / Critical:** 80–100
- **P1 / High:** 60–79
- **P2 / Medium:** 35–59
- **P3 / Low:** 0–34

These weights are intentionally transparent portfolio examples, not a claim of an industry-standard formula.

## Usage

Python 3.10+ is sufficient for the runtime code. Tests use `pytest`.

```bash
python -m src.cli data/synthetic_assets.json --output attack-surface-report.md
```

Run tests:

```bash
python -m pip install pytest
python -m pytest -q
```

## Example use cases

The synthetic dataset demonstrates several realistic defensive scenarios:

- an internet-facing, business-critical web asset with KEV and critical vulnerability correlation;
- an internal legacy server with EOL technology and missing endpoint protection;
- a high-criticality CI runner with limited direct exposure;
- a stale IoT gateway record with an ownership gap and unknown control state;
- an internet-facing payment API whose business criticality warrants review even without KEV correlation.

## Methodology

The assessment sequence is:

1. validate the asset record before scoring it;
2. normalize identifiers and categorical fields;
3. preserve business ownership, service context, control state, and freshness;
4. correlate defensible exposure indicators;
5. score using an explainable model;
6. rank remediation priorities;
7. surface data-quality issues separately;
8. remediate or document an approved exception;
9. rerun the same assessment and retain evidence of risk reduction.

A ticket being closed is not treated as proof that exposure has been removed.

## MITRE ATT&CK context

Mappings are contextual and are **not claims that adversary activity occurred**:

- **T1190 – Exploit Public-Facing Application** — relevant to vulnerable internet-facing applications and services.
- **T1210 – Exploitation of Remote Services** — relevant when vulnerable remote services create internal attack paths.
- **T1078 – Valid Accounts** — relevant to identity and ownership context surrounding exposed systems and privileged access paths.

## Remediation and validation workflow

For a P0/P1 asset, the project methodology recommends:

1. confirm accountable ownership and business criticality;
2. validate whether internet exposure is necessary;
3. remediate KEV and critical findings or apply approved compensating controls;
4. upgrade, isolate, or retire EOL technology;
5. restore defensive control coverage where applicable;
6. refresh inventory evidence;
7. rerun scoring;
8. compare before/after evidence and residual risk.

## Design decisions

- **Deterministic instead of opaque:** recruiters and reviewers can follow every risk driver.
- **Quality-aware:** unknown data is surfaced rather than hidden.
- **Offline by default:** the portfolio can be safely reviewed without credentials or infrastructure access.
- **Source-agnostic model:** future read-only adapters could ingest CMDB, EDR, vulnerability scanner, cloud, or EASM exports while preserving provenance.
- **Risk reduction over ticket closure:** revalidation is part of the workflow.

## Limitations

- The scoring weights are illustrative and should be calibrated to organizational risk appetite.
- Internet exposure is represented as a trusted input rather than discovered through active scanning.
- KEV and vulnerability counts are synthetic fields; this repository does not call external intelligence feeds.
- The model does not infer exploitability from vulnerability presence alone.
- Asset relationships and attack-path graph analysis are outside the current scope.

## Skills demonstrated

- Attack Surface Management / Exposure Management
- Vulnerability Management engineering
- Asset inventory normalization
- Risk-based prioritization
- Data quality and ownership governance
- Python security automation
- Defensive reporting and metrics
- Remediation validation
- MITRE ATT&CK contextual mapping
- Unit testing and CI/CD security hygiene

## Roadmap

- add source provenance and confidence scoring;
- add read-only adapters for common export formats;
- add relationship-aware attack-path enrichment;
- add configurable policy weights and organizational risk thresholds;
- add JSON/SARIF-style machine-readable output;
- add trend comparison between assessment snapshots;
- add automated remediation-evidence validation rules.

## Repository intent

This project is a portfolio demonstration of security engineering methodology. It does not represent confidential employer/client systems or claim production deployment. All examples are synthetic and designed to show defensible engineering decisions, clear risk communication, and measurable remediation workflows.
