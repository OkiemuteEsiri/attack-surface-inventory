# Architecture

## Objective

The project models a defensive attack-surface inventory pipeline that converts heterogeneous asset records into a normalized, prioritized exposure view. It is intentionally offline and synthetic by default: it does not scan networks, query production systems, or perform exploitation.

## Components

1. **Inventory ingestion (`src/inventory.py`)**
   - validates required fields
   - normalizes selected categorical values
   - enforces unique asset identifiers
   - exposes stale-record detection

2. **Canonical data model (`src/models.py`)**
   - immutable `Asset` representation
   - immutable `ExposureFinding` representation
   - separates business context, exposure context, control state, and data-quality flags

3. **Exposure scoring (`src/scoring.py`)**
   - combines business criticality, internet exposure, KEV correlation, critical findings, EOL status, endpoint protection state, and inventory freshness
   - caps output at 100
   - assigns transparent tiers and remediation priorities

4. **Reporting (`src/reporting.py`)**
   - fleet-level exposure metrics
   - data-quality metrics
   - Markdown prioritization report

5. **CLI (`src/cli.py`)**
   - deterministic batch execution from a JSON inventory
   - no network calls

## Trust boundaries

- **Input boundary:** asset inventories are untrusted until schema validation succeeds.
- **Scoring boundary:** absence of data is not silently interpreted as confirmed weakness; unknown values are retained as quality flags where appropriate.
- **Output boundary:** prioritization is a decision-support artifact, not proof of exploitability or compromise.

## Production extension points

A production implementation could add read-only adapters for CMDB, EDR, vulnerability scanners, cloud asset inventories, and EASM platforms. Those integrations should preserve source provenance, timestamps, and confidence rather than flattening uncertainty.

## Security design choices

- no credentials or API secrets in repository content
- no active scanning or exploit automation
- synthetic examples use reserved/non-routable naming conventions
- deterministic scoring supports review and auditability
- data-quality issues are surfaced rather than hidden
