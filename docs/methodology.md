# Methodology

## Assessment workflow

1. Collect asset records from approved inventory sources.
2. Normalize identifiers, categorical values, ownership, business-service context, freshness, and control state.
3. Reject structurally invalid records rather than scoring unreliable input.
4. Correlate defensive exposure signals such as internet reachability, known-exploited vulnerabilities, critical findings, EOL technology, and missing endpoint protection.
5. Apply explainable scoring and assign remediation priority.
6. Review data-quality flags separately from confirmed exposure drivers.
7. Remediate the highest-risk assets first, then rerun the same assessment to verify that exposure was reduced.

## Risk model

The scoring engine is intentionally deterministic and reviewable rather than predictive. The current weights are portfolio examples, not an industry standard:

- business criticality: up to 40 points
- internet exposure: 22 points
- known-exploited vulnerability correlation: up to 20 points
- critical vulnerability findings: up to 15 points
- end-of-life technology: 10 points
- endpoint protection absent: 8 points
- stale inventory record: 6 points

Scores are capped at 100.

### Priority bands

- **P0 / Critical:** 80–100
- **P1 / High:** 60–79
- **P2 / Medium:** 35–59
- **P3 / Low:** 0–34

## Data-quality treatment

Unknown ownership, missing business-service mapping, and unknown endpoint protection state are surfaced as governance issues. They are not automatically treated as evidence of exploitability.

## MITRE ATT&CK context

ATT&CK mappings are contextual, not evidence that a technique occurred:

- **T1190 – Exploit Public-Facing Application:** relevant when internet-facing assets carry exploitable vulnerabilities.
- **T1210 – Exploitation of Remote Services:** relevant when vulnerable network services expand internal attack paths.
- **T1078 – Valid Accounts:** identity ownership and control coverage matter when exposed systems rely on privileged or persistent access paths.

## Remediation and validation

For a P0/P1 asset:

1. confirm ownership and business criticality;
2. validate internet exposure and service necessity;
3. remediate KEV/critical vulnerabilities or apply approved compensating controls;
4. upgrade or isolate EOL technology;
5. restore endpoint protection coverage where applicable;
6. refresh inventory evidence;
7. rerun the scoring engine;
8. retain before/after scores and evidence for closure review.

A finding is not considered validated closed merely because a ticket is marked complete. The underlying exposure signal must change or an approved risk decision must be documented.
