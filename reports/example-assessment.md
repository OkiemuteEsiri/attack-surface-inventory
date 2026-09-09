# Example Attack Surface Assessment

> Synthetic demonstration only. No production systems, employer/client data, or live scanning results are represented.

## Executive summary

Five synthetic assets were assessed using the repository's deterministic exposure model. The highest priorities are the internet-facing customer portal with known-exploited vulnerability context and the legacy ordering server with end-of-life technology, critical findings, and absent endpoint protection.

## Prioritized findings

| Asset | Primary exposure | Expected priority | Remediation focus |
|---|---|---|---|
| `edge-web-01.lab.example` | Internet-facing, critical business service, KEV correlation, critical findings | P0/P1 | Patch KEV/critical findings, validate exposure necessity, retest |
| `legacy-app-02.lab.example` | EOL platform, KEV correlation, critical findings, no EDR | P0/P1 | Upgrade/isolate, patch, restore control coverage |
| `payments-api-01.lab.example` | Internet-facing and business critical | P1/P2 | Validate external exposure and hardening controls |
| `build-runner-01.lab.example` | High business criticality with limited direct exposure | P2 | Maintain patching and CI hardening |
| `lab-iot-gw-07.lab.example` | Stale record, ownership gap, unknown EDR state | P2/P3 + governance | Assign owner, refresh inventory, confirm control applicability |

## Validation evidence expected

- updated vulnerability evidence for remediated findings
- current asset inventory timestamp
- ownership confirmation
- internet exposure revalidation
- endpoint protection status where applicable
- approved exception/risk-acceptance evidence when remediation is deferred

## Residual-risk note

A lower score after remediation does not imply zero risk. Residual exposure should still be reviewed in the context of business criticality, attack paths, compensating controls, and accepted risk thresholds.
