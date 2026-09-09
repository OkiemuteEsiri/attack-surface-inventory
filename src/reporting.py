from collections import Counter
from typing import Iterable

from .models import Asset, ExposureFinding


def build_summary(assets: Iterable[Asset], findings: Iterable[ExposureFinding]) -> dict:
    assets = list(assets)
    findings = list(findings)
    tiers = Counter(f.tier for f in findings)
    priorities = Counter(f.remediation_priority for f in findings)
    return {
        "asset_count": len(assets),
        "internet_exposed": sum(a.internet_exposed for a in assets),
        "eol_assets": sum(a.eol for a in assets),
        "assets_with_kev": sum(a.kev_count > 0 for a in assets),
        "stale_assets": sum(a.last_seen_days > 30 for a in assets),
        "tier_counts": dict(sorted(tiers.items())),
        "priority_counts": dict(sorted(priorities.items())),
        "data_quality_issues": sum(bool(f.data_quality_flags) for f in findings),
    }


def to_markdown(assets: Iterable[Asset], findings: Iterable[ExposureFinding]) -> str:
    assets = list(assets)
    findings = list(findings)
    index = {a.asset_id: a for a in assets}
    summary = build_summary(assets, findings)
    lines = [
        "# Attack Surface Exposure Report",
        "",
        f"- Assets assessed: {summary['asset_count']}",
        f"- Internet exposed: {summary['internet_exposed']}",
        f"- EOL assets: {summary['eol_assets']}",
        f"- Assets with KEV correlation: {summary['assets_with_kev']}",
        f"- Stale inventory records: {summary['stale_assets']}",
        f"- Assets with data-quality issues: {summary['data_quality_issues']}",
        "",
        "| Asset | Service | Score | Tier | Priority | Primary reasons |",
        "|---|---|---:|---|---|---|",
    ]
    for finding in findings:
        asset = index[finding.asset_id]
        reasons = "; ".join(finding.reasons[:4])
        lines.append(
            f"| {asset.hostname} | {asset.business_service} | {finding.score} | "
            f"{finding.tier} | {finding.remediation_priority} | {reasons} |"
        )
    return "\n".join(lines) + "\n"
