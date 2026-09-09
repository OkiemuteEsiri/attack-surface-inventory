from typing import Iterable, List

from .models import Asset, ExposureFinding


def _tier(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def score_asset(asset: Asset) -> ExposureFinding:
    score = 0
    reasons: List[str] = []
    dq: List[str] = []

    score += asset.criticality * 8
    reasons.append(f"business criticality {asset.criticality}/5")

    if asset.internet_exposed:
        score += 22
        reasons.append("internet exposed")
    if asset.kev_count:
        score += min(20, asset.kev_count * 10)
        reasons.append(f"{asset.kev_count} known-exploited vulnerability finding(s)")
    if asset.critical_vulnerability_count:
        score += min(15, asset.critical_vulnerability_count * 5)
        reasons.append(f"{asset.critical_vulnerability_count} critical vulnerability finding(s)")
    if asset.eol:
        score += 10
        reasons.append("end-of-life technology")
    if asset.edr_present is False:
        score += 8
        reasons.append("endpoint protection absent")
    if asset.last_seen_days > 30:
        score += 6
        reasons.append(f"inventory stale for {asset.last_seen_days} days")

    if not asset.owner or asset.owner.lower() in {"unknown", "unassigned"}:
        dq.append("missing accountable owner")
    if not asset.business_service or asset.business_service.lower() == "unknown":
        dq.append("missing business-service mapping")
    if asset.edr_present is None:
        dq.append("endpoint protection state unknown")

    score = min(100, score)
    tier = _tier(score)
    remediation_priority = "P0" if score >= 80 else "P1" if score >= 60 else "P2" if score >= 35 else "P3"
    return ExposureFinding(asset.asset_id, score, tier, reasons, dq, remediation_priority)


def prioritize(assets: Iterable[Asset]) -> List[ExposureFinding]:
    findings = [score_asset(asset) for asset in assets]
    return sorted(findings, key=lambda f: (-f.score, f.asset_id))
