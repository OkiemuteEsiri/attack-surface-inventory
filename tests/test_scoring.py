from src.models import Asset
from src.reporting import build_summary
from src.scoring import prioritize, score_asset


def asset(**overrides):
    values = dict(
        asset_id="A-1",
        hostname="host-01",
        asset_type="server",
        owner="Platform",
        business_service="Portal",
        criticality=3,
        internet_exposed=False,
        environment="production",
        operating_system="Linux",
        last_seen_days=1,
        tags=[],
        vulnerability_count=0,
        critical_vulnerability_count=0,
        kev_count=0,
        eol=False,
        edr_present=True,
    )
    values.update(overrides)
    return Asset(**values)


def test_high_exposure_asset_scores_above_baseline():
    baseline = score_asset(asset())
    exposed = score_asset(asset(asset_id="A-2", internet_exposed=True, kev_count=1, criticality=5))
    assert exposed.score > baseline.score
    assert exposed.remediation_priority in {"P0", "P1"}


def test_score_is_capped_at_100():
    finding = score_asset(asset(criticality=5, internet_exposed=True, kev_count=5, critical_vulnerability_count=8, eol=True, edr_present=False, last_seen_days=90))
    assert finding.score == 100


def test_unknown_owner_is_data_quality_flag():
    finding = score_asset(asset(owner="unassigned"))
    assert "missing accountable owner" in finding.data_quality_flags


def test_prioritize_orders_descending_risk():
    low = asset(asset_id="LOW", criticality=1)
    high = asset(asset_id="HIGH", criticality=5, internet_exposed=True, kev_count=1)
    assert [f.asset_id for f in prioritize([low, high])] == ["HIGH", "LOW"]


def test_summary_tracks_exposure_and_quality():
    assets = [asset(asset_id="A", internet_exposed=True), asset(asset_id="B", owner="unknown", eol=True, last_seen_days=45)]
    findings = prioritize(assets)
    summary = build_summary(assets, findings)
    assert summary["asset_count"] == 2
    assert summary["internet_exposed"] == 1
    assert summary["eol_assets"] == 1
    assert summary["stale_assets"] == 1
    assert summary["data_quality_issues"] == 1
